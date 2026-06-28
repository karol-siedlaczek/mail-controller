"""All SQL for mail-controller. Fully parameterized; no f-string interpolation of
user data. Reads/writes the mail-server schema via the mail_admin_rw role."""
import psycopg2
from psycopg2 import errors
from mail_controller.exception.api_exceptions import ConflictError, UnprocessableError
from mail_controller.domain.domain import Domain
from mail_controller.domain.address import DomainName, EmailAddress
from mail_controller.domain.mailbox import Mailbox
from mail_controller.domain.forwarding import Forwarding
from mail_controller.domain.sender_login import SenderLogin
from mail_controller.domain.audit import AuditEntry

_USER_COLS = "id, email, quota_bytes, active, created_at, domain_id"
_DOMAIN_COLS = "id, domain, dkim_selector, active, created_at"
_FWD_COLS = "id, source, destination, keep_copy, active, created_at"
_SLM_COLS = "id, login_email, allowed_sender, active, created_at"
_AUDIT_COLS = ('id, event_type, success, login, host(src_ip) AS src_ip, host, '
               'sender, recipient, message_id, queue_id, score, msg, pid, "timestamp"')


def _like_term(term: str) -> str:
    """Wrap `term` as a substring ILIKE pattern, escaping LIKE wildcards (\\ % _)."""
    escaped = term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


def _created_clauses(created_since, created_until) -> tuple[list, dict]:
    clauses, params = [], {}
    if created_since is not None:
        clauses.append("created_at >= %(cs)s")
        params["cs"] = created_since
    if created_until is not None:
        clauses.append("created_at <= %(cu)s")
        params["cu"] = created_until
    return clauses, params


# ── domains ────────────────────────────────────────────────────────────────
def list_domains(cur, term=None, active=None, created_since=None, created_until=None) -> list[Domain]:
    clauses, params = [], {}
    if term:
        clauses.append("domain ILIKE %(flt)s ESCAPE '\\'")
        params["flt"] = _like_term(term)
    if active is not None:
        clauses.append("active = %(active)s")
        params["active"] = active
    c, p = _created_clauses(created_since, created_until)
    clauses += c
    params.update(p)
    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    cur.execute(f"SELECT {_DOMAIN_COLS} FROM domains{where} ORDER BY domain", params)
    return [Domain.from_row(r) for r in cur.fetchall()]


def get_domain(cur, name: DomainName) -> Domain | None:
    cur.execute(f"SELECT {_DOMAIN_COLS} FROM domains WHERE domain = %(d)s", {"d": name.value})
    row = cur.fetchone()
    return Domain.from_row(row) if row else None


def create_domain(cur, domain: Domain) -> Domain:
    try:
        cur.execute(
            f"INSERT INTO domains (domain, dkim_selector, active) "
            f"VALUES (%(d)s, %(s)s, %(a)s) RETURNING {_DOMAIN_COLS}",
            {"d": domain.name.value, "s": domain.dkim_selector, "a": domain.active},
        )
    except errors.UniqueViolation:
        raise ConflictError(msg="Domain already exists", detail={"domain": domain.name.value})
    return Domain.from_row(cur.fetchone())


def update_domain(cur, name: DomainName, dkim_selector, active) -> Domain | None:
    cur.execute(
        f"UPDATE domains SET "
        f"dkim_selector = COALESCE(%(s)s, dkim_selector), "
        f"active = COALESCE(%(a)s, active) "
        f"WHERE domain = %(d)s RETURNING {_DOMAIN_COLS}",
        {"d": name.value, "s": dkim_selector, "a": active},
    )
    row = cur.fetchone()
    return Domain.from_row(row) if row else None


def delete_domain(cur, domain: str) -> bool:
    cur.execute("DELETE FROM domains WHERE domain = %(d)s", {"d": domain})
    return cur.rowcount > 0


# ── users ──────────────────────────────────────────────────────────────────
def list_users(cur, domain=None, term=None, active=None, created_since=None, created_until=None) -> list[Mailbox]:
    clauses, params = [], {}
    if domain:
        clauses.append("domain_id = (SELECT id FROM domains WHERE domain = %(d)s)")
        params["d"] = domain.value if isinstance(domain, DomainName) else domain
    if term:
        clauses.append("email ILIKE %(flt)s ESCAPE '\\'")
        params["flt"] = _like_term(term)
    if active is not None:
        clauses.append("active = %(active)s")
        params["active"] = active
    c, p = _created_clauses(created_since, created_until)
    clauses += c
    params.update(p)
    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    cur.execute(f"SELECT {_USER_COLS} FROM users{where} ORDER BY email", params)
    return [Mailbox.from_row(r) for r in cur.fetchall()]


def get_user(cur, email: EmailAddress) -> Mailbox | None:
    cur.execute(f"SELECT {_USER_COLS} FROM users WHERE email = %(e)s", {"e": email.value})
    row = cur.fetchone()
    return Mailbox.from_row(row) if row else None


def create_user(cur, mailbox: Mailbox, password_hash: str) -> Mailbox:
    domain = mailbox.email.domain.value
    cur.execute("SELECT id FROM domains WHERE domain = %(d)s", {"d": domain})
    row = cur.fetchone()
    if not row:
        raise UnprocessableError(msg="Domain does not exist", detail={"domain": domain})
    domain_id = row["id"]
    try:
        cur.execute(
            f"INSERT INTO users (email, domain_id, password, quota_bytes, active) "
            f"VALUES (%(e)s, %(did)s, %(p)s, %(q)s, %(a)s) RETURNING {_USER_COLS}",
            {"e": mailbox.email.value, "did": domain_id, "p": password_hash,
             "q": mailbox.quota_bytes, "a": mailbox.active},
        )
    except errors.ForeignKeyViolation:
        raise UnprocessableError(msg="Referenced domain does not exist", detail={"email": mailbox.email.value})
    except errors.UniqueViolation:
        raise ConflictError(msg="User already exists", detail={"email": mailbox.email.value})
    return Mailbox.from_row(cur.fetchone())


def update_user(cur, email: EmailAddress, quota_bytes, active) -> Mailbox | None:
    cur.execute(
        f"UPDATE users SET "
        f"quota_bytes = COALESCE(%(q)s, quota_bytes), "
        f"active = COALESCE(%(a)s, active) "
        f"WHERE email = %(e)s RETURNING {_USER_COLS}",
        {"e": email.value, "q": quota_bytes, "a": active},
    )
    row = cur.fetchone()
    return Mailbox.from_row(row) if row else None


def set_user_password(cur, email: EmailAddress, password_hash) -> bool:
    cur.execute("UPDATE users SET password = %(p)s WHERE email = %(e)s",
                {"p": password_hash, "e": email.value})
    return cur.rowcount > 0


def delete_user(cur, email: EmailAddress) -> dict | None:
    cur.execute("DELETE FROM users WHERE email = %(e)s", {"e": email.value})
    if cur.rowcount == 0:
        return None
    cur.execute("DELETE FROM forwardings WHERE source = %(e)s OR destination = %(e)s", {"e": email.value})
    forwardings_deleted = cur.rowcount
    cur.execute("DELETE FROM sender_login_maps WHERE login_email = %(e)s OR allowed_sender = %(e)s", {"e": email.value})
    sender_logins_deleted = cur.rowcount
    return {"forwardings_deleted": forwardings_deleted, "sender_logins_deleted": sender_logins_deleted}


# ── forwardings ──────────────────────────────────────────────────────────────
def list_forwardings(cur, source=None, domain=None, term=None, active=None,
                     keep_copy=None, created_since=None, created_until=None) -> list[Forwarding]:
    clauses, params = [], {}
    if source:
        clauses.append("source = %(src)s")
        params["src"] = source.value if isinstance(source, EmailAddress) else source
    if domain:
        clauses.append("split_part(source, '@', 2) = %(dom)s")
        params["dom"] = domain.value if isinstance(domain, DomainName) else domain
    if term:
        clauses.append("(source ILIKE %(flt)s ESCAPE '\\' OR destination ILIKE %(flt)s ESCAPE '\\')")
        params["flt"] = _like_term(term)
    if active is not None:
        clauses.append("active = %(active)s")
        params["active"] = active
    if keep_copy is not None:
        clauses.append("keep_copy = %(keep_copy)s")
        params["keep_copy"] = keep_copy
    c, p = _created_clauses(created_since, created_until)
    clauses += c
    params.update(p)
    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    cur.execute(f"SELECT {_FWD_COLS} FROM forwardings{where} ORDER BY source, destination", params)
    return [Forwarding.from_row(r) for r in cur.fetchall()]


def create_forwarding(cur, fwd: Forwarding) -> Forwarding:
    try:
        cur.execute(
            f"INSERT INTO forwardings (source, destination, keep_copy) "
            f"VALUES (%(s)s, %(d)s, %(k)s) RETURNING {_FWD_COLS}",
            {"s": fwd.source.value, "d": fwd.destination.value, "k": fwd.keep_copy},
        )
    except errors.UniqueViolation:
        raise ConflictError(msg="Forwarding already exists",
                            detail={"source": fwd.source.value, "destination": fwd.destination.value})
    return Forwarding.from_row(cur.fetchone())


def delete_forwarding(cur, fid: int) -> bool:
    cur.execute("DELETE FROM forwardings WHERE id = %(i)s", {"i": fid})
    return cur.rowcount > 0


# ── sender_login_maps ────────────────────────────────────────────────────────
def list_sender_logins(cur, domain=None, term=None, active=None,
                       created_since=None, created_until=None) -> list[SenderLogin]:
    clauses, params = [], {}
    if domain:
        clauses.append("split_part(allowed_sender, '@', 2) = %(d)s")
        params["d"] = domain.value if isinstance(domain, DomainName) else domain
    if term:
        clauses.append("(login_email ILIKE %(flt)s ESCAPE '\\' OR allowed_sender ILIKE %(flt)s ESCAPE '\\')")
        params["flt"] = _like_term(term)
    if active is not None:
        clauses.append("active = %(active)s")
        params["active"] = active
    c, p = _created_clauses(created_since, created_until)
    clauses += c
    params.update(p)
    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    cur.execute(
        f"SELECT {_SLM_COLS} FROM sender_login_maps{where} "
        f"ORDER BY allowed_sender, login_email",
        params,
    )
    return [SenderLogin.from_row(r) for r in cur.fetchall()]


def create_sender_login(cur, grant: SenderLogin) -> SenderLogin:
    try:
        cur.execute(
            f"INSERT INTO sender_login_maps (login_email, allowed_sender) "
            f"VALUES (%(l)s, %(a)s) RETURNING {_SLM_COLS}",
            {"l": grant.login_email.value, "a": grant.allowed_sender.value},
        )
    except errors.UniqueViolation:
        raise ConflictError(msg="Sender-login grant already exists",
                            detail={"login_email": grant.login_email.value,
                                    "allowed_sender": grant.allowed_sender.value})
    return SenderLogin.from_row(cur.fetchone())


def delete_sender_login(cur, sid: int) -> bool:
    cur.execute("DELETE FROM sender_login_maps WHERE id = %(i)s", {"i": sid})
    return cur.rowcount > 0


# ── audit_logs (read-only) ───────────────────────────────────────────────────
def list_audit(cur, login=None, event_type=None, since=None, until=None, limit=100,
               success=None, queue_id=None, message_id=None, host=None,
               src_ip=None, sender=None, recipient=None) -> list[AuditEntry]:
    clauses, params = [], {"lim": limit}
    if login:
        clauses.append("login = %(login)s")
        params["login"] = login
    if event_type:
        clauses.append("event_type = %(et)s")
        params["et"] = event_type
    if since:
        clauses.append('"timestamp" >= %(since)s')
        params["since"] = since
    if until:
        clauses.append('"timestamp" <= %(until)s')
        params["until"] = until
    if success is not None:
        clauses.append("success = %(success)s")
        params["success"] = success
    if queue_id:
        clauses.append("queue_id = %(queue_id)s")
        params["queue_id"] = queue_id
    if message_id:
        clauses.append("message_id = %(message_id)s")
        params["message_id"] = message_id
    if host:
        clauses.append("host = %(host)s")
        params["host"] = host
    if src_ip:
        clauses.append("host(src_ip) = %(src_ip)s")
        params["src_ip"] = src_ip
    if sender:
        clauses.append("sender = %(sender)s")
        params["sender"] = sender
    if recipient:
        clauses.append("recipient = %(recipient)s")
        params["recipient"] = recipient
    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    cur.execute(
        f'SELECT {_AUDIT_COLS} FROM audit_logs{where} '
        f'ORDER BY "timestamp" DESC LIMIT %(lim)s',
        params,
    )
    return [AuditEntry.from_row(r) for r in cur.fetchall()]


# ── metrics aggregation (counts grouped by domain; filtered per-scope by caller) ─
def list_domain_names(cur) -> list[str]:
    cur.execute("SELECT domain FROM domains")
    return [r["domain"] for r in cur.fetchall()]


def _count_by_domain(cur, table: str, domain_expr: str) -> dict[str, int]:
    # table/domain_expr are module constants, never user input
    cur.execute(f"SELECT {domain_expr} AS dom, count(*) AS count FROM {table} GROUP BY dom")
    return {r["dom"]: r["count"] for r in cur.fetchall()}


def count_users_by_domain(cur) -> dict[str, int]:
    return _count_by_domain(cur, "users", "split_part(email, '@', 2)")


def count_forwardings_by_domain(cur) -> dict[str, int]:
    return _count_by_domain(cur, "forwardings", "split_part(source, '@', 2)")


def count_sender_logins_by_domain(cur) -> dict[str, int]:
    return _count_by_domain(cur, "sender_login_maps", "split_part(allowed_sender, '@', 2)")


def count_audit_by_domain(cur, since) -> list[dict]:
    cur.execute(
        "SELECT event_type, success, "
        "CASE event_type "
        "WHEN 'auth' THEN split_part(login, '@', 2) "
        "WHEN 'send' THEN split_part(sender, '@', 2) "
        "WHEN 'delivery' THEN split_part(recipient, '@', 2) "
        "END AS dom, count(*) AS count "
        'FROM audit_logs WHERE "timestamp" >= %(since)s '
        "GROUP BY event_type, success, dom",
        {"since": since},
    )
    return list(cur.fetchall())
