"""All SQL for mail-controller. Fully parameterized; no f-string interpolation of
user data. Reads/writes the mail-server schema via the mail_admin_rw role."""
import psycopg2
from psycopg2 import errors
from mail_controller.exception.api_exceptions import ConflictError, UnprocessableError
from mail_controller.domain.domain import Domain
from mail_controller.domain.address import DomainName, EmailAddress
from mail_controller.domain.mailbox import Mailbox

_USER_COLS = "id, email, quota_bytes, active, created_at, domain_id"
_DOMAIN_COLS = "id, domain, dkim_selector, active, created_at"
_FWD_COLS = "id, source, destination, keep_copy, active, created_at"
_SLM_COLS = "id, login_email, allowed_sender, active, created_at"
_AUDIT_COLS = ('id, event_type, success, login, host(src_ip) AS src_ip, host, '
               'sender, recipient, message_id, queue_id, score, msg, pid, "timestamp"')


# ── domains ────────────────────────────────────────────────────────────────
def list_domains(cur, term=None) -> list[Domain]:
    where, params = "", {}
    if term:
        where = " WHERE domain ILIKE %(flt)s"
        params["flt"] = f"%{term}%"
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
def list_users(cur, domain=None, term=None) -> list[Mailbox]:
    clauses, params = [], {}
    if domain:
        clauses.append("domain_id = (SELECT id FROM domains WHERE domain = %(d)s)")
        params["d"] = domain.value if isinstance(domain, DomainName) else domain
    if term:
        clauses.append("email ILIKE %(flt)s")
        params["flt"] = f"%{term}%"
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
def list_forwardings(cur, source=None, domain=None, term=None) -> list[dict]:
    clauses, params = [], {}
    if source:
        clauses.append("source = %(src)s")
        params["src"] = source
    if domain:
        clauses.append("split_part(source, '@', 2) = %(dom)s")
        params["dom"] = domain
    if term:
        clauses.append("(source ILIKE %(flt)s OR destination ILIKE %(flt)s)")
        params["flt"] = f"%{term}%"
    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    cur.execute(f"SELECT {_FWD_COLS} FROM forwardings{where} ORDER BY source, destination", params)
    return cur.fetchall()


def create_forwarding(cur, source, destination, keep_copy) -> dict:
    try:
        cur.execute(
            f"INSERT INTO forwardings (source, destination, keep_copy) "
            f"VALUES (%(s)s, %(d)s, %(k)s) RETURNING {_FWD_COLS}",
            {"s": source, "d": destination, "k": keep_copy},
        )
    except errors.UniqueViolation:
        raise ConflictError(msg="Forwarding already exists",
                            detail={"source": source, "destination": destination})
    return cur.fetchone()


def delete_forwarding(cur, fid: int) -> bool:
    cur.execute("DELETE FROM forwardings WHERE id = %(i)s", {"i": fid})
    return cur.rowcount > 0


# ── sender_login_maps ────────────────────────────────────────────────────────
def list_sender_logins(cur, domain=None, term=None) -> list[dict]:
    clauses, params = [], {}
    if domain:
        clauses.append("split_part(allowed_sender, '@', 2) = %(d)s")
        params["d"] = domain
    if term:
        clauses.append("(login_email ILIKE %(flt)s OR allowed_sender ILIKE %(flt)s)")
        params["flt"] = f"%{term}%"
    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    cur.execute(
        f"SELECT {_SLM_COLS} FROM sender_login_maps{where} "
        f"ORDER BY allowed_sender, login_email",
        params,
    )
    return cur.fetchall()


def create_sender_login(cur, login_email, allowed_sender) -> dict:
    try:
        cur.execute(
            f"INSERT INTO sender_login_maps (login_email, allowed_sender) "
            f"VALUES (%(l)s, %(a)s) RETURNING {_SLM_COLS}",
            {"l": login_email, "a": allowed_sender},
        )
    except errors.UniqueViolation:
        raise ConflictError(msg="Sender-login grant already exists",
                            detail={"login_email": login_email, "allowed_sender": allowed_sender})
    return cur.fetchone()


def delete_sender_login(cur, sid: int) -> bool:
    cur.execute("DELETE FROM sender_login_maps WHERE id = %(i)s", {"i": sid})
    return cur.rowcount > 0


# ── audit_logs (read-only) ───────────────────────────────────────────────────
def list_audit(cur, login=None, event_type=None, since=None, until=None, limit=100) -> list[dict]:
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
    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    cur.execute(
        f'SELECT {_AUDIT_COLS} FROM audit_logs{where} '
        f'ORDER BY "timestamp" DESC LIMIT %(lim)s',
        params,
    )
    return cur.fetchall()
