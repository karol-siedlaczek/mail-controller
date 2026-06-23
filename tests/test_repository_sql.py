import pytest
from mail_controller.db import repository as repo
from mail_controller.exception.api_exceptions import UnprocessableError


class FakeCursor:
    """Records SQL + params; returns canned rows. No real DB."""
    def __init__(self, rows=None, rowcount=1, rowcounts=None):
        self._rows = list(rows) if rows else []
        self.rowcount = rowcount
        # Optional per-execute() rowcount queue; each execute() pops the next
        # value so a sequence of statements can report different rowcounts.
        self._rowcounts = list(rowcounts) if rowcounts is not None else None
        self.executed = []  # list of (sql, params)

    def execute(self, sql, params=None):
        self.executed.append((sql, params))
        if self._rowcounts:
            self.rowcount = self._rowcounts.pop(0)

    def fetchall(self):
        return list(self._rows)

    def fetchone(self):
        return self._rows.pop(0) if self._rows else None

    @property
    def last_sql(self):
        return self.executed[-1][0]

    @property
    def all_sql(self):
        return " ".join(s for s, _ in self.executed)

    def all_sql_params(self):
        vals = []
        for _, p in self.executed:
            if isinstance(p, dict):
                vals.extend(p.values())
        return vals


def test_list_users_never_selects_password():
    cur = FakeCursor(rows=[{"id": 1, "email": "a@x.test", "quota_bytes": 0,
                             "active": True, "created_at": None, "domain_id": 1}])
    repo.list_users(cur)
    assert "password" not in cur.all_sql.lower()


def test_get_user_never_selects_password():
    cur = FakeCursor(rows=[{"email": "a@x.test", "id": 1, "quota_bytes": 0,
                             "active": True, "created_at": None, "domain_id": 1}])
    from mail_controller.domain.address import EmailAddress
    repo.get_user(cur, EmailAddress("a@x.test"))
    assert "password" not in cur.all_sql.lower()


def test_list_users_filter_by_domain_is_parameterized():
    cur = FakeCursor(rows=[])
    repo.list_users(cur, domain="example.com")
    sql, params = cur.executed[-1]
    assert "%(" in sql or "%s" in sql
    assert "example.com" in str(params)


def test_create_user_resolves_domain_id_first():
    # first execute resolves the domain; canned row gives its id
    # second row is the INSERT RETURNING result
    from mail_controller.domain.mailbox import Mailbox
    from mail_controller.domain.address import EmailAddress
    _row = {"id": 7, "email": "a@example.com", "quota_bytes": 0,
            "active": True, "created_at": None, "domain_id": 1}
    cur = FakeCursor(rows=[{"id": 7}, _row])
    mailbox = Mailbox(email=EmailAddress("a@example.com"), quota_bytes=0, active=True)
    repo.create_user(cur, mailbox, "{ARGON2ID}$argon2id$x")
    # the INSERT into users must be parameterized and reference domain_id
    assert "insert into users" in cur.all_sql.lower()
    assert "domain_id" in cur.all_sql.lower()


def test_list_audit_limit_is_parameterized():
    cur = FakeCursor(rows=[])
    repo.list_audit(cur, limit=50)
    sql, params = cur.executed[-1]
    assert "limit" in sql.lower()
    assert 50 in (params.values() if isinstance(params, dict) else params)


def test_create_user_missing_domain_raises_unprocessable():
    # fetchone() returns None because rows=[] — domain lookup finds nothing
    from mail_controller.domain.mailbox import Mailbox
    from mail_controller.domain.address import EmailAddress
    cur = FakeCursor(rows=[])
    with pytest.raises(UnprocessableError):
        mailbox = Mailbox(email=EmailAddress("a@example.com"), quota_bytes=0, active=True)
        repo.create_user(cur, mailbox, "{ARGON2ID}$x")


# ── substring (--filter) tests ───────────────────────────────────────────────
def test_list_domains_filter_is_parameterized_ilike():
    cur = FakeCursor(rows=[])
    repo.list_domains(cur, term="exam")
    sql, params = cur.executed[-1]
    assert "ilike" in sql.lower()
    assert "%exam%" in params.values()


def test_list_domains_without_filter_has_no_where():
    cur = FakeCursor(rows=[])
    repo.list_domains(cur)
    sql, params = cur.executed[-1]
    assert "where" not in sql.lower()
    assert params == {}


def test_list_users_filter_matches_email_with_ilike():
    cur = FakeCursor(rows=[])
    repo.list_users(cur, term="admin")
    sql, params = cur.executed[-1]
    assert "email ilike" in sql.lower()
    assert "%admin%" in params.values()


def test_list_users_filter_and_domain_combine():
    cur = FakeCursor(rows=[])
    repo.list_users(cur, domain="example.com", term="admin")
    sql, params = cur.executed[-1]
    assert " and " in sql.lower()
    assert "example.com" in params.values()
    assert "%admin%" in params.values()


def test_list_forwardings_filter_matches_source_or_destination():
    cur = FakeCursor(rows=[])
    repo.list_forwardings(cur, term="sales")
    sql, params = cur.executed[-1]
    assert "source ilike" in sql.lower()
    assert "destination ilike" in sql.lower()
    assert "%sales%" in params.values()


def test_list_sender_logins_filter_matches_login_or_allowed_sender():
    cur = FakeCursor(rows=[])
    repo.list_sender_logins(cur, term="ops")
    sql, params = cur.executed[-1]
    assert "login_email ilike" in sql.lower()
    assert "allowed_sender ilike" in sql.lower()
    assert "%ops%" in params.values()


def test_list_sender_logins_without_filter_has_no_where():
    cur = FakeCursor(rows=[])
    repo.list_sender_logins(cur)
    sql, params = cur.executed[-1]
    assert "where" not in sql.lower()


# ── audit --until tests ──────────────────────────────────────────────────────
def test_list_audit_until_is_parameterized():
    cur = FakeCursor(rows=[])
    repo.list_audit(cur, until="2026-06-30")
    sql, params = cur.executed[-1]
    assert "<=" in sql
    assert "2026-06-30" in params.values()


def test_list_audit_since_and_until_combine():
    cur = FakeCursor(rows=[])
    repo.list_audit(cur, since="2026-06-01", until="2026-06-30")
    sql, params = cur.executed[-1]
    assert ">=" in sql
    assert "<=" in sql
    assert "2026-06-01" in params.values()
    assert "2026-06-30" in params.values()


# ── delete_user cascade cleanup tests ────────────────────────────────────────
def test_delete_user_cascades_forwardings_and_sender_logins():
    # rowcounts: users delete=1, forwardings delete=3, sender_login_maps delete=2
    from mail_controller.domain.address import EmailAddress
    cur = FakeCursor(rowcounts=[1, 3, 2])
    result = repo.delete_user(cur, EmailAddress("alice@example.com"))

    sql = cur.all_sql.lower()
    assert "delete from forwardings" in sql
    assert "source" in sql and "destination" in sql
    assert "delete from sender_login_maps" in sql
    assert "login_email" in sql and "allowed_sender" in sql
    # every execute is parameterized by the email, not interpolated
    assert all(p == {"e": "alice@example.com"} for _, p in cur.executed)
    assert result == {"forwardings_deleted": 3, "sender_logins_deleted": 2}


def test_delete_user_absent_returns_none_and_skips_cascade():
    from mail_controller.domain.address import EmailAddress
    cur = FakeCursor(rowcounts=[0])  # no user row matched
    result = repo.delete_user(cur, EmailAddress("ghost@example.com"))

    assert result is None
    assert len(cur.executed) == 1  # only the users DELETE ran; no cascade
    assert "forwardings" not in cur.all_sql.lower()
    assert "sender_login_maps" not in cur.all_sql.lower()


# ── domain entity tests ──────────────────────────────────────────────────────
from mail_controller.domain.domain import Domain
from mail_controller.domain.address import DomainName

_DOMAIN_ROW = {"id": 1, "domain": "example.com", "dkim_selector": "default",
               "active": True, "created_at": None}


def test_list_domains_returns_domain_entities():
    cur = FakeCursor(rows=[_DOMAIN_ROW])
    result = repo.list_domains(cur)
    assert result == [Domain.from_row(_DOMAIN_ROW)]


def test_create_domain_binds_value_and_returns_entity():
    cur = FakeCursor(rows=[_DOMAIN_ROW])
    entity = Domain(name=DomainName("example.com"), dkim_selector="default", active=True)
    result = repo.create_domain(cur, entity)
    _, params = cur.executed[-1]
    assert "example.com" in params.values()
    assert result == Domain.from_row(_DOMAIN_ROW)


# ── mailbox entity tests ─────────────────────────────────────────────────────
from mail_controller.domain.mailbox import Mailbox
from mail_controller.domain.address import EmailAddress

_USER_ROW = {"id": 5, "email": "alice@example.com", "quota_bytes": 0,
             "active": True, "created_at": None, "domain_id": 1}


def test_list_users_returns_mailbox_entities():
    cur = FakeCursor(rows=[_USER_ROW])
    assert repo.list_users(cur) == [Mailbox.from_row(_USER_ROW)]
    assert "password" not in cur.all_sql.lower()


def test_create_user_binds_email_and_hash():
    cur = FakeCursor(rows=[{"id": 7}, _USER_ROW])  # domain lookup, then INSERT RETURNING
    mailbox = Mailbox(email=EmailAddress("alice@example.com"), quota_bytes=0, active=True)
    result = repo.create_user(cur, mailbox, "{ARGON2ID}$hash")
    assert "alice@example.com" in cur.all_sql_params()
    assert "{ARGON2ID}$hash" in cur.all_sql_params()
    assert result == Mailbox.from_row(_USER_ROW)


# ── forwarding entity tests ──────────────────────────────────────────────────
from mail_controller.domain.forwarding import Forwarding

_FWD_ROW = {"id": 3, "source": "a@example.com", "destination": "b@elsewhere.test",
            "keep_copy": False, "active": True, "created_at": None}


def test_list_forwardings_returns_entities():
    cur = FakeCursor(rows=[_FWD_ROW])
    assert repo.list_forwardings(cur) == [Forwarding.from_row(_FWD_ROW)]


def test_create_forwarding_binds_values_and_returns_entity():
    cur = FakeCursor(rows=[_FWD_ROW])
    fwd = Forwarding(source=EmailAddress("a@example.com"),
                     destination=EmailAddress("b@elsewhere.test"), keep_copy=False)
    result = repo.create_forwarding(cur, fwd)
    assert "a@example.com" in cur.all_sql_params()
    assert result == Forwarding.from_row(_FWD_ROW)


# ── sender_login entity tests ────────────────────────────────────────────────
from mail_controller.domain.sender_login import SenderLogin

_SLM_ROW = {"id": 9, "login_email": "ops@example.com", "allowed_sender": "boss@example.com",
            "active": True, "created_at": None}


def test_list_sender_logins_returns_entities():
    cur = FakeCursor(rows=[_SLM_ROW])
    assert repo.list_sender_logins(cur) == [SenderLogin.from_row(_SLM_ROW)]


def test_create_sender_login_binds_values_and_returns_entity():
    cur = FakeCursor(rows=[_SLM_ROW])
    grant = SenderLogin(login_email=EmailAddress("ops@example.com"),
                        allowed_sender=EmailAddress("boss@example.com"))
    result = repo.create_sender_login(cur, grant)
    assert "ops@example.com" in cur.all_sql_params()
    assert result == SenderLogin.from_row(_SLM_ROW)


# ── audit entity tests ───────────────────────────────────────────────────────
from mail_controller.domain.audit import AuditEntry

_AUDIT_ROW = {"id": 1, "event_type": "auth", "success": True, "login": "a@example.com",
              "src_ip": "10.0.0.1", "host": "mx1", "sender": None, "recipient": None,
              "message_id": None, "queue_id": None, "score": None, "msg": "ok",
              "pid": 1, "timestamp": None}


def test_list_audit_returns_entities():
    cur = FakeCursor(rows=[_AUDIT_ROW])
    assert repo.list_audit(cur, limit=10) == [AuditEntry.from_row(_AUDIT_ROW)]
