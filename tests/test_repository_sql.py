import pytest
from mail_controller.db import repository as repo
from mail_controller.exception.api_exceptions import UnprocessableError


class FakeCursor:
    """Records SQL + params; returns canned rows. No real DB."""
    def __init__(self, rows=None, rowcount=1, rowcounts=None):
        self.rows = rows or []
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
        return list(self.rows)

    def fetchone(self):
        return self.rows[0] if self.rows else None

    @property
    def last_sql(self):
        return self.executed[-1][0]

    @property
    def all_sql(self):
        return " ".join(s for s, _ in self.executed)


def test_list_users_never_selects_password():
    cur = FakeCursor(rows=[{"email": "a@x.test", "active": True}])
    repo.list_users(cur)
    assert "password" not in cur.all_sql.lower()


def test_get_user_never_selects_password():
    cur = FakeCursor(rows=[{"email": "a@x.test"}])
    repo.get_user(cur, "a@x.test")
    assert "password" not in cur.all_sql.lower()


def test_list_users_filter_by_domain_is_parameterized():
    cur = FakeCursor(rows=[])
    repo.list_users(cur, domain="example.com")
    sql, params = cur.executed[-1]
    assert "%(" in sql or "%s" in sql
    assert "example.com" in str(params)


def test_create_user_resolves_domain_id_first():
    # first execute resolves the domain; canned row gives its id
    cur = FakeCursor(rows=[{"id": 7}])
    repo.create_user(cur, "a@example.com", "example.com",
                     "{ARGON2ID}$argon2id$x", 0, True)
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
    cur = FakeCursor(rows=[])
    with pytest.raises(UnprocessableError):
        repo.create_user(cur, "a@example.com", "example.com",
                         "{ARGON2ID}$x", 0, True)


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
    cur = FakeCursor(rowcounts=[1, 3, 2])
    result = repo.delete_user(cur, "alice@example.com")

    sql = cur.all_sql.lower()
    assert "delete from forwardings" in sql
    assert "source" in sql and "destination" in sql
    assert "delete from sender_login_maps" in sql
    assert "login_email" in sql and "allowed_sender" in sql
    # every execute is parameterized by the email, not interpolated
    assert all(p == {"e": "alice@example.com"} for _, p in cur.executed)
    assert result == {"forwardings_deleted": 3, "sender_logins_deleted": 2}


def test_delete_user_absent_returns_none_and_skips_cascade():
    cur = FakeCursor(rowcounts=[0])  # no user row matched
    result = repo.delete_user(cur, "ghost@example.com")

    assert result is None
    assert len(cur.executed) == 1  # only the users DELETE ran; no cascade
    assert "forwardings" not in cur.all_sql.lower()
    assert "sender_login_maps" not in cur.all_sql.lower()
