import pytest
from mail_controller.db import repository as repo
from mail_controller.exception.api_exceptions import UnprocessableError


class FakeCursor:
    """Records SQL + params; returns canned rows. No real DB."""
    def __init__(self, rows=None, rowcount=1):
        self.rows = rows or []
        self.rowcount = rowcount
        self.executed = []  # list of (sql, params)

    def execute(self, sql, params=None):
        self.executed.append((sql, params))

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
