import os
import hmac
import hashlib
import base64
import contextlib
import pytest

RAW_KEY = b"0123456789abcdef0123456789abcdef"
KEY_B64 = base64.b64encode(RAW_KEY).decode()


def _hmac_hex(token):
    return hmac.new(RAW_KEY, token.encode(), hashlib.sha256).hexdigest()


class FakeCursor:
    def __init__(self, store):
        self.store = store
        self._result = []
        self.rowcount = 0

    def execute(self, sql, params=None):
        # Minimal router: enough for the route tests below.
        s = sql.lower()
        if "from domains" in s and "select" in s:
            self._result = list(self.store["domains"])
            if params and params.get("d"):
                self._result = [r for r in self._result if r["domain"] == params["d"]]
        elif "insert into domains" in s:
            row = {"id": 1, "domain": params["d"], "dkim_selector": params["s"],
                   "active": params["a"], "created_at": "2026-06-21T00:00:00+00:00"}
            self.store["domains"].append(row)
            self._result = [row]
        else:
            self._result = []
        self.rowcount = len(self._result)

    def fetchall(self):
        return list(self._result)

    def fetchone(self):
        return self._result[0] if self._result else None


class FakeDB:
    def __init__(self):
        self.store = {"domains": [{"id": 1, "domain": "example.com",
                                   "dkim_selector": "default", "active": True,
                                   "created_at": "2026-06-21T00:00:00+00:00"}]}

    @contextlib.contextmanager
    def transaction(self):
        yield FakeCursor(self.store)


@pytest.fixture
def client(monkeypatch, tmp_path):
    conf = tmp_path / "config.yaml"
    conf.write_text(
        "identities:\n"
        "  - id: admin\n"
        "    allowed_cidrs: [\"0.0.0.0/0\"]\n"
        "    permissions: [\"*:*\"]\n"
        "  - id: ro\n"
        "    allowed_cidrs: [\"0.0.0.0/0\"]\n"
        "    permissions: [\"other.com:read_domain\"]\n"
    )
    monkeypatch.setenv("HMAC_KEY_B64", KEY_B64)
    monkeypatch.setenv("PG_HOST", "db")
    monkeypatch.setenv("PG_DBNAME", "maildb")
    monkeypatch.setenv("PG_USER", "mail_admin_rw")
    monkeypatch.setenv("PG_PASSWORD", "x")
    monkeypatch.setenv("CONF_FILE", str(conf))
    monkeypatch.setenv("TOKEN_ADMIN_HMAC", _hmac_hex("adm"))
    monkeypatch.setenv("TOKEN_RO_HMAC", _hmac_hex("ro"))

    from mail_controller.app import create_app
    app = create_app(database=FakeDB())
    app.testing = True
    return app.test_client()


def _auth(token_id, token):
    return {"Authorization": f"Bearer {token_id}.{token}"}


def test_ping(client):
    assert client.get("/ping").data == b"pong"


def test_version_unauthenticated(client):
    r = client.get("/api/version")
    assert r.status_code == 200
    assert r.get_json()["data"]["name"] == "Mail controller"


def test_list_domains_requires_auth(client):
    assert client.get("/api/domains").status_code == 401


def test_list_domains_filters_to_readable(client):
    r = client.get("/api/domains", headers=_auth("ro", "ro"))
    assert r.status_code == 200
    # ro can read only other.com, store has example.com -> empty
    assert r.get_json()["data"] == []


def test_admin_creates_domain(client):
    r = client.post("/api/domains", json={"domain": "new.test"}, headers=_auth("admin", "adm"))
    assert r.status_code == 201, r.get_json()
    assert r.get_json()["data"]["domain"] == "new.test"


def test_ro_cannot_create_domain(client):
    r = client.post("/api/domains", json={"domain": "x.test"}, headers=_auth("ro", "ro"))
    assert r.status_code == 403


def test_token_identity(client):
    r = client.get("/api/token/identity", headers=_auth("admin", "adm"))
    assert r.get_json()["data"]["id"] == "admin"
