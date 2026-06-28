import base64
import hmac
import hashlib
import textwrap
import pytest
from werkzeug.middleware.proxy_fix import ProxyFix
from mail_controller.app import create_app

RAW_KEY = b"0123456789abcdef0123456789abcdef"
KEY_B64 = base64.b64encode(RAW_KEY).decode()


def _hmac_hex(token):
    return hmac.new(RAW_KEY, token.encode(), hashlib.sha256).hexdigest()


def _env(monkeypatch, tmp_path, hops=None):
    conf = tmp_path / "config.yaml"
    conf.write_text(textwrap.dedent("""
        identities:
          - id: admin
            allowed_cidrs: ["0.0.0.0/0"]
            permissions: ["*:*"]
    """))
    monkeypatch.setenv("HMAC_KEY_B64", KEY_B64)
    monkeypatch.setenv("PG_HOST", "db")
    monkeypatch.setenv("PG_DBNAME", "maildb")
    monkeypatch.setenv("PG_USER", "mail_admin_rw")
    monkeypatch.setenv("PG_PASSWORD", "x")
    monkeypatch.setenv("CONF_FILE", str(conf))
    monkeypatch.setenv("TOKEN_ADMIN_HMAC", _hmac_hex("adm"))
    if hops is None:
        monkeypatch.delenv("TRUSTED_PROXY_HOPS", raising=False)
    else:
        monkeypatch.setenv("TRUSTED_PROXY_HOPS", str(hops))


def test_no_proxyfix_when_hops_zero(monkeypatch, tmp_path):
    _env(monkeypatch, tmp_path, hops=0)
    app = create_app(database=object())
    assert not isinstance(app.wsgi_app, ProxyFix)


def test_proxyfix_applied_when_hops_positive(monkeypatch, tmp_path):
    _env(monkeypatch, tmp_path, hops=2)
    app = create_app(database=object())
    assert isinstance(app.wsgi_app, ProxyFix)
    assert app.wsgi_app.x_for == 2
