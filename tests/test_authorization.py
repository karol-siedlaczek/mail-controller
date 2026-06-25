import os
import hmac
import hashlib
import pytest
from flask import Flask
from mail_controller.domain.identity import Identity
from mail_controller.domain.permission import Permission, PermissionAction
from mail_controller.api.context import Context
from mail_controller.api.helpers import filter_rows_to_readable
from mail_controller.conf.config import Config
from mail_controller.exception.api_exceptions import PermissionDeniedError
from mail_controller.exception.auth_exceptions import AuthTokenMissingException, AuthFailedException

RAW_KEY = b"0123456789abcdef0123456789abcdef"


def _hmac_hex(token):
    return hmac.new(RAW_KEY, token.encode(), hashlib.sha256).hexdigest()


def _ident(monkeypatch, ident_id, perms, token="t"):
    monkeypatch.setenv(f"TOKEN_{ident_id.upper()}_HMAC", _hmac_hex(token))
    return Identity.from_dict({"id": ident_id, "allowed_cidrs": ["0.0.0.0/0"], "permissions": perms})


def _app_with(identity):
    app = Flask(__name__)
    cfg = Config(hmac_key=RAW_KEY, identities=[identity])
    app.extensions["config"] = cfg
    return app


def _ctx(identity):
    return Context(remote_ip="10.0.0.1", identity=identity)


def test_authenticate_resolves_identity_and_ip(monkeypatch):
    ident = _ident(monkeypatch, "a", ["example.com:read_domain"], token="tok")
    app = _app_with(ident)
    with app.test_request_context(
        "/", headers={"Authorization": "Bearer a.tok"}, environ_base={"REMOTE_ADDR": "1.2.3.4"}
    ):
        ctx = Context.authenticate()
        assert ctx.identity.id == "a"
        assert ctx.remote_ip == "1.2.3.4"


def test_authenticate_missing_header_raises(monkeypatch):
    ident = _ident(monkeypatch, "a", ["example.com:read_domain"])
    app = _app_with(ident)
    with app.test_request_context("/", environ_base={"REMOTE_ADDR": "1.2.3.4"}):
        with pytest.raises(AuthTokenMissingException):
            Context.authenticate()


def test_authenticate_bad_token_raises(monkeypatch):
    ident = _ident(monkeypatch, "a", ["example.com:read_domain"], token="tok")
    app = _app_with(ident)
    with app.test_request_context(
        "/", headers={"Authorization": "Bearer a.WRONG"}, environ_base={"REMOTE_ADDR": "1.2.3.4"}
    ):
        with pytest.raises(AuthFailedException):
            Context.authenticate()


def test_require_write_allowed(monkeypatch):
    ident = _ident(monkeypatch, "a", ["example.com:write_domain"])
    app = _app_with(ident)
    with app.test_request_context("/"):
        _ctx(ident).require("example.com", PermissionAction.WRITE_DOMAIN)  # no raise


def test_require_write_denied_for_read_only(monkeypatch):
    ident = _ident(monkeypatch, "a", ["example.com:read_domain"])
    app = _app_with(ident)
    with app.test_request_context("/"):
        with pytest.raises(PermissionDeniedError):
            _ctx(ident).require("example.com", PermissionAction.WRITE_DOMAIN)


def test_require_denied_wrong_domain(monkeypatch):
    ident = _ident(monkeypatch, "a", ["example.com:write_domain"])
    app = _app_with(ident)
    with app.test_request_context("/"):
        with pytest.raises(PermissionDeniedError):
            _ctx(ident).require("other.com", PermissionAction.WRITE_DOMAIN)


def test_filter_readable_by_domain_field(monkeypatch):
    ident = _ident(monkeypatch, "a", ["example.com:read_domain"])
    app = _app_with(ident)
    rows = [{"domain": "example.com"}, {"domain": "other.com"}]
    with app.test_request_context("/"):
        out = filter_rows_to_readable(_ctx(ident), rows, lambda r: r["domain"], PermissionAction.READ_DOMAIN)
    assert out == [{"domain": "example.com"}]


def test_filter_readable_by_email_field(monkeypatch):
    ident = _ident(monkeypatch, "a", ["example.com:read_user"])
    app = _app_with(ident)
    rows = [{"email": "u@example.com"}, {"email": "u@other.com"}]
    with app.test_request_context("/"):
        out = filter_rows_to_readable(_ctx(ident), rows, lambda r: r["email"].rsplit("@", 1)[1], PermissionAction.READ_USER)
    assert out == [{"email": "u@example.com"}]


def _login_domain(r):
    login = r["login"]
    if login and "@" in login:
        return login.rsplit("@", 1)[1]
    return None


def test_filter_audit_null_login_requires_star(monkeypatch):
    star = _ident(monkeypatch, "s", ["*:read_audit"], token="t")
    scoped = _ident(monkeypatch, "x", ["example.com:read_audit"], token="t")
    rows = [{"login": None}, {"login": "u@example.com"}]
    app = _app_with(star)
    with app.test_request_context("/"):
        assert filter_rows_to_readable(_ctx(star), rows, _login_domain, PermissionAction.READ_AUDIT) == rows
    app2 = _app_with(scoped)
    with app2.test_request_context("/"):
        assert filter_rows_to_readable(_ctx(scoped), rows, _login_domain, PermissionAction.READ_AUDIT) == [{"login": "u@example.com"}]


def test_filter_audit_malformed_login(monkeypatch):
    # A bare SASL username (no @) must not raise; it is treated like a null login.
    star = _ident(monkeypatch, "s", ["*:read_audit"], token="t")
    scoped = _ident(monkeypatch, "x", ["example.com:read_audit"], token="t")
    rows = [
        {"login": "garbage"},           # malformed — no @
        {"login": "u@example.com"},     # valid, scoped reader can see
        {"login": "u@other.com"},       # valid, scoped reader cannot see
    ]
    # *-scope reader keeps malformed row (same as null treatment)
    app_star = _app_with(star)
    with app_star.test_request_context("/"):
        result = filter_rows_to_readable(_ctx(star), rows, _login_domain, PermissionAction.READ_AUDIT)
    assert result == rows, "star reader should keep all rows including malformed"

    # scoped reader drops malformed row silently; keeps only its own domain
    app_scoped = _app_with(scoped)
    with app_scoped.test_request_context("/"):
        result = filter_rows_to_readable(_ctx(scoped), rows, _login_domain, PermissionAction.READ_AUDIT)
    assert result == [{"login": "u@example.com"}], "scoped reader should drop malformed and foreign rows"


def _ctx_with_scope(scope):
    perm = Permission(scope, PermissionAction.READ_DOMAIN)
    ident = Identity(id="t", hmac_hex="x" * 64, allowed_cidrs=[], permissions=[perm])
    return Context(remote_ip="127.0.0.1", identity=ident)


def test_filter_readable_uses_domain_accessor():
    ctx = _ctx_with_scope("example.com")
    rows = [{"d": "example.com"}, {"d": "other.test"}]
    visible = filter_rows_to_readable(ctx, rows, lambda r: r["d"], PermissionAction.READ_DOMAIN)
    assert visible == [{"d": "example.com"}]
