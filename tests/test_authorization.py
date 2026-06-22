import os
import hmac
import hashlib
import pytest
from flask import Flask
from mail_controller.domain.identity import Identity
from mail_controller.domain.permission import PermissionAction
from mail_controller.api.context import Context
from mail_controller.conf.config import Config
from mail_controller.exception.api_exceptions import PermissionDeniedError

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


def test_require_write_allowed(monkeypatch):
    ident = _ident(monkeypatch, "a", ["example.com:write"])
    app = _app_with(ident)
    with app.test_request_context("/"):
        _ctx(ident).require("example.com", PermissionAction.WRITE)  # no raise


def test_require_write_denied_for_read_only(monkeypatch):
    ident = _ident(monkeypatch, "a", ["example.com:read"])
    app = _app_with(ident)
    with app.test_request_context("/"):
        with pytest.raises(PermissionDeniedError):
            _ctx(ident).require("example.com", PermissionAction.WRITE)


def test_require_denied_wrong_domain(monkeypatch):
    ident = _ident(monkeypatch, "a", ["example.com:write"])
    app = _app_with(ident)
    with app.test_request_context("/"):
        with pytest.raises(PermissionDeniedError):
            _ctx(ident).require("other.com", PermissionAction.WRITE)


def test_filter_readable_by_domain_field(monkeypatch):
    ident = _ident(monkeypatch, "a", ["example.com:read"])
    app = _app_with(ident)
    rows = [{"domain": "example.com"}, {"domain": "other.com"}]
    with app.test_request_context("/"):
        out = _ctx(ident).filter_readable(rows, "domain")
    assert out == [{"domain": "example.com"}]


def test_filter_readable_by_email_field(monkeypatch):
    ident = _ident(monkeypatch, "a", ["example.com:read"])
    app = _app_with(ident)
    rows = [{"email": "u@example.com"}, {"email": "u@other.com"}]
    with app.test_request_context("/"):
        out = _ctx(ident).filter_readable(rows, "email")
    assert out == [{"email": "u@example.com"}]


def test_filter_audit_null_login_requires_star(monkeypatch):
    star = _ident(monkeypatch, "s", ["*:read"], token="t")
    scoped = _ident(monkeypatch, "x", ["example.com:read"], token="t")
    rows = [{"login": None}, {"login": "u@example.com"}]
    app = _app_with(star)
    with app.test_request_context("/"):
        assert _ctx(star).filter_readable(rows, "login") == rows
    app2 = _app_with(scoped)
    with app2.test_request_context("/"):
        assert _ctx(scoped).filter_readable(rows, "login") == [{"login": "u@example.com"}]


def test_filter_audit_malformed_login(monkeypatch):
    # A bare SASL username (no @) must not raise; it is treated like a null login.
    star = _ident(monkeypatch, "s", ["*:read"], token="t")
    scoped = _ident(monkeypatch, "x", ["example.com:read"], token="t")
    rows = [
        {"login": "garbage"},           # malformed — no @
        {"login": "u@example.com"},     # valid, scoped reader can see
        {"login": "u@other.com"},       # valid, scoped reader cannot see
    ]
    # *-scope reader keeps malformed row (same as null treatment)
    app_star = _app_with(star)
    with app_star.test_request_context("/"):
        result = _ctx(star).filter_readable(rows, "login")
    assert result == rows, "star reader should keep all rows including malformed"

    # scoped reader drops malformed row silently; keeps only its own domain
    app_scoped = _app_with(scoped)
    with app_scoped.test_request_context("/"):
        result = _ctx(scoped).filter_readable(rows, "login")
    assert result == [{"login": "u@example.com"}], "scoped reader should drop malformed and foreign rows"
