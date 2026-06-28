import os
import hmac
import hashlib
import pytest
from mail_controller.domain.identity import Identity
from mail_controller.domain.permission.permission_action import PermissionAction
from mail_controller.exception.validator_exceptions import ValidationError

KEY = b"0123456789abcdef0123456789abcdef"  # 32 bytes


def _hmac_hex(token: str) -> str:
    return hmac.new(KEY, token.encode(), hashlib.sha256).hexdigest()


def _identity(monkeypatch, token="s3cret", cidrs=None, perms=None):
    monkeypatch.setenv("TOKEN_ADMIN_HMAC", _hmac_hex(token))
    return Identity.from_dict({
        "id": "admin",
        "allowed_cidrs": cidrs if cidrs is not None else ["10.0.0.0/8", "127.0.0.1/32"],
        "permissions": perms if perms is not None else ["*:*"],
    })


def test_from_dict_ok(monkeypatch):
    ident = _identity(monkeypatch)
    assert ident.id == "admin"
    assert len(ident.permissions) == 1


def test_missing_token_env(monkeypatch):
    monkeypatch.delenv("TOKEN_ADMIN_HMAC", raising=False)
    with pytest.raises(ValidationError):
        Identity.from_dict({"id": "admin", "allowed_cidrs": ["10.0.0.0/8"], "permissions": ["*:*"]})


def test_token_valid(monkeypatch):
    ident = _identity(monkeypatch, token="s3cret")
    assert ident.is_token_valid(KEY, "s3cret")
    assert not ident.is_token_valid(KEY, "wrong")


def test_ip_allowed(monkeypatch):
    ident = _identity(monkeypatch, cidrs=["10.0.0.0/8"])
    assert ident.is_ip_allowed("10.1.2.3")
    assert not ident.is_ip_allowed("192.168.1.1")
    assert not ident.is_ip_allowed(None)
    assert not ident.is_ip_allowed("not-an-ip")


def test_allows_delegates_to_permissions(monkeypatch):
    ident = _identity(monkeypatch, perms=["example.com:read_domain"])
    assert ident.allows("example.com", PermissionAction.READ_DOMAIN)
    assert not ident.allows("example.com", PermissionAction.WRITE_DOMAIN)
    assert not ident.allows("other.com", PermissionAction.READ_DOMAIN)
