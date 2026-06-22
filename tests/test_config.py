import os
import base64
import hmac
import hashlib
import textwrap
import pytest
from mail_controller.conf.config import Config
from mail_controller.exception.validator_exceptions import ValidationError

RAW_KEY = b"0123456789abcdef0123456789abcdef"
KEY_B64 = base64.b64encode(RAW_KEY).decode()


def _hmac_hex(token):
    return hmac.new(RAW_KEY, token.encode(), hashlib.sha256).hexdigest()


def _write_conf(tmp_path, body):
    f = tmp_path / "config.yaml"
    f.write_text(textwrap.dedent(body))
    return str(f)


def _base_env(monkeypatch, conf_file):
    monkeypatch.setenv("HMAC_KEY_B64", KEY_B64)
    monkeypatch.setenv("PG_HOST", "db")
    monkeypatch.setenv("PG_DBNAME", "maildb")
    monkeypatch.setenv("PG_USER", "mail_admin_rw")
    monkeypatch.setenv("PG_PASSWORD", "secret")
    monkeypatch.setenv("CONF_FILE", conf_file)
    monkeypatch.setenv("TOKEN_ADMIN_HMAC", _hmac_hex("t0ken"))


def test_load_ok(tmp_path, monkeypatch):
    conf = _write_conf(tmp_path, """
        identities:
          - id: admin
            allowed_cidrs: ["10.0.0.0/8"]
            permissions: ["*:write"]
    """)
    _base_env(monkeypatch, conf)
    cfg = Config.load()
    assert cfg.pg_host == "db"
    assert cfg.pg_port == 5432
    assert cfg.password_scheme == "ARGON2ID"
    assert cfg.hmac_key == RAW_KEY
    assert len(cfg.identities) == 1
    assert cfg.identities[0].id == "admin"


def test_missing_required_env(tmp_path, monkeypatch):
    conf = _write_conf(tmp_path, "identities: []\n")
    _base_env(monkeypatch, conf)
    monkeypatch.delenv("PG_HOST")
    with pytest.raises(ValidationError):
        Config.load()


def test_pg_password_file_indirection(tmp_path, monkeypatch):
    conf = _write_conf(tmp_path, "identities: []\n")
    _base_env(monkeypatch, conf)
    monkeypatch.delenv("PG_PASSWORD")
    secret = tmp_path / "pw"
    secret.write_text("filesecret\n")
    monkeypatch.setenv("PG_PASSWORD__FILE", str(secret))
    cfg = Config.load()
    assert cfg.pg_password == "filesecret"


def test_bad_password_scheme(tmp_path, monkeypatch):
    conf = _write_conf(tmp_path, "identities: []\n")
    _base_env(monkeypatch, conf)
    monkeypatch.setenv("PASSWORD_SCHEME", "SHA512-CRYPT")
    with pytest.raises(ValidationError):
        Config.load()


def test_duplicate_identity_id(tmp_path, monkeypatch):
    conf = _write_conf(tmp_path, """
        identities:
          - id: admin
            allowed_cidrs: ["10.0.0.0/8"]
            permissions: ["*:write"]
          - id: admin
            allowed_cidrs: ["10.0.0.0/8"]
            permissions: ["*:read"]
    """)
    _base_env(monkeypatch, conf)
    with pytest.raises(ValidationError):
        Config.load()


def test_short_hmac_key_rejected(tmp_path, monkeypatch):
    conf = _write_conf(tmp_path, "identities: []\n")
    _base_env(monkeypatch, conf)
    monkeypatch.setenv("HMAC_KEY_B64", base64.b64encode(b"tooshort").decode())
    with pytest.raises(ValidationError):
        Config.load()
