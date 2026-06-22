import pytest
from mail_controller.security.password import hash_password, verify_password, SUPPORTED_SCHEMES
from mail_controller.exception.api_exceptions import InvalidRequestError


def test_argon2id_shape():
    h = hash_password("hunter2", "ARGON2ID")
    assert h.startswith("{ARGON2ID}$argon2id$")


def test_argon2id_verifies():
    h = hash_password("hunter2", "ARGON2ID")
    assert verify_password(h, "hunter2")
    assert not verify_password(h, "wrong")


def test_blfcrypt_shape():
    h = hash_password("hunter2", "BLF-CRYPT")
    assert h.startswith("{BLF-CRYPT}$2b$")


def test_blfcrypt_verifies():
    h = hash_password("hunter2", "BLF-CRYPT")
    assert verify_password(h, "hunter2")
    assert not verify_password(h, "wrong")


def test_default_is_argon2id():
    assert hash_password("x").startswith("{ARGON2ID}$argon2id$")


def test_unknown_scheme():
    with pytest.raises(InvalidRequestError):
        hash_password("x", "SHA512-CRYPT")


def test_empty_plaintext():
    with pytest.raises(InvalidRequestError):
        hash_password("", "ARGON2ID")


def test_supported_schemes():
    assert SUPPORTED_SCHEMES == ("ARGON2ID", "BLF-CRYPT")
