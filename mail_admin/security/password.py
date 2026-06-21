import bcrypt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHashError
from mail_admin.exception.api_exceptions import InvalidRequestError

SUPPORTED_SCHEMES = ("ARGON2ID", "BLF-CRYPT")
_ARGON2_PREFIX = "{ARGON2ID}"
_BLFCRYPT_PREFIX = "{BLF-CRYPT}"
_ph = PasswordHasher()


def hash_password(plaintext: str, scheme: str = "ARGON2ID") -> str:
    if not plaintext:
        raise InvalidRequestError("Password must not be empty")
    scheme = scheme.upper()
    if scheme == "ARGON2ID":
        return _ARGON2_PREFIX + _ph.hash(plaintext)
    if scheme == "BLF-CRYPT":
        digest = bcrypt.hashpw(plaintext.encode("utf-8"), bcrypt.gensalt()).decode("ascii")
        return _BLFCRYPT_PREFIX + digest
    raise InvalidRequestError(
        "Unsupported password scheme",
        detail={"scheme": scheme, "supported": list(SUPPORTED_SCHEMES)},
    )


def verify_password(stored: str, plaintext: str) -> bool:
    if stored.startswith(_ARGON2_PREFIX):
        try:
            return _ph.verify(stored[len(_ARGON2_PREFIX):], plaintext)
        except (VerifyMismatchError, InvalidHashError):
            return False
    if stored.startswith(_BLFCRYPT_PREFIX):
        return bcrypt.checkpw(plaintext.encode("utf-8"), stored[len(_BLFCRYPT_PREFIX):].encode("ascii"))
    return False
