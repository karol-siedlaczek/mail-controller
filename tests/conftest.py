import os
import base64
import hmac
import hashlib
import subprocess
import time
import pytest
import requests

HERE = os.path.dirname(os.path.abspath(__file__))
COMPOSE = os.path.join(HERE, "compose.test.yml")
RAW_KEY = base64.b64decode("MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=")
BASE_URL = "http://127.0.0.1:18080"

TOKENS = {
    "admin": "admintoken",
    "artform": "artformtoken",
    "reader": "readertoken",
    "blocked": "blockedtoken",
}


def _hmac_hex(token: str) -> str:
    return hmac.new(RAW_KEY, token.encode(), hashlib.sha256).hexdigest()


def bearer(identity: str) -> str:
    return f"{identity}.{TOKENS[identity]}"


def _compose(*args, env=None):
    return subprocess.run(["docker", "compose", "-f", COMPOSE, *args],
                          check=True, env={**os.environ, **(env or {})})


def _wait_http(url, timeout=120):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if requests.get(url, timeout=2).ok:
                return
        except requests.RequestException:
            pass
        time.sleep(2)
    raise RuntimeError(f"Service at {url} not healthy within {timeout}s")


@pytest.fixture(scope="session")
def stack():
    # Build the image, then bring the stack up with computed HMAC env overrides.
    subprocess.run(["docker", "build", "-t", "mail-controller:test", os.path.dirname(HERE)], check=True)
    env = {
        "TOKEN_ADMIN_HMAC": _hmac_hex(TOKENS["admin"]),
        "TOKEN_ARTFORM_HMAC": _hmac_hex(TOKENS["artform"]),
        "TOKEN_READER_HMAC": _hmac_hex(TOKENS["reader"]),
        "TOKEN_BLOCKED_HMAC": _hmac_hex(TOKENS["blocked"]),
    }
    # Pass real HMACs via compose env interpolation: rewrite the placeholders.
    # Simplest: use `docker compose run`-style env by exporting and templating.
    _compose("down", "-v")
    try:
        _compose("up", "-d", "--build", env=env)
        _wait_http(f"{BASE_URL}/ping")
        yield BASE_URL
    finally:
        _compose("down", "-v")
