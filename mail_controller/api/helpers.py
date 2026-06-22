import logging
from datetime import datetime, timezone
from typing import Any
from http import HTTPStatus
from flask import Response, jsonify, request
from mail_controller.domain.identity import Identity
from mail_controller.conf.config import Config
from mail_controller.exception.auth_exceptions import (
    AuthTokenMissingException, AuthFailedException, AuthIpNotAllowedException,
)

log = logging.getLogger(__name__)


def get_remote_ip() -> str | None:
    if request.remote_addr:
        return request.remote_addr
    xff = request.headers.get("X-Forwarded-For", "")
    return xff.split(",")[0].strip() if xff else None


def log_request(msg: str, *, identity: Identity | None = None, level: str = "info") -> None:
    level = level.lower()
    log_fn = getattr(log, level, None)
    if not callable(log_fn):
        raise ValueError(f"Invalid log level: {level}")
    log_fn(f"{request.remote_addr} {request.method} {request.path} "
           f"{f'({identity.id}) ' if identity else ''}{msg}")


def build_response(code: int, *, msg: str | None = None,
                   data: Any = None, detail: Any | None = None) -> Response:
    payload: dict[str, Any] = {}
    if msg is not None:
        payload["message"] = msg
    if detail is not None:
        payload["detail"] = detail
    if data is not None:
        payload["data"] = data

    payload = {
        "method": request.method,
        "http_code": code,
        "http_status": HTTPStatus(code).phrase,
        "path": request.path,
        **payload,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    response = jsonify(payload)
    response.status_code = code
    return response


def require_auth(remote_ip: str | None) -> Identity:
    auth_header = request.headers.get("Authorization", None)
    if not auth_header:
        raise AuthTokenMissingException("Authorization header is missing or empty")
    if not auth_header.startswith("Bearer "):
        raise AuthTokenMissingException("Authorization header does not start with 'Bearer '")

    token_raw = auth_header[len("Bearer "):].strip()
    try:
        identity_id, identity_token = token_raw.split(".", 1)
        if not identity_id or not identity_token:
            raise ValueError()
    except ValueError:
        raise AuthFailedException("Invalid token format, expected: 'Authorization: Bearer <id>.<token>'")

    conf = Config.get_from_global_context()
    identity = next((i for i in conf.identities if i.id == identity_id), None)
    if identity is None:
        raise AuthFailedException(f"Unknown identity '{identity_id}'")
    if not identity.is_token_valid(conf.hmac_key, identity_token):
        raise AuthFailedException(f"Invalid token for identity '{identity_id}'")
    if not identity.is_ip_allowed(remote_ip):
        raise AuthIpNotAllowedException(remote_ip)
    return identity
