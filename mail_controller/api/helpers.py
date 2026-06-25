import logging
from datetime import datetime, timezone
from typing import Any, Callable, TypeVar
from http import HTTPStatus
from flask import Response, jsonify, request
from mail_controller.domain.identity import Identity
from mail_controller.domain.permission import PermissionAction

log = logging.getLogger(__name__)
T = TypeVar("T")

def log_request(msg: str, *, identity: Identity | None = None, level: str = "info") -> None:
    level = level.lower()
    log_fn = getattr(log, level, None)
    
    if not callable(log_fn):
        raise ValueError(f"Invalid log level: {level}")
    log_fn(f"{request.remote_addr} {request.method} {request.path} {f'({identity.id}) ' if identity else ''}{msg}")


def build_response(
    code: int, 
    *, 
    msg: str | None = None,
    data: Any = None, 
    detail: Any | None = None
) -> Response:
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


def filter_rows_to_readable(
    ctx, rows: list[T], domain_fn: Callable[[T], str | None], action: PermissionAction
) -> list[T]:
    """Keep only rows whose domain the identity may access with `action`.

    `domain_fn` extracts a row's domain (or None for domain-less rows, e.g. audit
    entries with no login). Domain-less rows are visible only to a "*"-scope holder
    of `action`.
    """
    out: list[T] = []
    for row in rows:
        domain = domain_fn(row)
        if domain is None:
            if ctx._has_star(action):
                out.append(row)
            continue
        if ctx.identity.allows(domain, action):
            out.append(row)
    return out


def render_metrics(*, build_info: dict, totals: dict, traffic: dict) -> str:
    """Render Prometheus text-format metrics (mailctl_* gauges)."""
    def esc(value: object) -> str:
        return str(value).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")

    lines: list[str] = []

    lines.append("# HELP mailctl_build_info Build information.")
    lines.append("# TYPE mailctl_build_info gauge")
    lines.append(
        f'mailctl_build_info{{version="{esc(build_info.get("version", ""))}",'
        f'git_sha="{esc(build_info.get("git_sha", ""))}"}} 1'
    )

    for key, help_text in (
        ("domains", "Number of domains readable by the token."),
        ("users", "Number of mailboxes readable by the token."),
        ("forwardings", "Number of forwardings readable by the token."),
        ("sender_logins", "Number of send-as grants readable by the token."),
    ):
        metric = f"mailctl_{key}_total"
        lines.append(f"# HELP {metric} {help_text}")
        lines.append(f"# TYPE {metric} gauge")
        lines.append(f"{metric} {int(totals.get(key, 0))}")

    lines.append("# HELP mailctl_auth_events_5m Authentication events in the last 5 minutes.")
    lines.append("# TYPE mailctl_auth_events_5m gauge")
    lines.append(f'mailctl_auth_events_5m{{success="true"}} {int(traffic.get("auth_success", 0))}')
    lines.append(f'mailctl_auth_events_5m{{success="false"}} {int(traffic.get("auth_failure", 0))}')

    lines.append("# HELP mailctl_send_events_5m Outbound (send) events in the last 5 minutes.")
    lines.append("# TYPE mailctl_send_events_5m gauge")
    lines.append(f"mailctl_send_events_5m {int(traffic.get('send', 0))}")

    lines.append("# HELP mailctl_delivery_events_5m Inbound (delivery) events in the last 5 minutes.")
    lines.append("# TYPE mailctl_delivery_events_5m gauge")
    lines.append(f"mailctl_delivery_events_5m {int(traffic.get('delivery', 0))}")

    return "\n".join(lines) + "\n"
