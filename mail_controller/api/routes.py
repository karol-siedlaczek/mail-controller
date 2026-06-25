import os
import platform
from datetime import datetime, timedelta, timezone
from flask import Blueprint, Response
from mail_controller.api.context import Context
from mail_controller.api.helpers import build_response, render_metrics, filter_rows_to_readable
from mail_controller.api.validators import (
    query_str, query_int, query_bool, query_date, json_body, json_body_field,
)
from mail_controller.conf.config import Config
from mail_controller.db.pool import Database
from mail_controller.db import repository as repo
from mail_controller.domain.permission import PermissionAction
from mail_controller.domain.address import DomainName, EmailAddress
from mail_controller.domain.forwarding import Forwarding
from mail_controller.domain.domain import Domain
from mail_controller.domain.mailbox import Mailbox
from mail_controller.domain.sender_login import SenderLogin
from mail_controller.security.password import hash_password
from mail_controller.exception.api_exceptions import ResourceNotFoundError, InvalidRequestError

api = Blueprint("api", __name__)

# ── liveness / version  ────────────────────────────────────────────────

@api.route("/ping", methods=["GET"])
def ping() -> str:
    return "pong"


@api.route("/api/version", methods=["GET"])
def version() -> Response:
    payload = {
        "name": "Mail controller",
        "author": "karol@siedlaczek.com.pl",
        "app": os.environ.get("APP_VERSION", "unknown"),
        "git_sha": os.environ.get("GIT_SHA", "unknown"),
        "build_date": os.environ.get("BUILD_DATE", "unknown"),
        "python": platform.python_version()
    }
    return build_response(200, data=payload)


@api.route("/api/metrics", methods=["GET"])
def metrics() -> Response:
    ctx = Context.authenticate()
    ctx.require_action(PermissionAction.READ_METRICS)
    since = datetime.now(timezone.utc) - timedelta(minutes=5)
    
    db = Database.get_from_global_context()
    with db.transaction() as cur:
        domain_names = repo.list_domain_names(cur)
        users = repo.count_users_by_domain(cur)
        forwardings = repo.count_forwardings_by_domain(cur)
        sender_logins = repo.count_sender_logins_by_domain(cur)
        audit_rows = repo.count_audit_by_domain(cur, since=since)

    totals, traffic = _scope_metrics(ctx, domain_names, users, forwardings, sender_logins, audit_rows)
    build_info = {
        "version": os.environ.get("APP_VERSION", "unknown"),
        "git_sha": os.environ.get("GIT_SHA", "unknown"),
    }
    body = render_metrics(build_info=build_info, totals=totals, traffic=traffic)
    return Response(body, mimetype="text/plain; version=0.0.4")


# ── token  ────────────────────────────────────────────────


@api.route("/api/token/scope", methods=["GET"])
def token_scope() -> Response:
    ctx = Context.authenticate()
    identity = ctx.identity
    actions = [a for a in PermissionAction if a != PermissionAction.ANY]
    payload = {action.value: [] for action in actions}

    db = Database.get_from_global_context()
    with db.transaction() as cur:
        domains = [d.name.value for d in repo.list_domains(cur)]

    for domain in domains:
        for action in actions:
            if identity.allows(domain, action):
                payload[action.value].append(domain)

    return build_response(200, data=payload)


@api.route("/api/token/identity", methods=["GET"])
def token_identity() -> Response:
    ctx = Context.authenticate()
    identity = ctx.identity
    payload = {
        "id": identity.id,
        "allowed_cidrs": identity.allowed_cidrs,
        "permissions": [{"scope": p.scope, "action": p.action.value} for p in identity.permissions]
    }
    return build_response(200, data=payload)


# ── domains ──────────────────────────────────────────────────────────────────

@api.route("/api/domains", methods=["GET"])
def domain_list() -> Response:
    ctx = Context.authenticate()
    term = query_str("filter", default=None)
    active = query_bool("active", default=None)
    created_since = query_date("created_since", default=None)
    created_until = query_date("created_until", default=None)

    db = Database.get_from_global_context()
    with db.transaction() as cur:
        domains = repo.list_domains(cur, term=term, active=active,
                                    created_since=created_since, created_until=created_until)

    visible = filter_rows_to_readable(ctx, domains, lambda d: d.name.value, PermissionAction.READ_DOMAIN)
    return build_response(200, data=[d.to_dict() for d in visible])


@api.route("/api/domains", methods=["POST"])
def domain_create() -> Response:
    ctx = Context.authenticate()
    body = json_body()
    domain_name = DomainName.parse(json_body_field(body, "domain"))
    ctx.require(domain_name.value, PermissionAction.WRITE_DOMAIN)
    dkim_selector = json_body_field(body, "dkim_selector", required=False) or "default"
    active = json_body_field(body, "active", required=False)
    active = True if active is None else bool(active)
    new_domain = Domain(name=domain_name, dkim_selector=dkim_selector, active=active)
    
    db = Database.get_from_global_context()
    with db.transaction() as cur:
        domain = repo.create_domain(cur, new_domain)
        
    return build_response(201, data=domain.to_dict())


@api.route("/api/domains/<domain>", methods=["GET"])
def domain_get(domain: str) -> Response:
    name = DomainName.parse(domain)
    ctx = Context.authenticate()
    ctx.require(name.value, PermissionAction.READ_DOMAIN)
    db = Database.get_from_global_context()
    with db.transaction() as cur:
        row = repo.get_domain(cur, name)
    if not row:
        raise ResourceNotFoundError(msg="Domain not found", detail={"domain": name.value})
    return build_response(200, data=row.to_dict())


@api.route("/api/domains/<domain>", methods=["PATCH"])
def domain_update(domain: str) -> Response:
    name = DomainName.parse(domain)
    ctx = Context.authenticate()
    ctx.require(name.value, PermissionAction.WRITE_DOMAIN)
    body = json_body()
    dkim_selector = json_body_field(body, "dkim_selector", required=False)
    active = json_body_field(body, "active", required=False)
    db = Database.get_from_global_context()
    with db.transaction() as cur:
        row = repo.update_domain(cur, name, dkim_selector,
                                 None if active is None else bool(active))
    if not row:
        raise ResourceNotFoundError(msg="Domain not found", detail={"domain": name.value})
    return build_response(200, data=row.to_dict())


@api.route("/api/domains/<domain>", methods=["DELETE"])
def domain_delete(domain: str) -> Response:
    name = DomainName.parse(domain)
    ctx = Context.authenticate()
    ctx.require(name.value, PermissionAction.WRITE_DOMAIN)
    db = Database.get_from_global_context()
    with db.transaction() as cur:
        ok = repo.delete_domain(cur, name.value)
    if not ok:
        raise ResourceNotFoundError(msg="Domain not found", detail={"domain": name.value})
    return build_response(200, data={"domain": name.value, "deleted": True})


# ── users ────────────────────────────────────────────────────────────────────
@api.route("/api/users", methods=["GET"])
def user_list() -> Response:
    ctx = Context.authenticate()
    domain = query_str("domain", default=None)
    term = query_str("filter", default=None)
    active = query_bool("active", default=None)
    created_since = query_date("created_since", default=None)
    created_until = query_date("created_until", default=None)
    dom = DomainName.parse(domain) if domain else None
    db = Database.get_from_global_context()
    with db.transaction() as cur:
        rows = repo.list_users(cur, domain=dom, term=term, active=active,
                               created_since=created_since, created_until=created_until)
    visible = filter_rows_to_readable(ctx, rows, lambda m: m.email.domain.value, PermissionAction.READ_USER)
    return build_response(200, data=[m.to_dict() for m in visible])


@api.route("/api/users", methods=["POST"])
def user_create() -> Response:
    ctx = Context.authenticate()
    body = json_body()
    email = EmailAddress.parse(json_body_field(body, "email"))
    ctx.require(email.domain.value, PermissionAction.WRITE_USER)
    password = json_body_field(body, "password")
    quota_bytes = json_body_field(body, "quota_bytes", required=False, cast_fn=int) or 0
    active = json_body_field(body, "active", required=False)
    active = True if active is None else bool(active)
    conf = Config.get_from_global_context()
    pw_hash = hash_password(password, conf.password_scheme)
    mailbox = Mailbox(email=email, quota_bytes=quota_bytes, active=active)
    db = Database.get_from_global_context()
    with db.transaction() as cur:
        row = repo.create_user(cur, mailbox, pw_hash)
    return build_response(201, data=row.to_dict())


@api.route("/api/users/<email>", methods=["GET"])
def user_get(email: str) -> Response:
    addr = EmailAddress.parse(email)
    ctx = Context.authenticate()
    ctx.require(addr.domain.value, PermissionAction.READ_USER)
    db = Database.get_from_global_context()
    with db.transaction() as cur:
        row = repo.get_user(cur, addr)
    if not row:
        raise ResourceNotFoundError(msg="User not found", detail={"email": addr.value})
    return build_response(200, data=row.to_dict())


@api.route("/api/users/<email>", methods=["PATCH"])
def user_update(email: str) -> Response:
    addr = EmailAddress.parse(email)
    ctx = Context.authenticate()
    ctx.require(addr.domain.value, PermissionAction.WRITE_USER)
    body = json_body()
    quota_bytes = json_body_field(body, "quota_bytes", required=False, cast_fn=int)
    active = json_body_field(body, "active", required=False)
    db = Database.get_from_global_context()
    with db.transaction() as cur:
        row = repo.update_user(cur, addr, quota_bytes,
                               None if active is None else bool(active))
    if not row:
        raise ResourceNotFoundError(msg="User not found", detail={"email": addr.value})
    return build_response(200, data=row.to_dict())


@api.route("/api/users/<email>/password", methods=["POST"])
def user_update_password(email: str) -> Response:
    addr = EmailAddress.parse(email)
    ctx = Context.authenticate()
    ctx.require(addr.domain.value, PermissionAction.WRITE_USER)
    body = json_body()
    password = json_body_field(body, "password")
    conf = Config.get_from_global_context()
    pw_hash = hash_password(password, conf.password_scheme)
    db = Database.get_from_global_context()
    with db.transaction() as cur:
        ok = repo.set_user_password(cur, addr, pw_hash)
    if not ok:
        raise ResourceNotFoundError(msg="User not found", detail={"email": addr.value})
    return build_response(200, data={"email": addr.value, "password_set": True})


@api.route("/api/users/<email>", methods=["DELETE"])
def user_delete(email: str) -> Response:
    addr = EmailAddress.parse(email)
    ctx = Context.authenticate()
    ctx.require(addr.domain.value, PermissionAction.WRITE_USER)
    db = Database.get_from_global_context()
    with db.transaction() as cur:
        result = repo.delete_user(cur, addr)
    if result is None:
        raise ResourceNotFoundError(msg="User not found", detail={"email": addr.value})
    return build_response(200, data={"email": addr.value, "deleted": True, **result})

# ── forwardings ──────────────────────────────────────────────────────────────

@api.route("/api/forwardings", methods=["GET"])
def forwarding_list() -> Response:
    ctx = Context.authenticate()
    source = query_str("source", default=None)
    domain = query_str("domain", default=None)
    term = query_str("filter", default=None)
    active = query_bool("active", default=None)
    keep_copy = query_bool("keep_copy", default=None)
    created_since = query_date("created_since", default=None)
    created_until = query_date("created_until", default=None)
    src = EmailAddress.parse(source) if source else None
    dom = DomainName.parse(domain) if domain else None
    db = Database.get_from_global_context()
    with db.transaction() as cur:
        rows = repo.list_forwardings(cur, source=src, domain=dom, term=term, active=active,
                                     keep_copy=keep_copy, created_since=created_since,
                                     created_until=created_until)
    visible = filter_rows_to_readable(ctx, rows, lambda f: f.source.domain.value, PermissionAction.READ_FORWARDING)
    return build_response(200, data=[f.to_dict() for f in visible])


@api.route("/api/forwardings", methods=["POST"])
def forwarding_create() -> Response:
    ctx = Context.authenticate()
    body = json_body()
    source = EmailAddress.parse(json_body_field(body, "source"))
    destination = EmailAddress.parse(json_body_field(body, "destination"))
    ctx.require(source.domain.value, PermissionAction.WRITE_FORWARDING)
    keep_copy = json_body_field(body, "keep_copy", required=False)
    keep_copy = False if keep_copy is None else bool(keep_copy)
    fwd = Forwarding(source=source, destination=destination, keep_copy=keep_copy)
    db = Database.get_from_global_context()
    with db.transaction() as cur:
        row = repo.create_forwarding(cur, fwd)
    return build_response(201, data=row.to_dict())


@api.route("/api/forwardings/<int:fid>", methods=["DELETE"])
def forwarding_delete(fid: int) -> Response:
    ctx = Context.authenticate()
    db = Database.get_from_global_context()
    with db.transaction() as cur:
        rows = repo.list_forwardings(cur)
        target = next((r for r in rows if r.id == fid), None)
        if not target:
            raise ResourceNotFoundError(msg="Forwarding not found", detail={"id": fid})
        ctx.require(target.source.domain.value, PermissionAction.WRITE_FORWARDING)
        repo.delete_forwarding(cur, fid)
    return build_response(200, data={"id": fid, "deleted": True})

# ── sender-logins (send-as grants) ────────────────────────────────────────────

@api.route("/api/sender-logins", methods=["GET"])
def sender_login_list() -> Response:
    ctx = Context.authenticate()
    domain = query_str("domain", default=None)
    term = query_str("filter", default=None)
    active = query_bool("active", default=None)
    created_since = query_date("created_since", default=None)
    created_until = query_date("created_until", default=None)
    dom = DomainName.parse(domain) if domain else None
    db = Database.get_from_global_context()
    with db.transaction() as cur:
        rows = repo.list_sender_logins(cur, domain=dom, term=term, active=active,
                                       created_since=created_since, created_until=created_until)
    visible = filter_rows_to_readable(ctx, rows, lambda s: s.allowed_sender.domain.value, PermissionAction.READ_SENDER_LOGIN)
    return build_response(200, data=[s.to_dict() for s in visible])


@api.route("/api/sender-logins", methods=["POST"])
def sender_login_create() -> Response:
    ctx = Context.authenticate()
    body = json_body()
    login_email = EmailAddress.parse(json_body_field(body, "login_email"))
    allowed_sender = EmailAddress.parse(json_body_field(body, "allowed_sender"))
    ctx.require(allowed_sender.domain.value, PermissionAction.WRITE_SENDER_LOGIN)
    grant = SenderLogin(login_email=login_email, allowed_sender=allowed_sender)
    db = Database.get_from_global_context()
    with db.transaction() as cur:
        row = repo.create_sender_login(cur, grant)
    return build_response(201, data=row.to_dict())


@api.route("/api/sender-logins/<int:sid>", methods=["DELETE"])
def sender_login_delete(sid: int) -> Response:
    ctx = Context.authenticate()
    db = Database.get_from_global_context()
    with db.transaction() as cur:
        rows = repo.list_sender_logins(cur)
        target = next((r for r in rows if r.id == sid), None)
        if not target:
            raise ResourceNotFoundError(msg="Sender-login grant not found", detail={"id": sid})
        ctx.require(target.allowed_sender.domain.value, PermissionAction.WRITE_SENDER_LOGIN)
        repo.delete_sender_login(cur, sid)
    return build_response(200, data={"id": sid, "deleted": True})

# ── audit (read-only) ──────────────────────────────────────────────────────────

@api.route("/api/audit", methods=["GET"])
def audit_list() -> Response:
    ctx = Context.authenticate()
    login = query_str("login", default=None)
    event_type = query_str("event_type", default=None)
    since = query_date("since", default=None)
    until = query_date("until", default=None)
    limit = query_int("limit", default=100, min_val=1, max_val=1000)
    success = query_bool("success", default=None)
    queue_id = query_str("queue_id", default=None)
    message_id = query_str("message_id", default=None)
    host = query_str("host", default=None)
    src_ip = query_str("src_ip", default=None)
    sender = query_str("sender", default=None)
    recipient = query_str("recipient", default=None)
    db = Database.get_from_global_context()
    with db.transaction() as cur:
        rows = repo.list_audit(cur, login=login, event_type=event_type, since=since, until=until,
                               limit=limit, success=success, queue_id=queue_id,
                               message_id=message_id, host=host, src_ip=src_ip,
                               sender=sender, recipient=recipient)
    visible = filter_rows_to_readable(ctx, rows, lambda a: a.login_domain(), PermissionAction.READ_AUDIT)
    return build_response(200, data=[a.to_dict() for a in visible])



def _scope_metrics(ctx, domain_names, users_by, fwd_by, slm_by, audit_rows):
    """Reduce per-domain raw counts to read-scope-filtered totals + traffic.

    Authorization reuses ctx.identity.allows (single matching source); a "*" reader
    sees everything (including domain-less audit rows).
    """
    star = ctx._has_star(PermissionAction.READ_METRICS)

    def visible(dom):
        if not dom:
            return star
        return star or ctx.identity.allows(dom, PermissionAction.READ_METRICS)

    totals = {
        "domains": sum(1 for d in domain_names if visible(d)),
        "users": sum(c for d, c in users_by.items() if visible(d)),
        "forwardings": sum(c for d, c in fwd_by.items() if visible(d)),
        "sender_logins": sum(c for d, c in slm_by.items() if visible(d)),
    }

    traffic = {"auth_success": 0, "auth_failure": 0, "send": 0, "delivery": 0}
    for row in audit_rows:
        if not visible(row["dom"]):
            continue
        event_type, count = row["event_type"], row["count"]
        if event_type == "auth":
            traffic["auth_success" if row["success"] else "auth_failure"] += count
        elif event_type == "send":
            traffic["send"] += count
        elif event_type == "delivery":
            traffic["delivery"] += count

    return totals, traffic
