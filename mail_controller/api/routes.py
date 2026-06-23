import os
import platform
from flask import Blueprint, Response
from mail_controller.api.context import Context
from mail_controller.api.helpers import build_response
from mail_controller.api.validators import (
    query_str, query_int, query_date, json_body, json_body_field,
)
from mail_controller.conf.config import Config
from mail_controller.db.pool import Database
from mail_controller.db import repository as repo
from mail_controller.domain.permission import PermissionAction
from mail_controller.domain.address import normalize_email, normalize_domain, domain_of, DomainName, EmailAddress
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
    return build_response(200, data={
        "name": "Mail controller",
        "author": "karol@siedlaczek.com.pl",
        "app": os.environ.get("APP_VERSION", "unknown"),
        "python": platform.python_version(),
    })

# ── token  ────────────────────────────────────────────────


@api.route("/api/token/scope", methods=["GET"])
def token_scope() -> Response:
    ctx = Context.authenticate()
    return build_response(200, data={
        "permissions": [f"{p.scope}:{p.action.value}" for p in ctx.identity.permissions],
    })


@api.route("/api/token/identity", methods=["GET"])
def token_identity() -> Response:
    ctx = Context.authenticate()
    i = ctx.identity
    return build_response(200, data={
        "id": i.id,
        "allowed_cidrs": i.allowed_cidrs,
        "permissions": [{"scope": p.scope, "action": p.action.value} for p in i.permissions],
    })


# ── domains ──────────────────────────────────────────────────────────────────

@api.route("/api/domains", methods=["GET"])
def list_domains() -> Response:
    ctx = Context.authenticate()
    term = query_str("filter", default=None)
    db = Database.get_from_global_context()
    with db.transaction() as cur:
        rows = repo.list_domains(cur, term=term)
    visible = ctx.filter_readable(rows, lambda d: d.name.value)
    return build_response(200, data=[d.to_dict() for d in visible])


@api.route("/api/domains", methods=["POST"])
def create_domain() -> Response:
    ctx = Context.authenticate()
    body = json_body()
    name = DomainName.parse(json_body_field(body, "domain"))
    ctx.require(name.value, PermissionAction.WRITE)
    dkim_selector = json_body_field(body, "dkim_selector", required=False) or "default"
    active = json_body_field(body, "active", required=False)
    active = True if active is None else bool(active)
    entity = Domain(name=name, dkim_selector=dkim_selector, active=active)
    db = Database.get_from_global_context()
    with db.transaction() as cur:
        row = repo.create_domain(cur, entity)
    return build_response(201, data=row.to_dict())


@api.route("/api/domains/<domain>", methods=["GET"])
def get_domain(domain: str) -> Response:
    name = DomainName.parse(domain)
    ctx = Context.authenticate()
    ctx.require(name.value, PermissionAction.READ)
    db = Database.get_from_global_context()
    with db.transaction() as cur:
        row = repo.get_domain(cur, name)
    if not row:
        raise ResourceNotFoundError(msg="Domain not found", detail={"domain": name.value})
    return build_response(200, data=row.to_dict())


@api.route("/api/domains/<domain>", methods=["PATCH"])
def update_domain(domain: str) -> Response:
    name = DomainName.parse(domain)
    ctx = Context.authenticate()
    ctx.require(name.value, PermissionAction.WRITE)
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
def delete_domain(domain: str) -> Response:
    name = DomainName.parse(domain)
    ctx = Context.authenticate()
    ctx.require(name.value, PermissionAction.WRITE)
    db = Database.get_from_global_context()
    with db.transaction() as cur:
        ok = repo.delete_domain(cur, name.value)
    if not ok:
        raise ResourceNotFoundError(msg="Domain not found", detail={"domain": name.value})
    return build_response(200, data={"domain": name.value, "deleted": True})


# ── users ────────────────────────────────────────────────────────────────────
@api.route("/api/users", methods=["GET"])
def list_users() -> Response:
    ctx = Context.authenticate()
    domain = query_str("domain", default=None)
    term = query_str("filter", default=None)
    dom = DomainName.parse(domain) if domain else None
    db = Database.get_from_global_context()
    with db.transaction() as cur:
        rows = repo.list_users(cur, domain=dom, term=term)
    visible = ctx.filter_readable(rows, lambda m: m.email.domain.value)
    return build_response(200, data=[m.to_dict() for m in visible])


@api.route("/api/users", methods=["POST"])
def create_user() -> Response:
    ctx = Context.authenticate()
    body = json_body()
    email = EmailAddress.parse(json_body_field(body, "email"))
    ctx.require(email.domain.value, PermissionAction.WRITE)
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
def get_user(email: str) -> Response:
    addr = EmailAddress.parse(email)
    ctx = Context.authenticate()
    ctx.require(addr.domain.value, PermissionAction.READ)
    db = Database.get_from_global_context()
    with db.transaction() as cur:
        row = repo.get_user(cur, addr)
    if not row:
        raise ResourceNotFoundError(msg="User not found", detail={"email": addr.value})
    return build_response(200, data=row.to_dict())


@api.route("/api/users/<email>", methods=["PATCH"])
def update_user(email: str) -> Response:
    addr = EmailAddress.parse(email)
    ctx = Context.authenticate()
    ctx.require(addr.domain.value, PermissionAction.WRITE)
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
def set_password(email: str) -> Response:
    addr = EmailAddress.parse(email)
    ctx = Context.authenticate()
    ctx.require(addr.domain.value, PermissionAction.WRITE)
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
def delete_user(email: str) -> Response:
    addr = EmailAddress.parse(email)
    ctx = Context.authenticate()
    ctx.require(addr.domain.value, PermissionAction.WRITE)
    db = Database.get_from_global_context()
    with db.transaction() as cur:
        result = repo.delete_user(cur, addr)
    if result is None:
        raise ResourceNotFoundError(msg="User not found", detail={"email": addr.value})
    return build_response(200, data={"email": addr.value, "deleted": True, **result})


# ── forwardings ──────────────────────────────────────────────────────────────
@api.route("/api/forwardings", methods=["GET"])
def list_forwardings() -> Response:
    ctx = Context.authenticate()
    source = query_str("source", default=None)
    domain = query_str("domain", default=None)
    term = query_str("filter", default=None)
    src = EmailAddress.parse(source) if source else None
    dom = DomainName.parse(domain) if domain else None
    db = Database.get_from_global_context()
    with db.transaction() as cur:
        rows = repo.list_forwardings(cur, source=src, domain=dom, term=term)
    visible = ctx.filter_readable(rows, lambda f: f.source.domain.value)
    return build_response(200, data=[f.to_dict() for f in visible])


@api.route("/api/forwardings", methods=["POST"])
def create_forwarding() -> Response:
    ctx = Context.authenticate()
    body = json_body()
    source = EmailAddress.parse(json_body_field(body, "source"))
    destination = EmailAddress.parse(json_body_field(body, "destination"))
    ctx.require(source.domain.value, PermissionAction.WRITE)
    keep_copy = json_body_field(body, "keep_copy", required=False)
    keep_copy = False if keep_copy is None else bool(keep_copy)
    fwd = Forwarding(source=source, destination=destination, keep_copy=keep_copy)
    db = Database.get_from_global_context()
    with db.transaction() as cur:
        row = repo.create_forwarding(cur, fwd)
    return build_response(201, data=row.to_dict())


@api.route("/api/forwardings/<int:fid>", methods=["DELETE"])
def delete_forwarding(fid: int) -> Response:
    ctx = Context.authenticate()
    db = Database.get_from_global_context()
    with db.transaction() as cur:
        rows = repo.list_forwardings(cur)
        target = next((r for r in rows if r.id == fid), None)
        if not target:
            raise ResourceNotFoundError(msg="Forwarding not found", detail={"id": fid})
        ctx.require(target.source.domain.value, PermissionAction.WRITE)
        repo.delete_forwarding(cur, fid)
    return build_response(200, data={"id": fid, "deleted": True})


# ── sender-logins (send-as grants) ────────────────────────────────────────────
@api.route("/api/sender-logins", methods=["GET"])
def list_sender_logins() -> Response:
    ctx = Context.authenticate()
    domain = query_str("domain", default=None)
    term = query_str("filter", default=None)
    dom = DomainName.parse(domain) if domain else None
    db = Database.get_from_global_context()
    with db.transaction() as cur:
        rows = repo.list_sender_logins(cur, domain=dom, term=term)
    visible = ctx.filter_readable(rows, lambda s: s.allowed_sender.domain.value)
    return build_response(200, data=[s.to_dict() for s in visible])


@api.route("/api/sender-logins", methods=["POST"])
def create_sender_login() -> Response:
    ctx = Context.authenticate()
    body = json_body()
    login_email = EmailAddress.parse(json_body_field(body, "login_email"))
    allowed_sender = EmailAddress.parse(json_body_field(body, "allowed_sender"))
    ctx.require(allowed_sender.domain.value, PermissionAction.WRITE)
    grant = SenderLogin(login_email=login_email, allowed_sender=allowed_sender)
    db = Database.get_from_global_context()
    with db.transaction() as cur:
        row = repo.create_sender_login(cur, grant)
    return build_response(201, data=row.to_dict())


@api.route("/api/sender-logins/<int:sid>", methods=["DELETE"])
def delete_sender_login(sid: int) -> Response:
    ctx = Context.authenticate()
    db = Database.get_from_global_context()
    with db.transaction() as cur:
        rows = repo.list_sender_logins(cur)
        target = next((r for r in rows if r.id == sid), None)
        if not target:
            raise ResourceNotFoundError(msg="Sender-login grant not found", detail={"id": sid})
        ctx.require(target.allowed_sender.domain.value, PermissionAction.WRITE)
        repo.delete_sender_login(cur, sid)
    return build_response(200, data={"id": sid, "deleted": True})


# ── audit (read-only) ──────────────────────────────────────────────────────────
@api.route("/api/audit", methods=["GET"])
def list_audit() -> Response:
    ctx = Context.authenticate()
    login = query_str("login", default=None)
    event_type = query_str("event_type", default=None)
    since = query_date("since", default=None)
    until = query_date("until", default=None)
    limit = query_int("limit", default=100, min_val=1, max_val=1000)
    db = Database.get_from_global_context()
    with db.transaction() as cur:
        rows = repo.list_audit(cur, login=login, event_type=event_type, since=since, until=until, limit=limit)
    visible = ctx.filter_readable(rows, lambda a: a.login_domain())
    return build_response(200, data=[a.to_dict() for a in visible])
