import os
import platform
from flask import Blueprint, Response
from mail_admin.api.context import Context
from mail_admin.api.helpers import build_response
from mail_admin.api.validators import (
    query_str, query_int, query_bool, json_body, json_body_field,
)
from mail_admin.conf.config import Config
from mail_admin.db.pool import Database
from mail_admin.db import repository as repo
from mail_admin.domain.permission import PermissionAction
from mail_admin.domain.address import normalize_email, normalize_domain, domain_of
from mail_admin.security.password import hash_password
from mail_admin.exception.api_exceptions import ResourceNotFoundError, InvalidRequestError

api = Blueprint("api", __name__)

READ = PermissionAction.READ
WRITE = PermissionAction.WRITE


# ── liveness / introspection ────────────────────────────────────────────────
@api.route("/ping", methods=["GET"])
def ping() -> str:
    return "pong"


@api.route("/api/version", methods=["GET"])
def version() -> Response:
    return build_response(200, data={
        "name": "Mail Admin",
        "author": "karol@siedlaczek.com.pl",
        "app": os.environ.get("APP_VERSION", "unknown"),
        "python": platform.python_version(),
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


@api.route("/api/token/scope", methods=["GET"])
def token_scope() -> Response:
    ctx = Context.authenticate()
    return build_response(200, data={
        "permissions": [f"{p.scope}:{p.action.value}" for p in ctx.identity.permissions],
    })


# ── domains ──────────────────────────────────────────────────────────────────
@api.route("/api/domains", methods=["GET"])
def list_domains() -> Response:
    ctx = Context.authenticate()
    db = Database.get_from_global_context()
    with db.transaction() as cur:
        rows = repo.list_domains(cur)
    return build_response(200, data=ctx.filter_readable(rows, "domain"))


@api.route("/api/domains", methods=["POST"])
def create_domain() -> Response:
    ctx = Context.authenticate()
    body = json_body()
    domain = normalize_domain(json_body_field(body, "domain"))
    ctx.require(domain, WRITE)
    dkim_selector = json_body_field(body, "dkim_selector", required=False) or "default"
    active = json_body_field(body, "active", required=False)
    active = True if active is None else bool(active)
    db = Database.get_from_global_context()
    with db.transaction() as cur:
        row = repo.create_domain(cur, domain, dkim_selector, active)
    return build_response(201, data=row)


@api.route("/api/domains/<domain>", methods=["GET"])
def get_domain(domain: str) -> Response:
    domain = normalize_domain(domain)
    ctx = Context.authenticate()
    ctx.require(domain, READ)
    db = Database.get_from_global_context()
    with db.transaction() as cur:
        row = repo.get_domain(cur, domain)
    if not row:
        raise ResourceNotFoundError(msg="Domain not found", detail={"domain": domain})
    return build_response(200, data=row)


@api.route("/api/domains/<domain>", methods=["PATCH"])
def update_domain(domain: str) -> Response:
    domain = normalize_domain(domain)
    ctx = Context.authenticate()
    ctx.require(domain, WRITE)
    body = json_body()
    dkim_selector = json_body_field(body, "dkim_selector", required=False)
    active = json_body_field(body, "active", required=False)
    db = Database.get_from_global_context()
    with db.transaction() as cur:
        row = repo.update_domain(cur, domain, dkim_selector,
                                 None if active is None else bool(active))
    if not row:
        raise ResourceNotFoundError(msg="Domain not found", detail={"domain": domain})
    return build_response(200, data=row)


@api.route("/api/domains/<domain>", methods=["DELETE"])
def delete_domain(domain: str) -> Response:
    domain = normalize_domain(domain)
    ctx = Context.authenticate()
    ctx.require(domain, WRITE)
    db = Database.get_from_global_context()
    with db.transaction() as cur:
        ok = repo.delete_domain(cur, domain)
    if not ok:
        raise ResourceNotFoundError(msg="Domain not found", detail={"domain": domain})
    return build_response(200, data={"domain": domain, "deleted": True})


# ── users ────────────────────────────────────────────────────────────────────
@api.route("/api/users", methods=["GET"])
def list_users() -> Response:
    ctx = Context.authenticate()
    domain = query_str("domain", default=None)
    if domain:
        domain = normalize_domain(domain)
    db = Database.get_from_global_context()
    with db.transaction() as cur:
        rows = repo.list_users(cur, domain=domain)
    return build_response(200, data=ctx.filter_readable(rows, "email"))


@api.route("/api/users", methods=["POST"])
def create_user() -> Response:
    ctx = Context.authenticate()
    body = json_body()
    email = normalize_email(json_body_field(body, "email"))
    ctx.require(domain_of(email), WRITE)
    password = json_body_field(body, "password")
    quota_bytes = json_body_field(body, "quota_bytes", required=False, cast_fn=int) or 0
    active = json_body_field(body, "active", required=False)
    active = True if active is None else bool(active)
    conf = Config.get_from_global_context()
    pw_hash = hash_password(password, conf.password_scheme)
    db = Database.get_from_global_context()
    with db.transaction() as cur:
        row = repo.create_user(cur, email, domain_of(email), pw_hash, quota_bytes, active)
    return build_response(201, data=row)


@api.route("/api/users/<email>", methods=["GET"])
def get_user(email: str) -> Response:
    email = normalize_email(email)
    ctx = Context.authenticate()
    ctx.require(domain_of(email), READ)
    db = Database.get_from_global_context()
    with db.transaction() as cur:
        row = repo.get_user(cur, email)
    if not row:
        raise ResourceNotFoundError(msg="User not found", detail={"email": email})
    return build_response(200, data=row)


@api.route("/api/users/<email>", methods=["PATCH"])
def update_user(email: str) -> Response:
    email = normalize_email(email)
    ctx = Context.authenticate()
    ctx.require(domain_of(email), WRITE)
    body = json_body()
    quota_bytes = json_body_field(body, "quota_bytes", required=False, cast_fn=int)
    active = json_body_field(body, "active", required=False)
    db = Database.get_from_global_context()
    with db.transaction() as cur:
        row = repo.update_user(cur, email, quota_bytes,
                               None if active is None else bool(active))
    if not row:
        raise ResourceNotFoundError(msg="User not found", detail={"email": email})
    return build_response(200, data=row)


@api.route("/api/users/<email>/password", methods=["POST"])
def set_password(email: str) -> Response:
    email = normalize_email(email)
    ctx = Context.authenticate()
    ctx.require(domain_of(email), WRITE)
    body = json_body()
    password = json_body_field(body, "password")
    conf = Config.get_from_global_context()
    pw_hash = hash_password(password, conf.password_scheme)
    db = Database.get_from_global_context()
    with db.transaction() as cur:
        ok = repo.set_user_password(cur, email, pw_hash)
    if not ok:
        raise ResourceNotFoundError(msg="User not found", detail={"email": email})
    return build_response(200, data={"email": email, "password_set": True})


@api.route("/api/users/<email>", methods=["DELETE"])
def delete_user(email: str) -> Response:
    email = normalize_email(email)
    ctx = Context.authenticate()
    ctx.require(domain_of(email), WRITE)
    db = Database.get_from_global_context()
    with db.transaction() as cur:
        ok = repo.delete_user(cur, email)
    if not ok:
        raise ResourceNotFoundError(msg="User not found", detail={"email": email})
    return build_response(200, data={"email": email, "deleted": True})


# ── forwardings ──────────────────────────────────────────────────────────────
@api.route("/api/forwardings", methods=["GET"])
def list_forwardings() -> Response:
    ctx = Context.authenticate()
    source = query_str("source", default=None)
    domain = query_str("domain", default=None)
    if source:
        source = normalize_email(source)
    if domain:
        domain = normalize_domain(domain)
    db = Database.get_from_global_context()
    with db.transaction() as cur:
        rows = repo.list_forwardings(cur, source=source, domain=domain)
    return build_response(200, data=ctx.filter_readable(rows, "source"))


@api.route("/api/forwardings", methods=["POST"])
def create_forwarding() -> Response:
    ctx = Context.authenticate()
    body = json_body()
    source = normalize_email(json_body_field(body, "source"))
    destination = normalize_email(json_body_field(body, "destination"))
    ctx.require(domain_of(source), WRITE)
    keep_copy = json_body_field(body, "keep_copy", required=False)
    keep_copy = False if keep_copy is None else bool(keep_copy)
    db = Database.get_from_global_context()
    with db.transaction() as cur:
        row = repo.create_forwarding(cur, source, destination, keep_copy)
    return build_response(201, data=row)


@api.route("/api/forwardings/<int:fid>", methods=["DELETE"])
def delete_forwarding(fid: int) -> Response:
    ctx = Context.authenticate()
    db = Database.get_from_global_context()
    with db.transaction() as cur:
        rows = repo.list_forwardings(cur)
        target = next((r for r in rows if r["id"] == fid), None)
        if not target:
            raise ResourceNotFoundError(msg="Forwarding not found", detail={"id": fid})
        ctx.require(domain_of(target["source"]), WRITE)
        repo.delete_forwarding(cur, fid)
    return build_response(200, data={"id": fid, "deleted": True})


# ── sender-logins (send-as grants) ────────────────────────────────────────────
@api.route("/api/sender-logins", methods=["GET"])
def list_sender_logins() -> Response:
    ctx = Context.authenticate()
    domain = query_str("domain", default=None)
    if domain:
        domain = normalize_domain(domain)
    db = Database.get_from_global_context()
    with db.transaction() as cur:
        rows = repo.list_sender_logins(cur, domain=domain)
    return build_response(200, data=ctx.filter_readable(rows, "allowed_sender"))


@api.route("/api/sender-logins", methods=["POST"])
def create_sender_login() -> Response:
    ctx = Context.authenticate()
    body = json_body()
    login_email = normalize_email(json_body_field(body, "login_email"))
    allowed_sender = normalize_email(json_body_field(body, "allowed_sender"))
    ctx.require(domain_of(allowed_sender), WRITE)
    db = Database.get_from_global_context()
    with db.transaction() as cur:
        row = repo.create_sender_login(cur, login_email, allowed_sender)
    return build_response(201, data=row)


@api.route("/api/sender-logins/<int:sid>", methods=["DELETE"])
def delete_sender_login(sid: int) -> Response:
    ctx = Context.authenticate()
    db = Database.get_from_global_context()
    with db.transaction() as cur:
        rows = repo.list_sender_logins(cur)
        target = next((r for r in rows if r["id"] == sid), None)
        if not target:
            raise ResourceNotFoundError(msg="Sender-login grant not found", detail={"id": sid})
        ctx.require(domain_of(target["allowed_sender"]), WRITE)
        repo.delete_sender_login(cur, sid)
    return build_response(200, data={"id": sid, "deleted": True})


# ── audit (read-only) ──────────────────────────────────────────────────────────
@api.route("/api/audit", methods=["GET"])
def list_audit() -> Response:
    ctx = Context.authenticate()
    login = query_str("login", default=None)
    event_type = query_str("event_type", default=None)
    since = query_str("since", default=None)
    limit = query_int("limit", default=100, min_val=1, max_val=1000)
    db = Database.get_from_global_context()
    with db.transaction() as cur:
        rows = repo.list_audit(cur, login=login, event_type=event_type, since=since, limit=limit)
    return build_response(200, data=ctx.filter_readable(rows, "login"))
