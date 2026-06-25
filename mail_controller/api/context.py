from dataclasses import dataclass
from flask import request
from mail_controller.domain.identity import Identity
from mail_controller.domain.permission import PermissionAction
from mail_controller.conf.config import Config
from mail_controller.exception.api_exceptions import PermissionDeniedError
from mail_controller.exception.auth_exceptions import (
    AuthTokenMissingException, AuthFailedException, AuthIpNotAllowedException,
)


@dataclass
class Context:
    remote_ip: str | None = None
    identity: Identity | None = None


    @classmethod
    def authenticate(cls) -> "Context":
        ctx = cls()
        ctx.remote_ip = ctx.get_remote_ip()
        ctx.identity = ctx.resolve_identity()
        return ctx


    def resolve_identity(self) -> Identity:
        auth_header = request.headers.get("Authorization", None)

        if not auth_header or auth_header == "":
            raise AuthTokenMissingException("Authorization header is missing or empty")
        elif not auth_header.startswith("Bearer "):
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
        if not identity.is_ip_allowed(self.remote_ip):
            raise AuthIpNotAllowedException(self.remote_ip)

        return identity


    def get_remote_ip(self) -> str | None:
        if request.remote_addr:
            return request.remote_addr

        xff = request.headers.get("X-Forwarded-For", "")
        return xff.split(",")[0].strip() if xff else None
    

    def require(self, domain: str, action: PermissionAction) -> None:
        if not self.identity.allows(domain, action):
            raise PermissionDeniedError(
                detail={"identity": self.identity.id, "domain": domain, "action": action.value}
            )


    def require_action(self, action: PermissionAction) -> None:
        # Gate a non-domain-scoped surface (e.g. metrics): the identity must hold
        # at least one permission whose action satisfies `action`, regardless of scope.
        if not any(p.allows_action(action) for p in self.identity.permissions):
            raise PermissionDeniedError(
                detail={"identity": self.identity.id, "action": action.value}
            )

    def _has_star(self, action: PermissionAction) -> bool:
        # A "*"-scope permission grants `action` regardless of domain. Reuses
        # Permission.allows so the action/scope rule lives in one place.
        return any(p.scope == "*" and p.allows(domain="*", action=action)
                   for p in self.identity.permissions)
