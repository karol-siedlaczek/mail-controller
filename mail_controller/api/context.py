from dataclasses import dataclass
from mail_controller.domain.identity import Identity
from mail_controller.domain.permission import PermissionAction
from mail_controller.api.helpers import require_auth, get_remote_ip
from mail_controller.exception.api_exceptions import PermissionDeniedError


@dataclass(frozen=True)
class Context:
    remote_ip: str | None
    identity: Identity

    @classmethod
    def authenticate(cls) -> "Context":
        remote_ip = get_remote_ip()
        identity = require_auth(remote_ip)
        return cls(remote_ip, identity)

    def require(self, domain: str, action: PermissionAction) -> None:
        if not self.identity.allows(domain, action):
            raise PermissionDeniedError(
                detail={"identity": self.identity.id, "domain": domain, "action": action.value}
            )

    def _has_star_read(self) -> bool:
        # A global reader is any "*"-scope permission whose action grants READ
        # (READ, or WRITE/ANY which imply READ). No domain is involved.
        return any(p.scope == "*" and p._action_satisfies(PermissionAction.READ)
                   for p in self.identity.permissions)

    def filter_readable(self, rows: list, domain_fn) -> list:
        out: list = []
        for row in rows:
            domain = domain_fn(row)
            if domain is None:
                if self._has_star_read():
                    out.append(row)
                continue
            if self.identity.allows(domain, PermissionAction.READ):
                out.append(row)
        return out
