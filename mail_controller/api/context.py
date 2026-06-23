from dataclasses import dataclass
from mail_controller.domain.identity import Identity
from mail_controller.domain.permission import PermissionAction
from mail_controller.domain.address import domain_of
from mail_controller.api.helpers import require_auth, get_remote_ip
from mail_controller.exception.api_exceptions import PermissionDeniedError, InvalidRequestError


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

    def filter_readable(self, rows: list[dict], domain_key: str) -> list[dict]:
        out: list[dict] = []
        for row in rows:
            value = row.get(domain_key)
            if value is None:
                # audit rows with no login: visible only to a *-scope reader
                if self._has_star_read():
                    out.append(row)
                continue
            if domain_key == "domain":
                domain = value
            else:
                try:
                    domain = domain_of(value)
                except InvalidRequestError:
                    # malformed value (e.g. SASL login without @): treat like null
                    if self._has_star_read():
                        out.append(row)
                    continue
            if self.identity.allows(domain, PermissionAction.READ):
                out.append(row)
        return out
