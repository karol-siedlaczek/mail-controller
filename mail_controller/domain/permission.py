import re
import fnmatch
from enum import Enum
from dataclasses import dataclass
from mail_controller.validation.require import Require


class PermissionAction(Enum):
    ANY = "*"
    READ = "read"      # legacy — removed in the cleanup task
    WRITE = "write"    # legacy — removed in the cleanup task
    READ_DOMAIN = "read_domain"
    WRITE_DOMAIN = "write_domain"
    READ_USER = "read_user"
    WRITE_USER = "write_user"
    READ_FORWARDING = "read_forwarding"
    WRITE_FORWARDING = "write_forwarding"
    READ_SENDER_LOGIN = "read_sender_login"
    WRITE_SENDER_LOGIN = "write_sender_login"
    READ_AUDIT = "read_audit"
    READ_METRICS = "read_metrics"

    @classmethod
    def values(cls) -> list[str]:
        return [item.value for item in cls]


@dataclass(frozen=True)
class Permission:
    scope: str
    action: PermissionAction

    @classmethod
    def from_string(cls, index: int, permission: str) -> "Permission":
        allowed = [re.escape(v) for v in PermissionAction.values()]
        pattern = re.compile(rf'^(.*):(\*|{"|".join(allowed)})$')
        permission = permission.strip()
        match = Require.match(
            field=f"permissions[{index}]",
            val=permission,
            pattern=pattern,
            custom_err=(
                f"Key 'permissions[{index}]' with '{permission}' permission is invalid, "
                f"value needs to be provided in following format: "
                f"'(*|<domain_pattern>):({'|'.join(PermissionAction.values())})'"
            ),
        )
        scope, action_raw = match.groups()
        Require.present(f"permissions[{index}].scope", scope)
        Require.one_of(f"permissions[{index}]", action_raw, PermissionAction.values())
        
        return cls(scope, PermissionAction(action_raw))


    def allows_action(self, action: "PermissionAction") -> bool:
        # ANY satisfies every action.
        if self.action == PermissionAction.ANY:
            return True
        # Exact match.
        if self.action == action:
            return True
        # Legacy generic write ⇒ read (removed with READ/WRITE in the cleanup task).
        if self.action == PermissionAction.WRITE and action == PermissionAction.READ:
            return True
        # Per-entity: write_<entity> implies read_<entity>.
        return (self.action.value.startswith("write_")
                and action.value == "read_" + self.action.value[len("write_"):])

    def allows(self, domain: str, action: "PermissionAction") -> bool:
        # Action gate.
        if not self.allows_action(action):
            return False
        # Scope gate: "*", exact domain, or glob pattern (fnmatch).
        if self.scope == "*" or self.scope == domain.lower():
            return True
        return fnmatch.fnmatch(domain.lower(), self.scope.lower())
