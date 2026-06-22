import re
import fnmatch
from enum import Enum
from dataclasses import dataclass
from mail_controller.validation.require import Require


class PermissionAction(Enum):
    ANY = "*"
    READ = "read"
    WRITE = "write"

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

    def _scope_matches(self, domain: str) -> bool:
        if self.scope == "*":
            return True
        return fnmatch.fnmatch(domain.lower(), self.scope.lower())

    def _action_satisfies(self, action: PermissionAction) -> bool:
        if self.action == PermissionAction.ANY:
            return True
        if self.action == PermissionAction.WRITE:
            return action in (PermissionAction.READ, PermissionAction.WRITE)
        return action == PermissionAction.READ

    def allows(self, domain: str, action: PermissionAction) -> bool:
        return self._scope_matches(domain) and self._action_satisfies(action)
