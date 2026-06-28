import re
from dataclasses import dataclass
from mail_controller.validation.require import Require
from mail_controller.domain.permission.permission_action import PermissionAction

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
        # Per-entity: write_<entity> implies read_<entity>.
        return (self.action.value.startswith("write_")
                and action.value == "read_" + self.action.value[len("write_"):])

    def allows(self, domain: str, action: "PermissionAction") -> bool:
        # Action gate.
        if not self.allows_action(action):
            return False
        scope = self.scope.lower()
        domain = domain.lower()
        # "*" = all; exact domain match.
        if scope == "*" or scope == domain:
            return True
        # "*.base" matches exactly one label below base (no dots in that label).
        if scope.startswith("*."):
            base = scope[2:]
            if not domain.endswith("." + base):
                return False
            label = domain[: -(len(base) + 1)]
            return bool(label) and "." not in label
        return False
