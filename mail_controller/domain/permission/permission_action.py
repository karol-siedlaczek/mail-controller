from enum import Enum

class PermissionAction(Enum):
    ANY = "*"
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
