from dataclasses import dataclass
from datetime import datetime
from mail_controller.domain.address import EmailAddress


@dataclass(frozen=True, kw_only=True)
class SenderLogin:
    id: int | None = None
    login_email: EmailAddress
    allowed_sender: EmailAddress
    active: bool = True
    created_at: datetime | None = None


    @classmethod
    def from_row(cls, row: dict) -> "SenderLogin":
        return cls(
            login_email=EmailAddress(row["login_email"]),
            allowed_sender=EmailAddress(row["allowed_sender"]),
            active=row["active"],
            id=row["id"],
            created_at=row["created_at"]
        )


    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "login_email": self.login_email.value,
            "allowed_sender": self.allowed_sender.value,
            "active": self.active,
            "created_at": self.created_at,
        }
