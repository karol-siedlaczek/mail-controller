from dataclasses import dataclass
from datetime import datetime
from mail_controller.domain.address import EmailAddress


@dataclass(frozen=True)
class Mailbox:
    email: EmailAddress
    quota_bytes: int = 0
    active: bool = True
    domain_id: int | None = None
    id: int | None = None
    created_at: datetime | None = None

    @classmethod
    def from_row(cls, row: dict) -> "Mailbox":
        return cls(
            email=EmailAddress(row["email"]),
            quota_bytes=row["quota_bytes"],
            active=row["active"],
            domain_id=row["domain_id"],
            id=row["id"],
            created_at=row["created_at"],
        )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "email": self.email.value,
            "quota_bytes": self.quota_bytes,
            "active": self.active,
            "created_at": self.created_at,
            "domain_id": self.domain_id,
        }
