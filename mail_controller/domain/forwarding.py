from dataclasses import dataclass
from datetime import datetime
from mail_controller.domain.address import EmailAddress


@dataclass(frozen=True, kw_only=True)
class Forwarding:
    id: int | None = None
    source: EmailAddress
    destination: EmailAddress
    keep_copy: bool = False
    active: bool = True
    created_at: datetime | None = None


    @classmethod
    def from_row(cls, row: dict) -> "Forwarding":
        return cls(
            source=EmailAddress(row["source"]),
            destination=EmailAddress(row["destination"]),
            keep_copy=row["keep_copy"],
            active=row["active"],
            id=row["id"],
            created_at=row["created_at"]
        )


    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "source": self.source.value,
            "destination": self.destination.value,
            "keep_copy": self.keep_copy,
            "active": self.active,
            "created_at": self.created_at
        }
