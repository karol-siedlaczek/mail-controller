from dataclasses import dataclass
from datetime import datetime
from mail_controller.domain.address import DomainName


@dataclass(frozen=True)
class Domain:
    name: DomainName
    dkim_selector: str = "default"
    active: bool = True
    id: int | None = None
    created_at: datetime | None = None

    @classmethod
    def from_row(cls, row: dict) -> "Domain":
        return cls(
            name=DomainName(row["domain"]),
            dkim_selector=row["dkim_selector"],
            active=row["active"],
            id=row["id"],
            created_at=row["created_at"],
        )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "domain": self.name.value,
            "dkim_selector": self.dkim_selector,
            "active": self.active,
            "created_at": self.created_at,
        }
