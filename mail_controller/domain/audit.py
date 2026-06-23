from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class AuditEntry:
    id: int
    event_type: str
    success: bool | None = None
    login: str | None = None
    src_ip: str | None = None
    host: str | None = None
    sender: str | None = None
    recipient: str | None = None
    message_id: str | None = None
    queue_id: str | None = None
    score: float | None = None
    msg: str | None = None
    pid: int | None = None
    timestamp: datetime | None = None

    @classmethod
    def from_row(cls, row: dict) -> "AuditEntry":
        return cls(**{f: row.get(f) for f in (
            "id", "event_type", "success", "login", "src_ip", "host", "sender",
            "recipient", "message_id", "queue_id", "score", "msg", "pid", "timestamp",
        )})

    def to_dict(self) -> dict:
        return {f: getattr(self, f) for f in (
            "id", "event_type", "success", "login", "src_ip", "host", "sender",
            "recipient", "message_id", "queue_id", "score", "msg", "pid", "timestamp",
        )}

    def login_domain(self) -> str | None:
        if not self.login or "@" not in self.login:
            return None
        return self.login.rsplit("@", 1)[1].lower()
