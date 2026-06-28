from dataclasses import dataclass
from mail_controller.validation.require import Require
from mail_controller.exception.validator_exceptions import ValidationError


@dataclass(frozen=True)
class DomainName:
    value: str

    @classmethod
    def parse(cls, raw: str) -> "DomainName":
        normalized = raw.strip().lower()
        Require.domain("domain", normalized)
        return cls(normalized)


@dataclass(frozen=True)
class EmailAddress:
    value: str

    @classmethod
    def parse(cls, raw: str) -> "EmailAddress":
        normalized = raw.strip().lower()
        Require.email("email", normalized)
        Require.domain("email", normalized.rsplit("@", 1)[1])
        return cls(normalized)

    @property
    def domain(self) -> DomainName:
        if "@" not in self.value:
            raise ValidationError(f"Address '{self.value}' is missing a domain part")
        return DomainName(self.value.rsplit("@", 1)[1])
