from mail_controller.validation.require import Require
from mail_controller.exception.validator_exceptions import ValidationError
from mail_controller.exception.api_exceptions import InvalidRequestError


def normalize_email(email: str) -> str:
    try:
        Require.email("email", email)
    except ValidationError as e:
        raise InvalidRequestError("Invalid email address", detail={"email": email, "error": str(e)})
    return email.strip().lower()


def normalize_domain(domain: str) -> str:
    try:
        Require.domain("domain", domain)
    except ValidationError as e:
        raise InvalidRequestError("Invalid domain", detail={"domain": domain, "error": str(e)})
    return domain.strip().lower()


def domain_of(email: str) -> str:
    if not email or "@" not in email:
        raise InvalidRequestError("Address is missing a domain part", detail={"email": email})
    return email.rsplit("@", 1)[1].strip().lower()
