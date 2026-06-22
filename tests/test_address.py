import pytest
from mail_controller.domain.address import domain_of, normalize_email, normalize_domain
from mail_controller.exception.api_exceptions import InvalidRequestError


def test_domain_of():
    assert domain_of("Alice@Example.COM") == "example.com"


def test_domain_of_no_at():
    with pytest.raises(InvalidRequestError):
        domain_of("alice")


def test_normalize_email():
    assert normalize_email("Alice@Example.com") == "alice@example.com"


def test_normalize_email_invalid():
    with pytest.raises(InvalidRequestError):
        normalize_email("nope")


def test_normalize_domain():
    assert normalize_domain("Example.COM") == "example.com"


def test_normalize_domain_invalid():
    with pytest.raises(InvalidRequestError):
        normalize_domain("not a domain")
