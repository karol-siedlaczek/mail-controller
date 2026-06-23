import pytest
from mail_controller.domain.address import domain_of, normalize_email, normalize_domain, DomainName, EmailAddress
from mail_controller.exception.api_exceptions import InvalidRequestError
from mail_controller.exception.validator_exceptions import ValidationError


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


def test_domainname_parse_normalizes():
    assert DomainName.parse("  ExAmple.COM ").value == "example.com"


def test_domainname_parse_rejects_invalid():
    with pytest.raises(ValidationError):
        DomainName.parse("not a domain")


def test_emailaddress_parse_normalizes():
    assert EmailAddress.parse("  Alice@Example.COM ").value == "alice@example.com"


def test_emailaddress_parse_rejects_invalid():
    with pytest.raises(ValidationError):
        EmailAddress.parse("nope")


def test_emailaddress_domain_property():
    assert EmailAddress.parse("alice@example.com").domain == DomainName("example.com")


def test_direct_construction_does_not_validate():
    # trusted construction path: no exception even for non-canonical input
    assert DomainName("anything").value == "anything"
    assert EmailAddress("x@y").value == "x@y"
