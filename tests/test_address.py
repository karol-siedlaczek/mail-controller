import pytest
from mail_controller.domain.address import DomainName, EmailAddress
from mail_controller.exception.validator_exceptions import ValidationError


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


@pytest.mark.parametrize("bad", ["user@-bad.com", "user@b..com", "user@a-.com"])
def test_emailaddress_parse_rejects_invalid_domain_part(bad):
    with pytest.raises(ValidationError):
        EmailAddress.parse(bad)


def test_emailaddress_parse_accepts_valid_domain_part():
    assert EmailAddress.parse("alice@sub.example.com").value == "alice@sub.example.com"
