from datetime import datetime, timezone
from mail_controller.domain.domain import Domain
from mail_controller.domain.address import DomainName
from mail_controller.domain.mailbox import Mailbox
from mail_controller.domain.address import EmailAddress
from mail_controller.domain.forwarding import Forwarding
from mail_controller.domain.sender_login import SenderLogin

_TS = datetime(2026, 1, 1, tzinfo=timezone.utc)


def test_domain_from_row_to_dict_roundtrip():
    row = {"id": 1, "domain": "example.com", "dkim_selector": "default",
           "active": True, "created_at": _TS}
    d = Domain.from_row(row)
    assert d.name == DomainName("example.com")
    assert d.to_dict() == row  # exact key/value contract


def test_mailbox_from_row_to_dict_roundtrip():
    row = {"id": 5, "email": "alice@example.com", "quota_bytes": 1024,
           "active": True, "created_at": _TS, "domain_id": 1}
    m = Mailbox.from_row(row)
    assert m.email == EmailAddress("alice@example.com")
    assert m.to_dict() == row


def test_forwarding_from_row_to_dict_roundtrip():
    row = {"id": 3, "source": "a@example.com", "destination": "b@elsewhere.test",
           "keep_copy": False, "active": True, "created_at": _TS}
    f = Forwarding.from_row(row)
    assert f.source == EmailAddress("a@example.com")
    assert f.to_dict() == row


def test_sender_login_from_row_to_dict_roundtrip():
    row = {"id": 9, "login_email": "ops@example.com", "allowed_sender": "boss@example.com",
           "active": True, "created_at": _TS}
    s = SenderLogin.from_row(row)
    assert s.allowed_sender == EmailAddress("boss@example.com")
    assert s.to_dict() == row
