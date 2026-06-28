from datetime import datetime, timezone
from mail_controller.domain.domain import Domain
from mail_controller.domain.address import DomainName
from mail_controller.domain.mailbox import Mailbox
from mail_controller.domain.address import EmailAddress
from mail_controller.domain.forwarding import Forwarding
from mail_controller.domain.sender_login import SenderLogin
from mail_controller.domain.audit import AuditEntry

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


def test_audit_entry_roundtrip_and_login_domain():
    row = {"id": 1, "event_type": "auth", "success": True, "login": "alice@example.com",
           "src_ip": "10.0.0.1", "host": "mx1", "sender": None, "recipient": None,
           "message_id": None, "queue_id": None, "score": None, "msg": "ok",
           "pid": 42, "timestamp": _TS}
    a = AuditEntry.from_row(row)
    assert a.to_dict() == row
    assert a.login_domain() == "example.com"


def test_audit_entry_login_domain_none_when_no_at():
    a = AuditEntry(id=2, event_type="delivery", login="not-an-email")
    assert a.login_domain() is None
    assert AuditEntry(id=3, event_type="delivery", login=None).login_domain() is None


def test_audit_entry_authz_domain_by_event_type():
    from mail_controller.domain.audit import AuditEntry
    send = AuditEntry(id=1, event_type="send", login=None, sender="u@example.com")
    delivery = AuditEntry(id=2, event_type="delivery", login=None, recipient="v@other.com")
    auth = AuditEntry(id=3, event_type="auth", login="w@third.com")
    assert send.authz_domain() == "example.com"
    assert delivery.authz_domain() == "other.com"
    assert auth.authz_domain() == "third.com"
    assert AuditEntry(id=4, event_type="send", sender=None).authz_domain() is None
