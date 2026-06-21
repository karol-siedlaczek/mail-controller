from pathlib import Path

# Reads the vendored copy of the mail-server schema (tests/schema.sql). The
# authoritative schema lives in the mail-server image; this fixture must declare
# the mail_admin_rw role + grants this image depends on.
SCHEMA = (Path(__file__).resolve().parent / "schema.sql").read_text()


def test_mail_admin_rw_role_declared():
    assert "mail_admin_rw" in SCHEMA


def test_mail_admin_rw_has_write_grants():
    low = SCHEMA.lower()
    assert "insert" in low and "update" in low and "delete" in low
    # the write grant line references all four writable tables
    assert "domains, users, forwardings, sender_login_maps" in SCHEMA


def test_mail_admin_rw_audit_select():
    assert "SELECT ON audit_logs TO mail_admin_rw" in SCHEMA
