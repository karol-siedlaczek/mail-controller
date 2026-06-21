import pytest
from mail_admin.domain.permission import Permission, PermissionAction
from mail_admin.exception.validator_exceptions import ValidationError


def p(s):
    return Permission.from_string(0, s)


def test_parse_write():
    perm = p("example.com:write")
    assert perm.scope == "example.com"
    assert perm.action == PermissionAction.WRITE


def test_parse_star_write():
    perm = p("*:write")
    assert perm.scope == "*"
    assert perm.action == PermissionAction.WRITE


def test_parse_invalid_action():
    with pytest.raises(ValidationError):
        p("example.com:delete")


def test_parse_missing_colon():
    with pytest.raises(ValidationError):
        p("example.com")


def test_write_implies_read():
    perm = p("example.com:write")
    assert perm.allows("example.com", PermissionAction.READ)
    assert perm.allows("example.com", PermissionAction.WRITE)


def test_read_does_not_imply_write():
    perm = p("example.com:read")
    assert perm.allows("example.com", PermissionAction.READ)
    assert not perm.allows("example.com", PermissionAction.WRITE)


def test_star_scope_matches_any_domain():
    perm = p("*:read")
    assert perm.allows("anything.test", PermissionAction.READ)


def test_glob_scope():
    perm = p("*.example.com:write")
    assert perm.allows("a.example.com", PermissionAction.WRITE)
    assert not perm.allows("example.com", PermissionAction.WRITE)


def test_exact_scope_no_cross_domain():
    perm = p("example.com:write")
    assert not perm.allows("other.com", PermissionAction.WRITE)
