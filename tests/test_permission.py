import pytest
from mail_controller.domain.permission import Permission, PermissionAction
from mail_controller.exception.validator_exceptions import ValidationError


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


def test_parse_per_entity_action():
    perm = p("example.com:write_domain")
    assert perm.scope == "example.com"
    assert perm.action == PermissionAction.WRITE_DOMAIN


def test_write_entity_implies_read_same_entity():
    perm = p("example.com:write_forwarding")
    assert perm.allows("example.com", PermissionAction.WRITE_FORWARDING)
    assert perm.allows("example.com", PermissionAction.READ_FORWARDING)


def test_write_entity_does_not_imply_other_entity():
    perm = p("example.com:write_forwarding")
    assert not perm.allows("example.com", PermissionAction.READ_USER)
    assert not perm.allows("example.com", PermissionAction.WRITE_USER)


def test_read_entity_does_not_imply_write():
    perm = p("example.com:read_user")
    assert perm.allows("example.com", PermissionAction.READ_USER)
    assert not perm.allows("example.com", PermissionAction.WRITE_USER)


def test_any_satisfies_every_entity_action():
    perm = p("example.com:*")
    for action in (PermissionAction.READ_DOMAIN, PermissionAction.WRITE_DOMAIN,
                   PermissionAction.READ_AUDIT, PermissionAction.READ_METRICS):
        assert perm.allows("example.com", action)


def test_read_audit_and_metrics_satisfy_only_themselves():
    assert p("*:read_audit").allows("x.test", PermissionAction.READ_AUDIT)
    assert not p("*:read_audit").allows("x.test", PermissionAction.READ_DOMAIN)
    assert p("*:read_metrics").allows("x.test", PermissionAction.READ_METRICS)
    assert not p("*:read_metrics").allows("x.test", PermissionAction.READ_AUDIT)


def test_per_entity_glob_scope():
    perm = p("*.example.com:write_user")
    assert perm.allows("a.example.com", PermissionAction.WRITE_USER)
    assert perm.allows("a.example.com", PermissionAction.READ_USER)
    assert not perm.allows("example.com", PermissionAction.WRITE_USER)
