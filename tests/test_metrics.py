from mail_controller.api.helpers import render_metrics
from mail_controller.api.routes import _scope_metrics


class _FakeIdentity:
    def __init__(self, readable):
        self._readable = set(readable)

    def allows(self, dom, action):
        return dom in self._readable


class _FakeCtx:
    def __init__(self, star, readable):
        self._star = star
        self.identity = _FakeIdentity(readable)

    def _has_star(self, action):
        return self._star


def test_scope_metrics_scoped_filters_by_readable_domain():
    ctx = _FakeCtx(star=False, readable={"example.com"})
    totals, traffic = _scope_metrics(
        ctx,
        domain_names=["example.com", "other.test"],
        users_by={"example.com": 3, "other.test": 9},
        fwd_by={"example.com": 1},
        slm_by={"other.test": 4},
        audit_rows=[
            {"event_type": "auth", "success": True, "dom": "example.com", "count": 5},
            {"event_type": "auth", "success": False, "dom": "example.com", "count": 2},
            {"event_type": "send", "success": None, "dom": "example.com", "count": 4},
            {"event_type": "delivery", "success": None, "dom": "other.test", "count": 9},
            {"event_type": "auth", "success": True, "dom": None, "count": 1},
        ],
    )
    assert totals == {"domains": 1, "users": 3, "forwardings": 1, "sender_logins": 0}
    assert traffic == {"auth_success": 5, "auth_failure": 2, "send": 4, "delivery": 0}


def test_scope_metrics_star_sees_everything_including_null_domain():
    ctx = _FakeCtx(star=True, readable=set())
    totals, traffic = _scope_metrics(
        ctx,
        domain_names=["example.com", "other.test"],
        users_by={"example.com": 3, "other.test": 9},
        fwd_by={},
        slm_by={},
        audit_rows=[
            {"event_type": "delivery", "success": None, "dom": "other.test", "count": 9},
            {"event_type": "auth", "success": True, "dom": None, "count": 1},
        ],
    )
    assert totals["domains"] == 2 and totals["users"] == 12
    assert traffic["delivery"] == 9 and traffic["auth_success"] == 1


def _render():
    return render_metrics(
        build_info={"version": "1.2.3", "git_sha": "abc1234"},
        totals={"domains": 2, "users": 5, "forwardings": 1, "sender_logins": 0},
        traffic={"auth_success": 7, "auth_failure": 3, "send": 4, "delivery": 9},
    )


def test_render_includes_build_info_with_labels():
    out = _render()
    assert 'mailctl_build_info{version="1.2.3",git_sha="abc1234"} 1' in out


def test_render_includes_totals():
    out = _render()
    assert "mailctl_domains_total 2" in out
    assert "mailctl_users_total 5" in out
    assert "mailctl_forwardings_total 1" in out
    assert "mailctl_sender_logins_total 0" in out


def test_render_includes_traffic_with_success_label():
    out = _render()
    assert 'mailctl_auth_events_5m{success="true"} 7' in out
    assert 'mailctl_auth_events_5m{success="false"} 3' in out
    assert "mailctl_send_events_5m 4" in out
    assert "mailctl_delivery_events_5m 9" in out


def test_render_has_help_and_type_lines_and_trailing_newline():
    out = _render()
    assert "# HELP mailctl_build_info" in out
    assert "# TYPE mailctl_build_info gauge" in out
    assert out.endswith("\n")


def test_render_escapes_label_values():
    out = render_metrics(
        build_info={"version": 'a"b\\c', "git_sha": "x"},
        totals={"domains": 0, "users": 0, "forwardings": 0, "sender_logins": 0},
        traffic={"auth_success": 0, "auth_failure": 0, "send": 0, "delivery": 0},
    )
    assert 'version="a\\"b\\\\c"' in out
