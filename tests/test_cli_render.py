import importlib.util
import pytest
from pathlib import Path

# Load mailctl.py as a module (it lives at images/mail-controller/mailctl.py)
_SPEC = importlib.util.spec_from_file_location(
    "mailctl", str(Path(__file__).resolve().parents[1] / "mailctl.py"))
mailctl = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(mailctl)


def test_format_values():
    assert set(mailctl.Format.values()) == {"table", "json", "kv", "value"}


def test_format_default_is_table():
    assert mailctl.Format.default() == mailctl.Format.TABLE


def test_cmdresult_from_dict_ok():
    r = mailctl.CmdResult.from_dict({"a": 1})
    assert r.exit_code == mailctl.ExitCode.OK
    assert r.data == {"a": 1}


def test_cmdresult_parse_response_strips_envelope():
    class FakeResp:
        ok = True
        def json(self):
            return {"data": {"domain": "x.test"}, "timestamp": "t",
                    "path": "/api/domains", "http_code": 200}
    r = mailctl.CmdResult.from_response(FakeResp())
    assert r.data == {"domain": "x.test"}


# ── quota formatting (mailctl) ────────────────────────────────────────────────
def test_format_quota_zero_is_unlimited():
    assert mailctl.format_quota(0) == "unlimited"


def test_format_quota_exact_units_have_no_decimals():
    assert mailctl.format_quota(1024) == "1 KB"
    assert mailctl.format_quota(256 * 1024 ** 2) == "256 MB"
    assert mailctl.format_quota(2 * 1024 ** 3) == "2 GB"
    assert mailctl.format_quota(1024 ** 4) == "1 TB"


def test_format_quota_sub_kilobyte_is_bytes():
    assert mailctl.format_quota(500) == "500 B"


def test_format_quota_non_exact_uses_two_decimals():
    assert mailctl.format_quota(1536) == "1.50 KB"


def test_apply_quota_format_replaces_key_in_place_keeping_position():
    data = {"id": 1, "email": "a@x.test", "quota_bytes": 2 * 1024 ** 3, "active": True}
    mailctl.apply_quota_format(data, raw_quota=False)
    assert "quota_bytes" not in data
    assert data["quota"] == "2 GB"
    # column position preserved (between email and active)
    assert list(data.keys()) == ["id", "email", "quota", "active"]


def test_apply_quota_format_handles_list_of_rows():
    data = [{"quota_bytes": 0}, {"quota_bytes": 1024}]
    mailctl.apply_quota_format(data, raw_quota=False)
    assert data == [{"quota": "unlimited"}, {"quota": "1 KB"}]


def test_apply_quota_format_raw_is_noop():
    data = {"quota_bytes": 1024}
    mailctl.apply_quota_format(data, raw_quota=True)
    assert data == {"quota_bytes": 1024}
