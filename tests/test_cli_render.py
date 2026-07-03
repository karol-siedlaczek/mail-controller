import importlib.util
import pytest
import typer
from pathlib import Path
from typer.testing import CliRunner

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


# ── single-row (vertical) render ──────────────────────────────────────────────

ENV = {"MAILCTL_API_URL": "http://x", "MAILCTL_TOKEN": "t"}


def _pin_format(monkeypatch, fmt):
    settings = mailctl.Settings(
        api_url="http://x", token="t", log_file=None, log_level=None, format=fmt)
    monkeypatch.setattr(mailctl, "get_ctx_settings", lambda: settings)


def test_single_row_table_is_vertical(monkeypatch, capsys):
    _pin_format(monkeypatch, mailctl.Format.TABLE)
    result = mailctl.CmdResult.from_dict({"domain": "x.test", "active": True})

    with pytest.raises(typer.Exit) as exc:
        result.render_and_exit(single_row=True)

    assert exc.value.exit_code == 0
    out = capsys.readouterr().out
    assert "Field" in out and "Value" in out
    assert "x.test" in out
    assert "domain" in out


def test_table_without_single_row_stays_horizontal(monkeypatch, capsys):
    _pin_format(monkeypatch, mailctl.Format.TABLE)
    result = mailctl.CmdResult.from_dict({"domain": "x.test", "active": True})

    with pytest.raises(typer.Exit):
        result.render_and_exit()  # single_row defaults to False

    out = capsys.readouterr().out
    assert "domain" in out and "active" in out
    assert "Field" not in out


class _FakeResponse:
    def __init__(self, payload, ok=True, status_code=200):
        self._payload = payload
        self.ok = ok
        self.status_code = status_code
        self.text = "" if payload is None else str(payload)

    def json(self):
        return self._payload


class _FakeClient:
    def __init__(self, payload):
        self._payload = payload

    def request(self, method, path, *, params=None, json_body=None):
        return _FakeResponse(self._payload)


def _run(monkeypatch, tmp_path, payload, args, fmt=mailctl.Format.TABLE):
    monkeypatch.setattr(mailctl, "SETTINGS_FILE", tmp_path / "nonexistent-mailctl")
    _pin_format(monkeypatch, fmt)
    monkeypatch.setattr(
        mailctl.Client, "init",
        classmethod(lambda cls, ctx, fmt, *, timeout: _FakeClient(payload)),
    )
    return CliRunner().invoke(mailctl.app, args, env=ENV)


def test_domain_show_renders_vertical(monkeypatch, tmp_path):
    payload = {"data": {"domain": "x.test", "active": True, "dkim_selector": "sel"}}
    result = _run(monkeypatch, tmp_path, payload, ["domain", "show", "x.test"])
    assert result.exit_code == 0, result.output
    assert "Field" in result.output and "Value" in result.output
    assert "x.test" in result.output


def test_user_show_renders_vertical(monkeypatch, tmp_path):
    payload = {"data": {"email": "a@x.test", "active": True}}
    result = _run(monkeypatch, tmp_path, payload, ["user", "show", "a@x.test"])
    assert result.exit_code == 0, result.output
    assert "Field" in result.output and "Value" in result.output
    assert "a@x.test" in result.output


def test_domain_list_stays_horizontal(monkeypatch, tmp_path):
    payload = {"data": [{"domain": "x.test", "active": True}]}
    result = _run(monkeypatch, tmp_path, payload, ["domain", "list"])
    assert result.exit_code == 0, result.output
    assert "Field" not in result.output
    assert "domain" in result.output
