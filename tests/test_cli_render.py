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
