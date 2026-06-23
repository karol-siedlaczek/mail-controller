import pytest
from mail_controller.validation.require import Require
from mail_controller.exception.validator_exceptions import ValidationError


# ── Require.port ──────────────────────────────────────────────────────────────
def test_port_out_of_range_raises_port_specific_error():
    # 70000 > 65535: must raise the port-range message, not the generic max message.
    # "out of range" appears ONLY in the port-specific error, never in max's message.
    with pytest.raises(ValidationError) as exc:
        Require.port("PG_PORT", 70000)
    assert "out of range" in str(exc.value).lower()


def test_port_non_int_raises_port_specific_error():
    with pytest.raises(ValidationError) as exc:
        Require.port("PG_PORT", "not-a-number")
    assert "out of range" in str(exc.value).lower()


def test_port_valid_does_not_raise():
    Require.port("PG_PORT", 5432)  # in range → no exception


# ── Require.installed_module ──────────────────────────────────────────────────
def test_installed_module_raises_when_module_absent():
    with pytest.raises(ValidationError):
        Require.installed_module("FEATURE", "on", "definitely_missing_module_xyz")


def test_installed_module_silent_when_module_present():
    Require.installed_module("FEATURE", "on", "os")  # stdlib → installed → no raise
