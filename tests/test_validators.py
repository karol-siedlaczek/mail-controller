import pytest
from datetime import datetime
from flask import Flask
from mail_controller.api import validators as v
from mail_controller.exception.api_exceptions import InvalidRequestError

app = Flask(__name__)


def test_query_int_ok():
    with app.test_request_context("/?limit=20"):
        assert v.query_int("limit", default=100) == 20


def test_query_int_default():
    with app.test_request_context("/"):
        assert v.query_int("limit", default=100) == 100


def test_query_int_bad():
    with app.test_request_context("/?limit=abc"):
        with pytest.raises(InvalidRequestError):
            v.query_int("limit", default=100)


def test_query_bool():
    with app.test_request_context("/?keep_copy=true"):
        assert v.query_bool("keep_copy") is True


def test_json_body_required_missing():
    with app.test_request_context("/", method="POST"):
        with pytest.raises(InvalidRequestError):
            v.json_body()


def test_json_body_field_required():
    with app.test_request_context("/", method="POST", json={"a": 1}):
        body = v.json_body()
        with pytest.raises(InvalidRequestError):
            v.json_body_field(body, "missing")
        assert v.json_body_field(body, "a") == 1


def test_json_body_non_object_rejected():
    with app.test_request_context("/", method="POST", json=[1, 2, 3]):
        with pytest.raises(InvalidRequestError):
            v.json_body()


def test_query_date_parses_iso_date():
    with app.test_request_context("/?since=2026-06-01"):
        assert v.query_date("since", default=None) == datetime(2026, 6, 1)


def test_query_date_parses_iso_datetime():
    with app.test_request_context("/?since=2026-06-01T12:30:00"):
        assert v.query_date("since", default=None) == datetime(2026, 6, 1, 12, 30, 0)


def test_query_date_absent_returns_none():
    with app.test_request_context("/"):
        assert v.query_date("since", default=None) is None


def test_query_date_absent_returns_default():
    default = datetime(2000, 1, 1)
    with app.test_request_context("/"):
        assert v.query_date("since", default=default) == default


def test_query_date_absent_required_raises():
    with app.test_request_context("/"):
        with pytest.raises(InvalidRequestError):
            v.query_date("since", default=None, required=True)


def test_query_date_invalid_format_raises():
    with app.test_request_context("/?since=not-a-date"):
        with pytest.raises(InvalidRequestError):
            v.query_date("since", default=None)
