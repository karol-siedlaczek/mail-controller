import pytest
from flask import Flask
from mail_admin.api import validators as v
from mail_admin.exception.api_exceptions import InvalidRequestError

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
