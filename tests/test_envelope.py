from flask import Flask
from mail_admin.api.helpers import build_response

app = Flask(__name__)


def test_build_response_success_shape():
    with app.test_request_context("/api/domains", method="GET"):
        resp = build_response(200, data=[{"domain": "x.test"}])
        body = resp.get_json()
    assert resp.status_code == 200
    assert body["http_code"] == 200
    assert body["http_status"] == "OK"
    assert body["method"] == "GET"
    assert body["path"] == "/api/domains"
    assert body["data"] == [{"domain": "x.test"}]
    assert "timestamp" in body


def test_build_response_error_shape():
    with app.test_request_context("/api/domains", method="POST"):
        resp = build_response(409, msg="Domain already exists", detail={"domain": "x.test"})
        body = resp.get_json()
    assert resp.status_code == 409
    assert body["message"] == "Domain already exists"
    assert body["detail"] == {"domain": "x.test"}
