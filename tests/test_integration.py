import requests
import pytest
from conftest import bearer, BASE_URL
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

pytestmark = pytest.mark.integration


def _h(identity):
    return {"Authorization": f"Bearer {bearer(identity)}"}


def test_unauthenticated_rejected(stack):
    assert requests.get(f"{stack}/api/domains").status_code == 401


def test_ping_and_version(stack):
    assert requests.get(f"{stack}/ping").text == "pong"
    v = requests.get(f"{stack}/api/version").json()
    assert v["data"]["name"] == "Mail controller"


def test_full_crud_flow(stack):
    # 1) admin creates a domain
    r = requests.post(f"{stack}/api/domains", json={"domain": "artform.test"}, headers=_h("admin"))
    assert r.status_code == 201, r.text
    # 2) create a user
    r = requests.post(f"{stack}/api/users",
                      json={"email": "alice@artform.test", "password": "Sup3rSecret!"},
                      headers=_h("admin"))
    assert r.status_code == 201, r.text
    assert "password" not in r.json()["data"]  # write-only
    # 3) GET never returns the hash
    r = requests.get(f"{stack}/api/users/alice@artform.test", headers=_h("admin"))
    assert r.status_code == 200
    assert "password" not in r.json()["data"]
    # 4) forwarding
    r = requests.post(f"{stack}/api/forwardings",
                      json={"source": "alice@artform.test", "destination": "ext@elsewhere.test",
                            "keep_copy": True},
                      headers=_h("admin"))
    assert r.status_code == 201, r.text
    fid = r.json()["data"]["id"]
    # 5) send-as grant
    r = requests.post(f"{stack}/api/sender-logins",
                      json={"login_email": "alice@artform.test", "allowed_sender": "boss@artform.test"},
                      headers=_h("admin"))
    assert r.status_code == 201, r.text
    sid = r.json()["data"]["id"]
    # 6) lists reflect the rows
    assert any(d["domain"] == "artform.test" for d in requests.get(f"{stack}/api/domains", headers=_h("admin")).json()["data"])
    # 7) cleanup
    assert requests.delete(f"{stack}/api/forwardings/{fid}", headers=_h("admin")).status_code == 200
    assert requests.delete(f"{stack}/api/sender-logins/{sid}", headers=_h("admin")).status_code == 200
    assert requests.delete(f"{stack}/api/users/alice@artform.test", headers=_h("admin")).status_code == 200


def test_conflict_on_duplicate(stack):
    requests.post(f"{stack}/api/domains", json={"domain": "dup.test"}, headers=_h("admin"))
    r = requests.post(f"{stack}/api/domains", json={"domain": "dup.test"}, headers=_h("admin"))
    assert r.status_code == 409, r.text
    requests.delete(f"{stack}/api/domains/dup.test", headers=_h("admin"))


def test_user_create_missing_domain_422(stack):
    r = requests.post(f"{stack}/api/users",
                      json={"email": "ghost@nodomain.test", "password": "x"},
                      headers=_h("admin"))
    assert r.status_code == 422, r.text


def test_per_domain_authorization(stack):
    # admin sets up two domains
    requests.post(f"{stack}/api/domains", json={"domain": "artform.test"}, headers=_h("admin"))
    requests.post(f"{stack}/api/domains", json={"domain": "other.test"}, headers=_h("admin"))
    # artform identity may write artform.test...
    r = requests.post(f"{stack}/api/users",
                      json={"email": "bob@artform.test", "password": "Sup3rSecret!"},
                      headers=_h("artform"))
    assert r.status_code == 201, r.text
    # ...but NOT other.test
    r = requests.post(f"{stack}/api/users",
                      json={"email": "eve@other.test", "password": "x"},
                      headers=_h("artform"))
    assert r.status_code == 403, r.text
    # reader cannot write at all
    r = requests.post(f"{stack}/api/users",
                      json={"email": "carol@artform.test", "password": "x"},
                      headers=_h("reader"))
    assert r.status_code == 403, r.text
    # reader CAN read artform.test
    assert requests.get(f"{stack}/api/users?domain=artform.test", headers=_h("reader")).status_code == 200
    requests.delete(f"{stack}/api/users/bob@artform.test", headers=_h("admin"))


def test_list_filtered_to_readable(stack):
    # reader sees only artform.test in the domain list
    requests.post(f"{stack}/api/domains", json={"domain": "artform.test"}, headers=_h("admin"))
    requests.post(f"{stack}/api/domains", json={"domain": "other.test"}, headers=_h("admin"))
    domains = {d["domain"] for d in requests.get(f"{stack}/api/domains", headers=_h("reader")).json()["data"]}
    assert "artform.test" in domains
    assert "other.test" not in domains


def test_stored_hash_is_dovecot_argon2id(stack):
    """The stored password must be a Dovecot-readable {ARGON2ID} hash that
    verifies against the plaintext — the contract mail-server's Dovecot relies on."""
    requests.post(f"{stack}/api/domains", json={"domain": "artform.test"}, headers=_h("admin"))
    requests.post(f"{stack}/api/users",
                  json={"email": "hashcheck@artform.test", "password": "Sup3rSecret!"},
                  headers=_h("admin"))
    # Read the raw stored hash directly from Postgres (the API never returns it).
    import psycopg2
    conn = psycopg2.connect(host="127.0.0.1", port=15432, dbname="maildb",
                            user="maildba", password="testpw")
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT password FROM users WHERE email=%s", ("hashcheck@artform.test",))
            stored = cur.fetchone()[0]
    finally:
        conn.close()
    assert stored.startswith("{ARGON2ID}$argon2id$")
    ph = PasswordHasher()
    assert ph.verify(stored[len("{ARGON2ID}"):], "Sup3rSecret!")
    with pytest.raises(VerifyMismatchError):
        ph.verify(stored[len("{ARGON2ID}"):], "wrong")
    requests.delete(f"{stack}/api/users/hashcheck@artform.test", headers=_h("admin"))


def test_delete_user_cascades_all_references(stack):
    dom = "cascade.test"
    requests.post(f"{stack}/api/domains", json={"domain": dom}, headers=_h("admin"))
    requests.post(f"{stack}/api/users",
                  json={"email": f"alice@{dom}", "password": "Sup3rSecret!"},
                  headers=_h("admin"))

    # alice as forwarding SOURCE
    requests.post(f"{stack}/api/forwardings",
                  json={"source": f"alice@{dom}", "destination": "ext@elsewhere.test"},
                  headers=_h("admin"))
    # alice as forwarding DESTINATION (a list alias points at her)
    requests.post(f"{stack}/api/forwardings",
                  json={"source": f"list@{dom}", "destination": f"alice@{dom}"},
                  headers=_h("admin"))
    # alice as send-as LOGIN_EMAIL
    requests.post(f"{stack}/api/sender-logins",
                  json={"login_email": f"alice@{dom}", "allowed_sender": f"boss@{dom}"},
                  headers=_h("admin"))
    # alice as send-as ALLOWED_SENDER
    requests.post(f"{stack}/api/sender-logins",
                  json={"login_email": f"carol@{dom}", "allowed_sender": f"alice@{dom}"},
                  headers=_h("admin"))

    r = requests.delete(f"{stack}/api/users/alice@{dom}", headers=_h("admin"))
    assert r.status_code == 200, r.text
    data = r.json()["data"]
    assert data["forwardings_deleted"] == 2
    assert data["sender_logins_deleted"] == 2

    # nothing referencing alice remains
    fwds = requests.get(f"{stack}/api/forwardings", headers=_h("admin")).json()["data"]
    assert not [f for f in fwds
                if f"alice@{dom}" in (f["source"], f["destination"])]
    slms = requests.get(f"{stack}/api/sender-logins", headers=_h("admin")).json()["data"]
    assert not [s for s in slms
                if f"alice@{dom}" in (s["login_email"], s["allowed_sender"])]

    # deleting a non-existent user is a 404, not a 200
    assert requests.delete(f"{stack}/api/users/ghost@{dom}",
                           headers=_h("admin")).status_code == 404

    # cleanup leftover rows/domain
    requests.delete(f"{stack}/api/users/carol@{dom}", headers=_h("admin"))
    for f in requests.get(f"{stack}/api/forwardings", headers=_h("admin")).json()["data"]:
        if dom in f["source"]:
            requests.delete(f"{stack}/api/forwardings/{f['id']}", headers=_h("admin"))
    requests.delete(f"{stack}/api/domains/{dom}", headers=_h("admin"))
