# User-delete Cascade Cleanup Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** When a mailbox is deleted, atomically remove every forwarding and send-as grant that references that address, and report the counts back to the caller.

**Architecture:** Extend `repo.delete_user` to issue two extra parameterized DELETEs (forwardings, sender_login_maps) inside the route's existing single transaction, after confirming the user existed. The route returns the cascade counts; the CLI surfaces them with no code change.

**Tech Stack:** Python 3.12, psycopg2, Flask (routes), Typer (CLI), pytest (unit + integration against a real Postgres stack via `tests/compose.test.yml`).

## Global Constraints

- All SQL fully parameterized (`%(name)s`); never f-string-interpolate user data — copied verbatim from `repository.py` module docstring.
- Reads/writes go through the `mail_admin_rw` role; no schema changes (source/destination/login_email/allowed_sender stay `text`, no FK, no DB trigger).
- Authorization for user-delete is unchanged: `ctx.require(domain_of(email), WRITE)`. The cascade is privileged — it removes referencing rows regardless of their domain.
- Follow existing module patterns (FakeCursor unit tests in `tests/test_repository_sql.py`; real-stack tests in `tests/test_integration.py` gated by `pytestmark = pytest.mark.integration`).

---

## File Structure

- Modify: `mail_controller/db/repository.py` — `delete_user` gains the cascade; return type `bool` → `dict | None`.
- Modify: `mail_controller/api/routes.py` — `delete_user` route handles the new return shape and merges counts into the response.
- Modify: `tests/test_repository_sql.py` — extend `FakeCursor` for per-execute rowcounts; add cascade unit tests.
- Modify: `tests/test_integration.py` — add a real-stack cascade test.
- No change: `mailctl.py` (generic renderer already prints all response fields).

---

### Task 1: Cascade cleanup in `repo.delete_user` (unit-tested with FakeCursor)

**Files:**
- Modify: `mail_controller/db/repository.py:111-113` (`delete_user`)
- Test: `tests/test_repository_sql.py` (extend `FakeCursor`, add two tests)

**Interfaces:**
- Consumes: a DB cursor `cur` with `.execute(sql, params)` and `.rowcount`.
- Produces: `delete_user(cur, email) -> dict | None`. Returns `None` when no user row matched (no cascade performed); otherwise returns `{"forwardings_deleted": int, "sender_logins_deleted": int}`.

- [ ] **Step 1: Extend `FakeCursor` to script per-execute rowcounts**

In `tests/test_repository_sql.py`, replace the `FakeCursor.__init__` and `execute` with:

```python
    def __init__(self, rows=None, rowcount=1, rowcounts=None):
        self.rows = rows or []
        self.rowcount = rowcount
        self._rowcounts = list(rowcounts) if rowcounts is not None else None
        self.executed = []  # list of (sql, params)

    def execute(self, sql, params=None):
        self.executed.append((sql, params))
        if self._rowcounts:
            self.rowcount = self._rowcounts.pop(0)
```

(Existing tests pass `rowcount` or nothing, so default behavior is unchanged.)

- [ ] **Step 2: Write the failing tests**

Add to `tests/test_repository_sql.py`:

```python
def test_delete_user_cascades_forwardings_and_sender_logins():
    # rowcounts: users delete=1, forwardings delete=3, sender_login_maps delete=2
    cur = FakeCursor(rowcounts=[1, 3, 2])
    result = repo.delete_user(cur, "alice@example.com")

    sql = cur.all_sql.lower()
    assert "delete from forwardings" in sql
    assert "source" in sql and "destination" in sql
    assert "delete from sender_login_maps" in sql
    assert "login_email" in sql and "allowed_sender" in sql
    # every execute is parameterized by the email, not interpolated
    assert all(p == {"e": "alice@example.com"} for _, p in cur.executed)
    assert result == {"forwardings_deleted": 3, "sender_logins_deleted": 2}


def test_delete_user_absent_returns_none_and_skips_cascade():
    cur = FakeCursor(rowcounts=[0])  # no user row matched
    result = repo.delete_user(cur, "ghost@example.com")

    assert result is None
    assert len(cur.executed) == 1  # only the users DELETE ran; no cascade
    assert "forwardings" not in cur.all_sql.lower()
    assert "sender_login_maps" not in cur.all_sql.lower()
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cd /home/karol-siedlaczek/repo/python/mail-controller && python -m pytest tests/test_repository_sql.py -k delete_user -v`
Expected: FAIL — current `delete_user` returns a bool and issues only one execute (assertions on cascade SQL / return dict fail).

- [ ] **Step 4: Implement the cascade**

Replace `delete_user` in `mail_controller/db/repository.py` (currently lines 111-113):

```python
def delete_user(cur, email) -> dict | None:
    cur.execute("DELETE FROM users WHERE email = %(e)s", {"e": email})
    if cur.rowcount == 0:
        return None  # nothing existed; perform no cascade
    cur.execute(
        "DELETE FROM forwardings WHERE source = %(e)s OR destination = %(e)s",
        {"e": email},
    )
    forwardings_deleted = cur.rowcount
    cur.execute(
        "DELETE FROM sender_login_maps "
        "WHERE login_email = %(e)s OR allowed_sender = %(e)s",
        {"e": email},
    )
    sender_logins_deleted = cur.rowcount
    return {
        "forwardings_deleted": forwardings_deleted,
        "sender_logins_deleted": sender_logins_deleted,
    }
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd /home/karol-siedlaczek/repo/python/mail-controller && python -m pytest tests/test_repository_sql.py -v`
Expected: PASS (the two new tests plus all pre-existing ones).

- [ ] **Step 6: Commit**

```bash
cd /home/karol-siedlaczek/repo/python/mail-controller
git add mail_controller/db/repository.py tests/test_repository_sql.py
git commit -m "feat(repo): cascade-delete forwardings & send-as grants on user delete"
```

---

### Task 2: Route returns cascade counts

**Files:**
- Modify: `mail_controller/api/routes.py:204-214` (`delete_user` route)

**Interfaces:**
- Consumes: `repo.delete_user(cur, email) -> dict | None` (Task 1).
- Produces: `DELETE /api/users/<email>` → 200 with `data = {"email": <email>, "deleted": True, "forwardings_deleted": int, "sender_logins_deleted": int}`; 404 (`ResourceNotFoundError`) when the user did not exist.

- [ ] **Step 1: Update the route**

Replace the body of `delete_user` in `mail_controller/api/routes.py` (lines 204-214) with:

```python
@api.route("/api/users/<email>", methods=["DELETE"])
def delete_user(email: str) -> Response:
    email = normalize_email(email)
    ctx = Context.authenticate()
    ctx.require(domain_of(email), WRITE)
    db = Database.get_from_global_context()
    with db.transaction() as cur:
        result = repo.delete_user(cur, email)
    if result is None:
        raise ResourceNotFoundError(msg="User not found", detail={"email": email})
    return build_response(200, data={"email": email, "deleted": True, **result})
```

- [ ] **Step 2: Sanity-check imports compile**

Run: `cd /home/karol-siedlaczek/repo/python/mail-controller && python -c "import mail_controller.api.routes"`
Expected: no output, exit 0 (no syntax/import error).

- [ ] **Step 3: Commit**

```bash
cd /home/karol-siedlaczek/repo/python/mail-controller
git add mail_controller/api/routes.py
git commit -m "feat(api): report cascade-deleted counts in user-delete response"
```

---

### Task 3: Integration test — cascade against the real stack

**Files:**
- Modify: `tests/test_integration.py` (add one test using the existing `stack` fixture and `_h` helper)

**Interfaces:**
- Consumes: live endpoints `POST /api/domains`, `POST /api/users`, `POST /api/forwardings`, `POST /api/sender-logins`, `DELETE /api/users/<email>`, `GET /api/forwardings`, `GET /api/sender-logins`.

- [ ] **Step 1: Write the failing integration test**

Add to `tests/test_integration.py`:

```python
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
```

- [ ] **Step 2: Run the integration test**

Run: `cd /home/karol-siedlaczek/repo/python/mail-controller && python -m pytest tests/test_integration.py::test_delete_user_cascades_all_references -v`
Expected: PASS. (If the suite needs the compose stack up, follow the project's existing integration-run convention — see `tests/compose.test.yml` / `Makefile`. With Task 1 + Task 2 applied, the assertions hold; without them the counts/404 assertions fail.)

- [ ] **Step 3: Commit**

```bash
cd /home/karol-siedlaczek/repo/python/mail-controller
git add tests/test_integration.py
git commit -m "test(integration): verify user-delete cascade across all four references"
```

---

## Self-Review

**Spec coverage:**
- Decision 1 (app-level, not trigger) → Task 1 implements it in `repo.delete_user`; no schema change. ✓
- Decision 2 (all four references) → Task 1 deletes on `forwardings.source|destination` and `sender_login_maps.login_email|allowed_sender`; Task 3 exercises all four. ✓
- Decision 3 (cascade privileged, auth unchanged) → Task 2 keeps `ctx.require(domain_of(email), WRITE)` and adds no per-row auth. ✓
- Counts in response → Task 2 merges `**result`; Task 3 asserts both counts. ✓
- CLI surfaces counts with no change → noted in File Structure (no task needed; `_filter_data` returns full dict when no `--columns`). ✓
- 404/no-op when user absent → Task 1 returns `None`, Task 2 raises `ResourceNotFoundError`, Task 3 asserts 404. ✓

**Placeholder scan:** No TBD/TODO; every code step shows full code. ✓

**Type consistency:** `delete_user` returns `dict | None` in Task 1; Task 2 checks `result is None` and spreads `**result`; keys `forwardings_deleted` / `sender_logins_deleted` match across repository, route, and both test layers. ✓
