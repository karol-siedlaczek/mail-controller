# Configurable Reverse-Proxy IP Trust Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make reverse-proxy IP trust explicit, configurable, and secure-by-default via a `TRUSTED_PROXY_HOPS` env, replacing the hardcoded always-on `ProxyFix`.

**Architecture:** Add a validated `trusted_proxy_hops` config value. Apply Werkzeug `ProxyFix(x_for=hops)` inside `create_app()` only when `hops > 0` (default 0 = off), and remove the unconditional `ProxyFix` from `wsgi.py`. Simplify `Context.get_remote_ip()` to return `request.remote_addr` (which ProxyFix rewrites to the real client when configured).

**Tech Stack:** Python 3, Flask, Werkzeug `ProxyFix`, pytest. Config via env + `Config.load()`; validation via `Require`.

## Global Constraints

- Spec: `docs/superpowers/specs/2026-06-26-trusted-proxy-hops-design.md` — every task conforms to it.
- Default `TRUSTED_PROXY_HOPS=0` → ProxyFix off → `remote_addr` is the direct TCP peer (spoof-safe).
- Only `x_for` is trusted; do NOT set `x_proto/x_host/x_port/x_prefix`.
- `x_for=N` trusts the N **rightmost** `X-Forwarded-For` entries.
- `TRUSTED_PROXY_HOPS` must validate as an integer `>= 0`; otherwise raise `ValidationError`.
- **Breaking:** proxied deployments must set `TRUSTED_PROXY_HOPS=1` (or correct hop count); default-off fails closed, not open.
- Unit tests: `make test`. Integration: `make itest`. Single test: `cd tests && .venv/bin/python -m pytest <file>::<test> -v`.
- User manages git: only `git add`/`git commit` the files each step names; never push.

---

## File Structure

- `mail_controller/conf/config.py` — add `trusted_proxy_hops: int` field + parse/validate in `load()`. (Task 1)
- `mail_controller/app.py` — apply gated `ProxyFix` in `create_app()`. (Task 2)
- `wsgi.py` — remove the unconditional `ProxyFix` and its import. (Task 2)
- `mail_controller/api/context.py` — simplify `get_remote_ip()`. (Task 3)
- `tests/test_config.py` — config parsing/validation tests. (Task 1)
- `tests/test_app.py` — NEW: `create_app` ProxyFix wiring tests. (Task 2)
- `tests/test_authorization.py` — `get_remote_ip` behavior test. (Task 3)
- `README.md` — document `TRUSTED_PROXY_HOPS`; delete `note_for_you.txt`. (Task 4)

---

## Task 1: Config — `TRUSTED_PROXY_HOPS`

**Files:**
- Modify: `mail_controller/conf/config.py`
- Test: `tests/test_config.py`

**Interfaces:**
- Consumes: `Require.min`, `ValidationError` (already imported in config.py).
- Produces: `Config.trusted_proxy_hops: int` (default `0`), populated by `Config.load()` from env `TRUSTED_PROXY_HOPS`.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_config.py`:

```python
def test_trusted_proxy_hops_default_zero(tmp_path, monkeypatch):
    conf = _write_conf(tmp_path, "identities: []\n")
    _base_env(monkeypatch, conf)
    monkeypatch.delenv("TRUSTED_PROXY_HOPS", raising=False)
    cfg = Config.load()
    assert cfg.trusted_proxy_hops == 0


def test_trusted_proxy_hops_parsed(tmp_path, monkeypatch):
    conf = _write_conf(tmp_path, "identities: []\n")
    _base_env(monkeypatch, conf)
    monkeypatch.setenv("TRUSTED_PROXY_HOPS", "2")
    cfg = Config.load()
    assert cfg.trusted_proxy_hops == 2


def test_trusted_proxy_hops_negative_rejected(tmp_path, monkeypatch):
    conf = _write_conf(tmp_path, "identities: []\n")
    _base_env(monkeypatch, conf)
    monkeypatch.setenv("TRUSTED_PROXY_HOPS", "-1")
    with pytest.raises(ValidationError):
        Config.load()


def test_trusted_proxy_hops_non_integer_rejected(tmp_path, monkeypatch):
    conf = _write_conf(tmp_path, "identities: []\n")
    _base_env(monkeypatch, conf)
    monkeypatch.setenv("TRUSTED_PROXY_HOPS", "abc")
    with pytest.raises(ValidationError):
        Config.load()
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd tests && .venv/bin/python -m pytest test_config.py -k trusted_proxy -v`
Expected: FAIL — `AttributeError: 'Config' object has no attribute 'trusted_proxy_hops'` (and the negative/non-integer cases don't raise yet).

- [ ] **Step 3: Add the dataclass field**

In `mail_controller/conf/config.py`, add the field after `password_scheme`:

```python
    password_scheme: str = "ARGON2ID"
    trusted_proxy_hops: int = 0
    hmac_key: bytes = None
```

- [ ] **Step 4: Parse and validate in `load()`**

In `Config.load()`, after the `password_scheme` block and before `pg_password = cls._resolve_secret("PG_PASSWORD")`, add:

```python
        try:
            trusted_proxy_hops = int(os.getenv("TRUSTED_PROXY_HOPS", "0"))
        except ValueError:
            raise ValidationError(
                f"Invalid 'TRUSTED_PROXY_HOPS={os.getenv('TRUSTED_PROXY_HOPS')}', "
                f"must be an integer >= 0"
            )
        Require.min("TRUSTED_PROXY_HOPS", trusted_proxy_hops, 0)
```

Then add to the `return cls(...)` call, after `password_scheme=password_scheme,`:

```python
            password_scheme=password_scheme,
            trusted_proxy_hops=trusted_proxy_hops,
            hmac_key=hmac_key,
```

- [ ] **Step 5: Run the config tests to verify they pass**

Run: `cd tests && .venv/bin/python -m pytest test_config.py -v`
Expected: PASS (new tests + existing config tests).

- [ ] **Step 6: Commit**

```bash
git add mail_controller/conf/config.py tests/test_config.py
git commit -m "feat(config): add TRUSTED_PROXY_HOPS (validated int, default 0)"
```

---

## Task 2: Apply gated ProxyFix in `create_app`; drop it from `wsgi.py`

**Files:**
- Modify: `mail_controller/app.py`
- Modify: `wsgi.py`
- Test: `tests/test_app.py` (new)

**Interfaces:**
- Consumes: `Config.trusted_proxy_hops` from Task 1.
- Produces: `create_app()` wraps `app.wsgi_app` in `werkzeug.middleware.proxy_fix.ProxyFix(app.wsgi_app, x_for=hops)` iff `hops > 0`.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_app.py`:

```python
import base64
import hmac
import hashlib
import textwrap
import pytest
from werkzeug.middleware.proxy_fix import ProxyFix
from mail_controller.app import create_app

RAW_KEY = b"0123456789abcdef0123456789abcdef"
KEY_B64 = base64.b64encode(RAW_KEY).decode()


def _hmac_hex(token):
    return hmac.new(RAW_KEY, token.encode(), hashlib.sha256).hexdigest()


def _env(monkeypatch, tmp_path, hops=None):
    conf = tmp_path / "config.yaml"
    conf.write_text(textwrap.dedent("""
        identities:
          - id: admin
            allowed_cidrs: ["0.0.0.0/0"]
            permissions: ["*:*"]
    """))
    monkeypatch.setenv("HMAC_KEY_B64", KEY_B64)
    monkeypatch.setenv("PG_HOST", "db")
    monkeypatch.setenv("PG_DBNAME", "maildb")
    monkeypatch.setenv("PG_USER", "mail_admin_rw")
    monkeypatch.setenv("PG_PASSWORD", "x")
    monkeypatch.setenv("CONF_FILE", str(conf))
    monkeypatch.setenv("TOKEN_ADMIN_HMAC", _hmac_hex("adm"))
    if hops is None:
        monkeypatch.delenv("TRUSTED_PROXY_HOPS", raising=False)
    else:
        monkeypatch.setenv("TRUSTED_PROXY_HOPS", str(hops))


def test_no_proxyfix_when_hops_zero(monkeypatch, tmp_path):
    _env(monkeypatch, tmp_path, hops=0)
    app = create_app(database=object())
    assert not isinstance(app.wsgi_app, ProxyFix)


def test_proxyfix_applied_when_hops_positive(monkeypatch, tmp_path):
    _env(monkeypatch, tmp_path, hops=2)
    app = create_app(database=object())
    assert isinstance(app.wsgi_app, ProxyFix)
    assert app.wsgi_app.x_for == 2
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd tests && .venv/bin/python -m pytest test_app.py -v`
Expected: FAIL — `test_proxyfix_applied_when_hops_positive` fails because `create_app` does not wrap `wsgi_app` yet (`app.wsgi_app` is not a `ProxyFix`).

- [ ] **Step 3: Apply ProxyFix in `create_app`**

In `mail_controller/app.py`, add the import near the top (with the other imports):

```python
from werkzeug.middleware.proxy_fix import ProxyFix
```

In `create_app`, add the gating just before `return app`:

```python
    app.register_blueprint(api_blueprint)

    if config.trusted_proxy_hops > 0:
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=config.trusted_proxy_hops)

    return app
```

- [ ] **Step 4: Remove the unconditional ProxyFix from `wsgi.py`**

In `wsgi.py`, delete line 4 (`from werkzeug.middleware.proxy_fix import ProxyFix`) and line 15 (`app.wsgi_app = ProxyFix(...)`). The file becomes:

```python
import os
from mail_controller.app import create_app
from mail_controller.validation.require import Require

bind_ip = os.getenv("GUNICORN_BIND_IP")
if bind_ip:
    Require.ip_address("GUNICORN_BIND_IP", bind_ip)

bind_port = os.getenv("GUNICORN_BIND_PORT")
if bind_port:
    Require.port("GUNICORN_BIND_PORT", int(bind_port))

app = create_app()
```

- [ ] **Step 5: Run the app tests to verify they pass**

Run: `cd tests && .venv/bin/python -m pytest test_app.py -v`
Expected: PASS (both tests).

- [ ] **Step 6: Verify `wsgi.py` still imports cleanly**

Run: `.venv/bin/python -m py_compile wsgi.py` from the repo root via the test venv:
`tests/.venv/bin/python -m py_compile wsgi.py`
Expected: no output, exit 0 (no leftover `ProxyFix` reference).

- [ ] **Step 7: Commit**

```bash
git add mail_controller/app.py wsgi.py tests/test_app.py
git commit -m "feat(app): gate ProxyFix on TRUSTED_PROXY_HOPS; remove hardcoded wsgi ProxyFix"
```

---

## Task 3: Simplify `Context.get_remote_ip()`

**Files:**
- Modify: `mail_controller/api/context.py`
- Test: `tests/test_authorization.py`

**Interfaces:**
- Consumes: nothing new.
- Produces: `Context.get_remote_ip(self) -> str | None` returns `request.remote_addr` only.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_authorization.py`:

```python
def test_get_remote_ip_returns_remote_addr_ignoring_xff(monkeypatch):
    # With ProxyFix off (bare app), a forged X-Forwarded-For must be ignored;
    # the allowlist must see the real TCP peer (REMOTE_ADDR).
    ident = _ident(monkeypatch, "a", ["example.com:read_domain"])
    app = _app_with(ident)
    with app.test_request_context(
        "/", environ_base={"REMOTE_ADDR": "9.9.9.9"},
        headers={"X-Forwarded-For": "1.2.3.4"},
    ):
        assert Context().get_remote_ip() == "9.9.9.9"
```

- [ ] **Step 2: Run the test to verify it passes-by-accident or fails**

Run: `cd tests && .venv/bin/python -m pytest test_authorization.py::test_get_remote_ip_returns_remote_addr_ignoring_xff -v`
Expected: PASS already (current code returns `remote_addr` when set). This test pins the contract before simplifying; proceed to remove the dead branch.

- [ ] **Step 3: Simplify the method**

In `mail_controller/api/context.py`, replace `get_remote_ip`:

```python
    def get_remote_ip(self) -> str | None:
        return request.remote_addr
```

- [ ] **Step 4: Run the test + full auth suite to verify they pass**

Run: `cd tests && .venv/bin/python -m pytest test_authorization.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add mail_controller/api/context.py tests/test_authorization.py
git commit -m "refactor(api): get_remote_ip returns remote_addr; drop spoofable XFF fallback"
```

---

## Task 4: Document `TRUSTED_PROXY_HOPS`; remove the note

**Files:**
- Modify: `README.md`
- Delete: `note_for_you.txt`

**Interfaces:**
- Consumes: behavior from Tasks 1–3.
- Produces: documentation only.

- [ ] **Step 1: Document the env var**

In `README.md`, find the environment-variables section (near the line listing `HMAC_KEY_B64`, `PG_HOST`, `PG_DBNAME`, `PG_USER` as required — around line 141). Add an entry describing the new optional var:

```markdown
- `TRUSTED_PROXY_HOPS` (optional, integer, default `0`) - number of trusted reverse-proxy hops.
  When `0`, `X-Forwarded-For` is ignored and the IP allowlist (`allowed_cidrs`) uses the
  direct TCP peer (spoof-safe). **If mail-controller runs behind a reverse proxy
  (nginx/HAProxy), set this to the number of proxies (usually `1`)** — otherwise the
  allowlist sees the proxy's IP and rejects legitimate clients. `ProxyFix` trusts only the
  `TRUSTED_PROXY_HOPS` rightmost `X-Forwarded-For` entries.
```

- [ ] **Step 2: Delete the note file**

```bash
git rm note_for_you.txt
```

- [ ] **Step 3: Run the full unit suite**

Run: `make test`
Expected: PASS.

- [ ] **Step 4: Run the integration suite**

Run: `make itest`
Expected: PASS (the integration stack uses `allowed_cidrs: ["0.0.0.0/0", "::/0"]`, so it needs no `TRUSTED_PROXY_HOPS`).

- [ ] **Step 5: Commit**

```bash
git add README.md note_for_you.txt
git commit -m "docs: document TRUSTED_PROXY_HOPS; remove ported cert-hub note"
```

---

## Self-Review

**Spec coverage:**
- ProxyFix moved into `create_app`, gated, `x_for` only → Task 2. ✓
- New env `TRUSTED_PROXY_HOPS`, int `>= 0`, default 0, non-integer rejected → Task 1. ✓
- `get_remote_ip` simplified to `request.remote_addr` → Task 3. ✓
- Behavior/security (default off ignores forged XFF) → Task 3 test. ✓
- Breaking-change documentation → Task 4 README. ✓
- Cleanup (delete `note_for_you.txt`) → Task 4. ✓
- Testing (config defaults/validation, app wiring with `.x_for`, get_remote_ip) → Tasks 1–3. ✓

**Placeholder scan:** No TBD/TODO; every code/edit step shows concrete content.

**Type consistency:** `trusted_proxy_hops: int` is defined in Task 1 and consumed identically in Task 2 (`config.trusted_proxy_hops`, compared `> 0`, passed as `x_for=`). `get_remote_ip(self) -> str | None` matches the existing signature. `ProxyFix(...).x_for` is the attribute asserted in Task 2's test (Werkzeug exposes `x_for`).

---

## Execution Handoff

Plan complete and saved to `docs/superpowers/plans/2026-06-26-trusted-proxy-hops.md`. Two execution options:

1. **Subagent-Driven (recommended)** — I dispatch a fresh subagent per task, review between tasks, fast iteration.
2. **Inline Execution** — Execute tasks in this session using executing-plans, batch execution with checkpoints.

Which approach?
