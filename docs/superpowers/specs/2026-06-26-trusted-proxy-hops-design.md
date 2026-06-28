# Configurable Reverse-Proxy IP Trust — Design

**Date:** 2026-06-26
**Status:** Approved (design)
**Area:** `mail_controller/app.py`, `wsgi.py`, `mail_controller/conf/config.py`, `mail_controller/api/context.py`
**Origin:** ported from a cert-hub review (`note_for_you.txt`)

## Problem

The IP allowlist (`Identity.allowed_cidrs` → `Identity.is_ip_allowed`, enforced in
`Context.resolve_identity`) authorizes requests by client IP. That client IP comes
from `Context.get_remote_ip()`, which returns `request.remote_addr`.

Two defects:

1. **`wsgi.py` applies `ProxyFix` unconditionally and over-broadly:**
   ```python
   app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1, x_prefix=1)
   ```
   - Always on, always trusting 1 hop. If the service is ever run **not** behind a
     proxy, a client can forge `X-Forwarded-For`; ProxyFix(`x_for=1`) takes the
     forged rightmost entry as `remote_addr` → **allowlist bypass**.
   - Trusts `x_proto/x_host/x_port/x_prefix`, none of which the allowlist needs.
   - Lives in `wsgi.py`, so `create_app()` (what tests drive) has no proxy
     handling — the allowlist's proxy behavior is untested.

2. **`Context.get_remote_ip()` has a spoofable, dead fallback:**
   ```python
   if request.remote_addr:
       return request.remote_addr
   xff = request.headers.get("X-Forwarded-For", "")
   return xff.split(",")[0].strip() if xff else None   # leftmost = client-controlled
   ```
   Under WSGI `remote_addr` is effectively always set, so the XFF branch is dead;
   were it ever reached it would trust the **leftmost** (spoofable) XFF entry.

`X-Forwarded-For` must never be trusted without an explicit, configured proxy
hop count.

## Goal

Make proxy trust **explicit and configurable**, **secure by default**, and
**testable**, matching the cert-hub pattern.

## Design

### 1. ProxyFix moves into `create_app`, gated by config

Remove the `ProxyFix` line (and its import) from `wsgi.py`. In
`mail_controller/app.py`:

```python
from werkzeug.middleware.proxy_fix import ProxyFix
...
def create_app(database: Database | None = None) -> Flask:
    app = Flask(__name__)
    config = Config.load()
    ...
    if config.trusted_proxy_hops > 0:
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=config.trusted_proxy_hops)
    ...
    return app
```

Only `x_for` is set — `x_for=N` trusts the **N rightmost** `X-Forwarded-For`
entries (spoof-safe), which is all the allowlist needs. `x_proto/x_host/x_port/
x_prefix` are intentionally dropped.

Single source of truth, and because tests use `create_app()`, proxy behavior is
now exercised by tests.

### 2. Config — new env `TRUSTED_PROXY_HOPS`

- Add `trusted_proxy_hops: int` to the `Config` dataclass.
- In `Config.load()`: `trusted_proxy_hops = int(os.getenv("TRUSTED_PROXY_HOPS", "0"))`.
- Validate `>= 0`; a negative value raises `ValidationError`. A non-integer value
  raises (the `int(...)` cast fails) — surface it as a `ValidationError` with a
  clear message rather than a raw `ValueError`.
- Default `0` → ProxyFix off → `remote_addr` is the direct TCP peer.

### 3. Simplify `Context.get_remote_ip()`

```python
def get_remote_ip(self) -> str | None:
    return request.remote_addr
```

With ProxyFix configured, `remote_addr` is already the real client; with it off,
the manual XFF parse was both dead and unsafe. Return type stays `str | None`
(`remote_addr` can be `None`, e.g. in synthetic test requests).

### 4. Behavior & Security

| Deployment | `TRUSTED_PROXY_HOPS` | `remote_addr` seen by allowlist |
|------------|----------------------|---------------------------------|
| Direct (no proxy) | `0` (default) | TCP peer; forged XFF ignored — spoof-safe |
| Behind 1 proxy | `1` | real client (rightmost XFF) |
| Chained N proxies | `N` | real client (N rightmost XFF) |
| Behind proxy but left at `0` | `0` | **proxy IP** — allowlist will reject/mis-scope legit traffic (misconfig, fails closed) |

### 5. Breaking Change & Migration

The current build always trusts 1 hop. After this change the default is `0`
(off). **Any deployment behind a reverse proxy must set `TRUSTED_PROXY_HOPS=1`**
(or the correct hop count), otherwise the allowlist sees the proxy IP and
legitimate clients are denied (fails closed, not open).

- Document `TRUSTED_PROXY_HOPS` in `README.md` (env section) with the "set this
  behind a proxy" warning.
- The integration test stack uses `allowed_cidrs: ["0.0.0.0/0", "::/0"]`, so it is
  unaffected (no env needed for tests).

### 6. Cleanup

Delete `note_for_you.txt` once implemented (the note states it can be removed
after the check).

## Testing

- **`tests/test_config.py`**
  - default `trusted_proxy_hops == 0` when env unset.
  - `TRUSTED_PROXY_HOPS=2` → `cfg.trusted_proxy_hops == 2`.
  - `TRUSTED_PROXY_HOPS=-1` → `ValidationError`.
  - `TRUSTED_PROXY_HOPS=abc` → `ValidationError`.
- **`tests/test_app.py`** (new, or extend an existing app test)
  - `hops=0` → `app.wsgi_app` is **not** a `ProxyFix` instance.
  - `hops>0` → `app.wsgi_app` **is** a `ProxyFix` instance with `.x_for == hops`.
- **`tests/test_authorization.py`**
  - `get_remote_ip()` returns `request.remote_addr`.
  - With ProxyFix off (default), a request carrying a forged `X-Forwarded-For`
    yields the peer `REMOTE_ADDR`, not the forged value.

## Out of Scope

- Trusting `x_proto/x_host/x_port/x_prefix` (not needed for the allowlist).
- Per-identity or per-route proxy configuration.
- Any change to the allowlist matching logic itself (`is_ip_allowed`).
