# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Twin repository — keep in sync

`mail-controller` and its sibling `cert-hub` (`~/repo/python/cert-hub`,
GitHub `karol-siedlaczek/cert-hub`) are deliberately built on the same skeleton
and have historically mirrored each other. Before diverging from a pattern
here, check how the other repo does it; when you change a shared convention,
apply the equivalent change in both.

What is shared (structurally identical, names differ):
- **CLI skeleton** — `mailctl.py` ↔ `certhub.py`: the `ExitCode`, `Format`
  (`table`/`json`/`kv`/`value`), `Opt` option factory, `Settings`, `CmdResult`
  (`from_response`/`_parse_response`/`_filter_data`/`_mask_sensitive`/
  `render_and_exit`) and `Client` classes, the `token gen-hmac` command, and
  settings resolution (flags → env vars → `~/.<tool>` file requiring `600`).
- **`render_and_exit()` rendering** — including the `single_row=True` mode that
  renders one record as a vertical two-column `Field`/`Value` table. Here it is
  wired into every single-record command (`domain`/`user`/`forward`
  `add|show|set|rm`, `user passwd`, `sendas grant|revoke`); `list`, `token`,
  `version` and `audit` stay horizontal. This must behave identically to `cert-hub`.
- **Server package layout** — `<pkg>/api/{routes,context,helpers,validators}.py`,
  `<pkg>/domain/`, `<pkg>/domain/permission/`, `<pkg>/exception/`,
  `<pkg>/validation/require.py`, `<pkg>/conf/config.py`, `app.py`, `wsgi.py`,
  `gunicorn.conf.py`.
- **Auth model** — HMAC bearer tokens, per-identity RBAC `<scope>:<action>`
  permissions plus allowed-CIDR checks, resolved in `api/context.py`.
- **Tooling** — `Makefile` targets and `tests/` layout (see below).

## Common commands

Run from the repo root:

- `make test` — unit tests only, excludes integration (`-m "not integration"`, no Docker).
- `make itest` — integration tests via the compose stack (builds the image, `postgres:16`); marked `@pytest.mark.integration` in `test_integration.py`.
- `make lint` — validates `compose.test.yml` and `py_compile`s `mailctl.py`, `wsgi.py`, `gunicorn.conf.py`, `mail_controller/**`.
- `make build` — build the `mail-controller:test` Docker image.
- `make venv` / `make clean` — create / tear down the test virtualenv and stack.

Single test (tests use `pythonpath=..` via `tests/pytest.ini`, so run from `tests/`):

```bash
cd tests && .venv/bin/python -m pytest test_cli_render.py::test_single_row_table_is_vertical -v
```

Note: server-side tests import `mail_controller`, which needs its full deps
(`bcrypt`, `psycopg2-binary`, `argon2-cffi`, …). If those are absent from the
venv, those modules fail to *collect* — that is an environment gap, not a
regression. CLI tests (`test_cli_render.py`) load `mailctl.py` in isolation and
run without them.

Run the API locally (see README for env vars — `HMAC_KEY_B64`, `TOKEN_ADMIN_HMAC`, `PG_*`):

```bash
gunicorn wsgi:app -c gunicorn.conf.py   # then: curl -s http://127.0.0.1:8080/ping
```

## Architecture

Two halves talking over HTTP:

1. **`mailctl.py`** — the Typer + Rich CLI. It is a **thin HTTP client**: each
   command builds request params, calls the API via `Client`, wraps the
   response in `CmdResult`, and prints through `render_and_exit()`. Local-only
   touches are cosmetic: `apply_quota_format`/`parse_quota` translate the
   server's `quota_bytes` to/from human units, and `token gen-hmac` computes a
   token HMAC offline.

2. **`mail_controller/` package** — the Flask app (served by `wsgi.py` +
   gunicorn) doing the real work. Request flow: `mail_controller/api/routes.py`
   endpoints → `Context.authenticate()` (`api/context.py`, token + RBAC + CIDR)
   → domain objects → `mail_controller/db/repository.py` (SQL over the pool in
   `db/pool.py`).

This service is a **companion to the separate `mail-server`** image. Its
**only shared surface with `mail-server` is that server's PostgreSQL schema**
(tables `domains`, `users`, `forwardings`, `sender_login_maps`; read-only
`audit_logs`) plus the `{SCHEME}`-prefixed password format Dovecot reads
(`mail_controller/security/password.py`, bcrypt/argon2). It never touches the
mail daemons, the mail store, or DKIM key files. It requires a login role
holding `mail_admin_rw`.

Because each resource has a dedicated endpoint (`GET /api/domains/{domain}`
etc.), the `show` commands need no client-side match logic — the server returns
one object and a 404 becomes a CRITICAL result directly. (`cert-hub`'s `cert show`
differs: it reuses a list endpoint and resolves the single match client-side.)
