# Domain model: value objects + entities — design

**Date:** 2026-06-23
**Repo:** mail-controller (`mail_controller/`)
**Reference model:** cert-hub's `domain/` (frozen dataclasses with `from_dict` + behaviour, e.g. `Cert`, `Identity`, `Permission`)

## Problem

`mail_controller/domain/` is meant to hold the domain model, but today it mixes two
unlike things:

- `identity.py` / `permission.py` — proper domain types (frozen dataclasses / enum
  with behaviour and `from_dict`/`from_string`).
- `address.py` — three free functions (`normalize_email`, `normalize_domain`,
  `domain_of`) with no type. They also raise `InvalidRequestError` (an API/HTTP-layer
  exception), so a "domain" module reaches up into the web layer.

Everywhere else, table rows flow through the app as untyped `dict`s straight from
`repository.py`. There is no `Domain`, `Mailbox`, `Forwarding`, or `SenderLogin`
type — routes and the repository pass dicts and primitives.

## Goal

Model the persistent domain the way cert-hub models its config domain: rich,
self-validating value objects and entities. The repository and routes speak these
types in both directions (a **full domain layer**), and address parsing/validation
becomes a value object instead of free functions raising HTTP errors.

## Decisions (resolved during brainstorming)

1. **Full domain layer.** Reads return entities; creates accept entities; routes and
   repository speak domain types throughout (not just at the boundary).
2. **One entity per table, server fields optional.** Each entity is a single frozen
   dataclass with `id: int | None = None` and `created_at: datetime | None = None`
   (`None` = not yet persisted). `create_*` takes the entity and returns the persisted
   entity (with `id`). The write-only `password` is **not** a field of `Mailbox`; it is
   passed alongside: `create_user(cur, mailbox, password_hash)`.
3. **Singular file names = one class per file** (matches `cert.py`/`identity.py`/
   `permission.py`). The `Domain` entity lives in `domain/domain.py` (the redundant-looking
   `mail_controller.domain.domain` import path is accepted; it is valid and keeps the
   convention).
4. **Domain raises domain-layer `ValidationError`.** `app.py` already has
   `@app.errorhandler(ValidationError)` returning 400, so value objects raise
   `ValidationError` and the app translates to HTTP 400. Routes need no `try/except` for
   validation. This removes the current layering violation (`address.py` raising
   `InvalidRequestError`).
5. **Response JSON is unchanged.** Each entity's `to_dict()` reproduces exactly today's
   row keys/values so the CLI (`mailctl.py`) and integration tests are unaffected.

## Module layout (`mail_controller/domain/`)

| File | Class(es) | Status |
|------|-----------|--------|
| `address.py` | `DomainName`, `EmailAddress` | rewritten (replaces free functions) |
| `domain.py` | `Domain` | new |
| `mailbox.py` | `Mailbox` | new |
| `forwarding.py` | `Forwarding` | new |
| `sender_login.py` | `SenderLogin` | new |
| `audit.py` | `AuditEntry` | new |
| `identity.py`, `permission.py` | `Identity`, `Permission`, `PermissionAction` | unchanged |

## Value objects (`domain/address.py`)

```python
@dataclass(frozen=True)
class DomainName:
    value: str

    @classmethod
    def parse(cls, raw: str) -> "DomainName":
        # untrusted input: Require.domain(...) -> ValidationError; normalize strip/lower
        ...

@dataclass(frozen=True)
class EmailAddress:
    value: str

    @classmethod
    def parse(cls, raw: str) -> "EmailAddress":
        # untrusted input: Require.email(...) -> ValidationError; normalize strip/lower
        ...

    @property
    def domain(self) -> DomainName:
        # split on "@"; replaces domain_of(); DB-trusted construction (no re-parse)
        ...
```

- `parse()` is the validating/normalizing entry point for **untrusted** input
  (request bodies, path params). It raises domain `ValidationError`.
- Direct construction `DomainName(value)` / `EmailAddress(value)` is for **trusted**
  data already in canonical form (DB rows via `from_row`); it does not re-validate.
- `domain_of`, `normalize_email`, `normalize_domain` are removed. Callers use the
  value objects.

## Entities

All frozen dataclasses. Address-typed fields use the value objects. `from_row(row)`
builds from a psycopg2 `RealDictCursor` row (direct construction, DB-trusted).
`to_dict()` reproduces today's response keys exactly.

```python
@dataclass(frozen=True)
class Domain:
    name: DomainName
    dkim_selector: str = "default"
    active: bool = True
    id: int | None = None
    created_at: datetime | None = None

    @classmethod
    def from_row(cls, row: dict) -> "Domain": ...
    def to_dict(self) -> dict:
        # keys: id, domain, dkim_selector, active, created_at
        ...
```

- `Mailbox`: `email: EmailAddress`, `quota_bytes: int = 0`, `active: bool = True`,
  `domain_id: int | None = None`, `id`, `created_at`. **No `password`.**
  `to_dict()` keys: `id, email, quota_bytes, active, created_at, domain_id`.
- `Forwarding`: `source: EmailAddress`, `destination: EmailAddress`,
  `keep_copy: bool = False`, `active: bool = True`, `id`, `created_at`.
  `to_dict()` keys: `id, source, destination, keep_copy, active, created_at`.
- `SenderLogin`: `login_email: EmailAddress`, `allowed_sender: EmailAddress`,
  `active: bool = True`, `id`, `created_at`.
  `to_dict()` keys: `id, login_email, allowed_sender, active, created_at`.
- `AuditEntry` (read-only): all audit columns, all nullable except `id`/`event_type`:
  `id, event_type, success, login, src_ip, host, sender, recipient, message_id,
  queue_id, score, msg, pid, timestamp`. `login`/`sender`/`recipient` stored as plain
  strings (they may be malformed SASL logins, not always valid addresses). Has a helper
  `login_domain() -> str | None` returning the domain part of `login`, or `None` when
  `login` is absent or has no `@` (used by `filter_readable`).

## Repository boundary (`db/repository.py`)

Column-select constants (`_USER_COLS`, etc.) stay. `from_row` wraps fetched rows.
SQL parameter binding uses `.value` of value objects.

- **Reads → entities**
  - `list_domains(cur, term=None) -> list[Domain]`
  - `get_domain(cur, name: DomainName) -> Domain | None`
  - `list_users(cur, domain=None, term=None) -> list[Mailbox]`
  - `get_user(cur, email: EmailAddress) -> Mailbox | None`
  - `list_forwardings(cur, source=None, domain=None, term=None) -> list[Forwarding]`
  - `list_sender_logins(cur, domain=None, term=None) -> list[SenderLogin]`
  - `list_audit(cur, ...) -> list[AuditEntry]`
- **Creates → take entity, return entity**
  - `create_domain(cur, domain: Domain) -> Domain`
  - `create_user(cur, mailbox: Mailbox, password_hash: str) -> Mailbox`
  - `create_forwarding(cur, fwd: Forwarding) -> Forwarding`
  - `create_sender_login(cur, grant: SenderLogin) -> SenderLogin`
- **Updates → explicit optional fields** (PATCH/COALESCE semantics; an entity cannot
  express "leave unchanged"), return the updated entity:
  - `update_domain(cur, name, dkim_selector, active) -> Domain | None`
  - `update_user(cur, email, quota_bytes, active) -> Mailbox | None`
- **Unchanged shape**: `set_user_password(cur, email, password_hash) -> bool`;
  `delete_*` as today; `delete_user` keeps returning the cascade-count `dict | None`.

## Routes + `context.py`

- Routes parse untrusted input with the value objects (`EmailAddress.parse(...)`,
  `DomainName.parse(...)`), build entities for creates, call the repo, and serialize
  with `entity.to_dict()` (lists: `[e.to_dict() for e in rows]`).
- No `try/except` for validation in routes: `ValidationError` is handled by
  `app.py`'s error handler (400).
- `Context.filter_readable` changes from `(rows: list[dict], domain_key: str)` to
  operate on entities via a domain accessor:
  `filter_readable(rows: list, domain_fn: Callable[[Any], str | None]) -> list`.
  The accessor returns the row's domain string (or `None`). Per-route accessors:
  - domains: `lambda d: d.name.value`
  - users: `lambda m: m.email.domain.value`
  - forwardings: `lambda f: f.source.domain.value`
  - sender-logins: `lambda s: s.allowed_sender.domain.value`
  - audit: `lambda a: a.login_domain()` returning `None` when `login` is absent or has
    no `@` (preserving today's "visible only to a `*`-reader" behaviour via
    `_has_star_read`).
  Serialization to dict happens after filtering.

## Error handling

- Untrusted parse failures → domain `ValidationError` → app error handler → HTTP 400.
- Not-found / conflict / unprocessable continue to use the existing
  `ResourceNotFoundError` / `ConflictError` / `UnprocessableError` raised in routes or
  repository as today.

## Testing (TDD throughout)

- **Value objects** (`tests/test_address.py`, new): `parse` normalizes and validates;
  bad input raises `ValidationError`; `EmailAddress.domain` returns the right
  `DomainName`; direct construction does not validate.
- **Entities** (`tests/test_entities.py`, new): `from_row` → `to_dict` round-trips and
  `to_dict` keys/values match the legacy row shape exactly (guards the JSON contract).
- **Repository** (`tests/test_repository_sql.py`, updated): `FakeCursor` returns rows;
  assert repo wraps them into the right entity type and that creates bind `.value`.
  Existing SQL-shape assertions stay.
- **Routes/context**: update `test_authorization.py` for the new `filter_readable`
  accessor signature.
- **Integration** (`tests/test_integration.py`): must pass **unchanged** — the JSON
  response contract is preserved.

## Staging

This is large but mechanical. The implementation plan will stage it to keep each step
green:

1. Value objects (`address.py`) + their tests; keep thin `domain_of`/`normalize_*`
   shims delegating to the value objects so nothing breaks yet.
2. Entities + `from_row`/`to_dict` + tests.
3. Repository returns/accepts entities (one table at a time).
4. Routes + `context.filter_readable` switch to entities; remove the shims.
5. Delete the old free functions; final full-suite + integration run.

## Out of scope

- Schema changes (tables, columns, FKs stay as-is).
- Changing the HTTP API surface or JSON response shape.
- cert-hub (separate repo; its `domain/` already uses this style).
- ORM adoption — psycopg2 + explicit `from_row`/`to_dict` mapping, no SQLAlchemy.
