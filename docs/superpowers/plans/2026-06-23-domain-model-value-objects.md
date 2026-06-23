# Domain Model: Value Objects + Entities Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace dict-based table data and the free-function `address.py` with a full domain layer of self-validating value objects (`DomainName`, `EmailAddress`) and entities (`Domain`, `Mailbox`, `Forwarding`, `SenderLogin`, `AuditEntry`) that the repository and routes speak in both directions.

**Architecture:** Add value objects and entities alongside the existing code first (zero behaviour change), migrate the repository to return/accept entities one table at a time, switch routes + `Context.filter_readable` to entities, then delete the old free functions. The HTTP JSON response shape is preserved throughout by making each entity's `to_dict()` reproduce today's row keys and Python value types (`jsonify` then renders them identically).

**Tech Stack:** Python 3.12, frozen `@dataclass`, psycopg2 (`RealDictCursor` rows), Flask, pytest. No ORM.

## Global Constraints

- Value objects/entities are `@dataclass(frozen=True)`; address-typed fields use the value objects (copied from the spec).
- `parse()` validates+normalizes untrusted input and raises domain `ValidationError`; direct construction (`DomainName(value)`) is for DB-trusted data and does not validate.
- `app.py` already has `@app.errorhandler(ValidationError)` → HTTP 400; routes do NOT wrap validation in try/except.
- `to_dict()` MUST reproduce today's response keys AND Python value types (e.g. `created_at` stays a `datetime`, not isoformat) — the JSON contract is fixed.
- All SQL stays fully parameterized; bind value objects via `.value`. No schema changes.
- Tests run via the project venv: `make test` (unit, `-m "not integration"`) and `make itest` (compose stack). Per-test runs use `tests/.venv/bin/python -m pytest`.
- Run all `pytest` commands from the repo root unless noted; `tests/pytest.ini` sets `pythonpath = ..`.

---

## File Structure

- Create: `mail_controller/domain/domain.py` (`Domain`), `mailbox.py` (`Mailbox`), `forwarding.py` (`Forwarding`), `sender_login.py` (`SenderLogin`), `audit.py` (`AuditEntry`).
- Modify: `mail_controller/domain/address.py` (add `DomainName`, `EmailAddress`; remove free functions in the final task).
- Modify: `mail_controller/db/repository.py` (reads return entities; creates take entities).
- Modify: `mail_controller/api/context.py` (`filter_readable` accessor signature).
- Modify: `mail_controller/api/routes.py` (parse with value objects, build entities, serialize `to_dict()`).
- Create tests: `tests/test_address.py`, `tests/test_entities.py`; Modify: `tests/test_repository_sql.py`, `tests/test_authorization.py`.

---

## Stage 1 — Value objects

### Task 1: `DomainName` and `EmailAddress` value objects

**Files:**
- Modify: `mail_controller/domain/address.py` (add classes; leave existing functions intact)
- Test: `tests/test_address.py` (create)

**Interfaces:**
- Produces: `DomainName(value: str)`, `DomainName.parse(raw: str) -> DomainName`; `EmailAddress(value: str)`, `EmailAddress.parse(raw: str) -> EmailAddress`, `EmailAddress.domain -> DomainName`. `parse` raises `mail_controller.exception.validator_exceptions.ValidationError` on invalid input.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_address.py`:

```python
import pytest
from mail_controller.domain.address import DomainName, EmailAddress
from mail_controller.exception.validator_exceptions import ValidationError


def test_domainname_parse_normalizes():
    assert DomainName.parse("  ExAmple.COM ").value == "example.com"


def test_domainname_parse_rejects_invalid():
    with pytest.raises(ValidationError):
        DomainName.parse("not a domain")


def test_emailaddress_parse_normalizes():
    assert EmailAddress.parse("  Alice@Example.COM ").value == "alice@example.com"


def test_emailaddress_parse_rejects_invalid():
    with pytest.raises(ValidationError):
        EmailAddress.parse("nope")


def test_emailaddress_domain_property():
    assert EmailAddress.parse("alice@example.com").domain == DomainName("example.com")


def test_direct_construction_does_not_validate():
    # trusted construction path: no exception even for non-canonical input
    assert DomainName("anything").value == "anything"
    assert EmailAddress("x@y").value == "x@y"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `tests/.venv/bin/python -m pytest tests/test_address.py -q`
Expected: FAIL — `ImportError: cannot import name 'DomainName'`.

- [ ] **Step 3: Add the value objects**

In `mail_controller/domain/address.py`, add at the top (keep the existing
`normalize_email`/`normalize_domain`/`domain_of` functions untouched below):

```python
from dataclasses import dataclass
from mail_controller.validation.require import Require
from mail_controller.exception.validator_exceptions import ValidationError
from mail_controller.exception.api_exceptions import InvalidRequestError


@dataclass(frozen=True)
class DomainName:
    value: str

    @classmethod
    def parse(cls, raw: str) -> "DomainName":
        Require.domain("domain", raw)
        return cls(raw.strip().lower())


@dataclass(frozen=True)
class EmailAddress:
    value: str

    @classmethod
    def parse(cls, raw: str) -> "EmailAddress":
        Require.email("email", raw)
        return cls(raw.strip().lower())

    @property
    def domain(self) -> DomainName:
        if "@" not in self.value:
            raise ValidationError(f"Address '{self.value}' is missing a domain part")
        return DomainName(self.value.rsplit("@", 1)[1])
```

(The existing `from ... import` lines at the top of the file may already include
`Require`/`ValidationError`/`InvalidRequestError`; do not duplicate imports.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `tests/.venv/bin/python -m pytest tests/test_address.py -q`
Expected: PASS (6 passed).

- [ ] **Step 5: Commit**

```bash
git add mail_controller/domain/address.py tests/test_address.py
git commit -m "feat(domain): add DomainName and EmailAddress value objects"
```

---

## Stage 2 — Entities

Each entity is a frozen dataclass with `from_row` and `to_dict`. The round-trip
test (`from_row(row).to_dict() == row`) locks the JSON contract.

### Task 2: `Domain` entity

**Files:**
- Create: `mail_controller/domain/domain.py`
- Test: `tests/test_entities.py` (create)

**Interfaces:**
- Consumes: `DomainName` (Task 1).
- Produces: `Domain(name: DomainName, dkim_selector: str = "default", active: bool = True, id: int | None = None, created_at: datetime | None = None)`; `Domain.from_row(row: dict) -> Domain`; `Domain.to_dict() -> dict` with keys `id, domain, dkim_selector, active, created_at`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_entities.py`:

```python
from datetime import datetime, timezone
from mail_controller.domain.domain import Domain
from mail_controller.domain.address import DomainName

_TS = datetime(2026, 1, 1, tzinfo=timezone.utc)


def test_domain_from_row_to_dict_roundtrip():
    row = {"id": 1, "domain": "example.com", "dkim_selector": "default",
           "active": True, "created_at": _TS}
    d = Domain.from_row(row)
    assert d.name == DomainName("example.com")
    assert d.to_dict() == row  # exact key/value contract
```

- [ ] **Step 2: Run test to verify it fails**

Run: `tests/.venv/bin/python -m pytest tests/test_entities.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'mail_controller.domain.domain'`.

- [ ] **Step 3: Create the entity**

Create `mail_controller/domain/domain.py`:

```python
from dataclasses import dataclass
from datetime import datetime
from mail_controller.domain.address import DomainName


@dataclass(frozen=True)
class Domain:
    name: DomainName
    dkim_selector: str = "default"
    active: bool = True
    id: int | None = None
    created_at: datetime | None = None

    @classmethod
    def from_row(cls, row: dict) -> "Domain":
        return cls(
            name=DomainName(row["domain"]),
            dkim_selector=row["dkim_selector"],
            active=row["active"],
            id=row["id"],
            created_at=row["created_at"],
        )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "domain": self.name.value,
            "dkim_selector": self.dkim_selector,
            "active": self.active,
            "created_at": self.created_at,
        }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `tests/.venv/bin/python -m pytest tests/test_entities.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add mail_controller/domain/domain.py tests/test_entities.py
git commit -m "feat(domain): add Domain entity"
```

### Task 3: `Mailbox` entity

**Files:**
- Create: `mail_controller/domain/mailbox.py`
- Test: `tests/test_entities.py` (append)

**Interfaces:**
- Produces: `Mailbox(email: EmailAddress, quota_bytes: int = 0, active: bool = True, domain_id: int | None = None, id: int | None = None, created_at: datetime | None = None)`; `from_row`; `to_dict` keys `id, email, quota_bytes, active, created_at, domain_id`. No `password` field.

- [ ] **Step 1: Write the failing test** (append to `tests/test_entities.py`)

```python
from mail_controller.domain.mailbox import Mailbox
from mail_controller.domain.address import EmailAddress


def test_mailbox_from_row_to_dict_roundtrip():
    row = {"id": 5, "email": "alice@example.com", "quota_bytes": 1024,
           "active": True, "created_at": _TS, "domain_id": 1}
    m = Mailbox.from_row(row)
    assert m.email == EmailAddress("alice@example.com")
    assert m.to_dict() == row
```

- [ ] **Step 2: Run test to verify it fails**

Run: `tests/.venv/bin/python -m pytest tests/test_entities.py::test_mailbox_from_row_to_dict_roundtrip -q`
Expected: FAIL — module missing.

- [ ] **Step 3: Create the entity**

Create `mail_controller/domain/mailbox.py`:

```python
from dataclasses import dataclass
from datetime import datetime
from mail_controller.domain.address import EmailAddress


@dataclass(frozen=True)
class Mailbox:
    email: EmailAddress
    quota_bytes: int = 0
    active: bool = True
    domain_id: int | None = None
    id: int | None = None
    created_at: datetime | None = None

    @classmethod
    def from_row(cls, row: dict) -> "Mailbox":
        return cls(
            email=EmailAddress(row["email"]),
            quota_bytes=row["quota_bytes"],
            active=row["active"],
            domain_id=row["domain_id"],
            id=row["id"],
            created_at=row["created_at"],
        )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "email": self.email.value,
            "quota_bytes": self.quota_bytes,
            "active": self.active,
            "created_at": self.created_at,
            "domain_id": self.domain_id,
        }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `tests/.venv/bin/python -m pytest tests/test_entities.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add mail_controller/domain/mailbox.py tests/test_entities.py
git commit -m "feat(domain): add Mailbox entity"
```

### Task 4: `Forwarding` entity

**Files:**
- Create: `mail_controller/domain/forwarding.py`
- Test: `tests/test_entities.py` (append)

**Interfaces:**
- Produces: `Forwarding(source: EmailAddress, destination: EmailAddress, keep_copy: bool = False, active: bool = True, id: int | None = None, created_at: datetime | None = None)`; `from_row`; `to_dict` keys `id, source, destination, keep_copy, active, created_at`.

- [ ] **Step 1: Write the failing test** (append to `tests/test_entities.py`)

```python
from mail_controller.domain.forwarding import Forwarding


def test_forwarding_from_row_to_dict_roundtrip():
    row = {"id": 3, "source": "a@example.com", "destination": "b@elsewhere.test",
           "keep_copy": False, "active": True, "created_at": _TS}
    f = Forwarding.from_row(row)
    assert f.source == EmailAddress("a@example.com")
    assert f.to_dict() == row
```

- [ ] **Step 2: Run test to verify it fails**

Run: `tests/.venv/bin/python -m pytest tests/test_entities.py::test_forwarding_from_row_to_dict_roundtrip -q`
Expected: FAIL — module missing.

- [ ] **Step 3: Create the entity**

Create `mail_controller/domain/forwarding.py`:

```python
from dataclasses import dataclass
from datetime import datetime
from mail_controller.domain.address import EmailAddress


@dataclass(frozen=True)
class Forwarding:
    source: EmailAddress
    destination: EmailAddress
    keep_copy: bool = False
    active: bool = True
    id: int | None = None
    created_at: datetime | None = None

    @classmethod
    def from_row(cls, row: dict) -> "Forwarding":
        return cls(
            source=EmailAddress(row["source"]),
            destination=EmailAddress(row["destination"]),
            keep_copy=row["keep_copy"],
            active=row["active"],
            id=row["id"],
            created_at=row["created_at"],
        )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "source": self.source.value,
            "destination": self.destination.value,
            "keep_copy": self.keep_copy,
            "active": self.active,
            "created_at": self.created_at,
        }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `tests/.venv/bin/python -m pytest tests/test_entities.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add mail_controller/domain/forwarding.py tests/test_entities.py
git commit -m "feat(domain): add Forwarding entity"
```

### Task 5: `SenderLogin` entity

**Files:**
- Create: `mail_controller/domain/sender_login.py`
- Test: `tests/test_entities.py` (append)

**Interfaces:**
- Produces: `SenderLogin(login_email: EmailAddress, allowed_sender: EmailAddress, active: bool = True, id: int | None = None, created_at: datetime | None = None)`; `from_row`; `to_dict` keys `id, login_email, allowed_sender, active, created_at`.

- [ ] **Step 1: Write the failing test** (append to `tests/test_entities.py`)

```python
from mail_controller.domain.sender_login import SenderLogin


def test_sender_login_from_row_to_dict_roundtrip():
    row = {"id": 9, "login_email": "ops@example.com", "allowed_sender": "boss@example.com",
           "active": True, "created_at": _TS}
    s = SenderLogin.from_row(row)
    assert s.allowed_sender == EmailAddress("boss@example.com")
    assert s.to_dict() == row
```

- [ ] **Step 2: Run test to verify it fails**

Run: `tests/.venv/bin/python -m pytest tests/test_entities.py::test_sender_login_from_row_to_dict_roundtrip -q`
Expected: FAIL — module missing.

- [ ] **Step 3: Create the entity**

Create `mail_controller/domain/sender_login.py`:

```python
from dataclasses import dataclass
from datetime import datetime
from mail_controller.domain.address import EmailAddress


@dataclass(frozen=True)
class SenderLogin:
    login_email: EmailAddress
    allowed_sender: EmailAddress
    active: bool = True
    id: int | None = None
    created_at: datetime | None = None

    @classmethod
    def from_row(cls, row: dict) -> "SenderLogin":
        return cls(
            login_email=EmailAddress(row["login_email"]),
            allowed_sender=EmailAddress(row["allowed_sender"]),
            active=row["active"],
            id=row["id"],
            created_at=row["created_at"],
        )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "login_email": self.login_email.value,
            "allowed_sender": self.allowed_sender.value,
            "active": self.active,
            "created_at": self.created_at,
        }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `tests/.venv/bin/python -m pytest tests/test_entities.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add mail_controller/domain/sender_login.py tests/test_entities.py
git commit -m "feat(domain): add SenderLogin entity"
```

### Task 6: `AuditEntry` entity

**Files:**
- Create: `mail_controller/domain/audit.py`
- Test: `tests/test_entities.py` (append)

**Interfaces:**
- Produces: `AuditEntry` with fields `id, event_type, success, login, src_ip, host, sender, recipient, message_id, queue_id, score, msg, pid, timestamp` (all but `id`/`event_type` default `None`); `from_row`; `to_dict` reproducing those keys; `login_domain() -> str | None` (domain of `login`, or `None` when absent / no `@`).

- [ ] **Step 1: Write the failing test** (append to `tests/test_entities.py`)

```python
from mail_controller.domain.audit import AuditEntry


def test_audit_entry_roundtrip_and_login_domain():
    row = {"id": 1, "event_type": "auth", "success": True, "login": "alice@example.com",
           "src_ip": "10.0.0.1", "host": "mx1", "sender": None, "recipient": None,
           "message_id": None, "queue_id": None, "score": None, "msg": "ok",
           "pid": 42, "timestamp": _TS}
    a = AuditEntry.from_row(row)
    assert a.to_dict() == row
    assert a.login_domain() == "example.com"


def test_audit_entry_login_domain_none_when_no_at():
    a = AuditEntry(id=2, event_type="delivery", login="not-an-email")
    assert a.login_domain() is None
    assert AuditEntry(id=3, event_type="delivery", login=None).login_domain() is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `tests/.venv/bin/python -m pytest tests/test_entities.py -k audit -q`
Expected: FAIL — module missing.

- [ ] **Step 3: Create the entity**

Create `mail_controller/domain/audit.py`:

```python
from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class AuditEntry:
    id: int
    event_type: str
    success: bool | None = None
    login: str | None = None
    src_ip: str | None = None
    host: str | None = None
    sender: str | None = None
    recipient: str | None = None
    message_id: str | None = None
    queue_id: str | None = None
    score: float | None = None
    msg: str | None = None
    pid: int | None = None
    timestamp: datetime | None = None

    @classmethod
    def from_row(cls, row: dict) -> "AuditEntry":
        return cls(**{f: row.get(f) for f in (
            "id", "event_type", "success", "login", "src_ip", "host", "sender",
            "recipient", "message_id", "queue_id", "score", "msg", "pid", "timestamp",
        )})

    def to_dict(self) -> dict:
        return {f: getattr(self, f) for f in (
            "id", "event_type", "success", "login", "src_ip", "host", "sender",
            "recipient", "message_id", "queue_id", "score", "msg", "pid", "timestamp",
        )}

    def login_domain(self) -> str | None:
        if not self.login or "@" not in self.login:
            return None
        return self.login.rsplit("@", 1)[1].lower()
```

- [ ] **Step 4: Run test to verify it passes**

Run: `tests/.venv/bin/python -m pytest tests/test_entities.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add mail_controller/domain/audit.py tests/test_entities.py
git commit -m "feat(domain): add AuditEntry entity"
```

---

## Stage 3 — Repository returns/accepts entities

Each task changes one table's repo functions to return entities (reads) and accept
entities (creates), then updates the corresponding `test_repository_sql.py` tests.
After each task the route layer still calls the repo but now receives entities — so
routes are updated in Stage 4. To keep the suite green between stages, **the route
changes for each table are done in the same commit boundary as Stage 4**; Stage 3
tasks are verified by their repository unit tests (which use `FakeCursor`).

### Task 7: domains repository → entities

**Files:**
- Modify: `mail_controller/db/repository.py` (`list_domains`, `get_domain`, `create_domain`, `update_domain`)
- Test: `tests/test_repository_sql.py`

**Interfaces:**
- Consumes: `Domain` (Task 2), `DomainName` (Task 1).
- Produces: `list_domains(cur, term=None) -> list[Domain]`; `get_domain(cur, name: DomainName) -> Domain | None`; `create_domain(cur, domain: Domain) -> Domain`; `update_domain(cur, name: DomainName, dkim_selector, active) -> Domain | None`.

- [ ] **Step 1: Write the failing tests** (append to `tests/test_repository_sql.py`)

```python
from mail_controller.domain.domain import Domain
from mail_controller.domain.address import DomainName

_DOMAIN_ROW = {"id": 1, "domain": "example.com", "dkim_selector": "default",
               "active": True, "created_at": None}


def test_list_domains_returns_domain_entities():
    cur = FakeCursor(rows=[_DOMAIN_ROW])
    result = repo.list_domains(cur)
    assert result == [Domain.from_row(_DOMAIN_ROW)]


def test_create_domain_binds_value_and_returns_entity():
    cur = FakeCursor(rows=[_DOMAIN_ROW])
    entity = Domain(name=DomainName("example.com"), dkim_selector="default", active=True)
    result = repo.create_domain(cur, entity)
    _, params = cur.executed[-1]
    assert "example.com" in params.values()
    assert result == Domain.from_row(_DOMAIN_ROW)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `tests/.venv/bin/python -m pytest tests/test_repository_sql.py -k "domains_returns_domain or create_domain_binds" -q`
Expected: FAIL — `create_domain` takes positional args / returns a dict, not a `Domain`.

- [ ] **Step 3: Update the repository functions**

In `mail_controller/db/repository.py`, add `from mail_controller.domain.domain import Domain` and `from mail_controller.domain.address import DomainName` at the top, then replace the domain functions:

```python
def list_domains(cur, term=None) -> list[Domain]:
    where, params = "", {}
    if term:
        where = " WHERE domain ILIKE %(flt)s"
        params["flt"] = f"%{term}%"
    cur.execute(f"SELECT {_DOMAIN_COLS} FROM domains{where} ORDER BY domain", params)
    return [Domain.from_row(r) for r in cur.fetchall()]


def get_domain(cur, name: DomainName) -> Domain | None:
    cur.execute(f"SELECT {_DOMAIN_COLS} FROM domains WHERE domain = %(d)s", {"d": name.value})
    row = cur.fetchone()
    return Domain.from_row(row) if row else None


def create_domain(cur, domain: Domain) -> Domain:
    try:
        cur.execute(
            f"INSERT INTO domains (domain, dkim_selector, active) "
            f"VALUES (%(d)s, %(s)s, %(a)s) RETURNING {_DOMAIN_COLS}",
            {"d": domain.name.value, "s": domain.dkim_selector, "a": domain.active},
        )
    except errors.UniqueViolation:
        raise ConflictError(msg="Domain already exists", detail={"domain": domain.name.value})
    return Domain.from_row(cur.fetchone())


def update_domain(cur, name: DomainName, dkim_selector, active) -> Domain | None:
    cur.execute(
        f"UPDATE domains SET "
        f"dkim_selector = COALESCE(%(s)s, dkim_selector), "
        f"active = COALESCE(%(a)s, active) "
        f"WHERE domain = %(d)s RETURNING {_DOMAIN_COLS}",
        {"d": name.value, "s": dkim_selector, "a": active},
    )
    row = cur.fetchone()
    return Domain.from_row(row) if row else None
```

`delete_domain` is unchanged.

- [ ] **Step 4: Run the domain repository tests**

Run: `tests/.venv/bin/python -m pytest tests/test_repository_sql.py -q`
Expected: PASS (new tests pass; pre-existing domain SQL-shape tests still pass).

- [ ] **Step 5: Commit**

```bash
git add mail_controller/db/repository.py tests/test_repository_sql.py
git commit -m "refactor(repo): domains read/create speak Domain entity"
```

### Task 8: users repository → entities

**Files:**
- Modify: `mail_controller/db/repository.py` (`list_users`, `get_user`, `create_user`, `update_user`)
- Test: `tests/test_repository_sql.py`

**Interfaces:**
- Consumes: `Mailbox` (Task 3), `EmailAddress` (Task 1), `DomainName`.
- Produces: `list_users(cur, domain=None, term=None) -> list[Mailbox]`; `get_user(cur, email: EmailAddress) -> Mailbox | None`; `create_user(cur, mailbox: Mailbox, password_hash: str) -> Mailbox`; `update_user(cur, email: EmailAddress, quota_bytes, active) -> Mailbox | None`.

- [ ] **Step 1: Write the failing tests** (append to `tests/test_repository_sql.py`)

```python
from mail_controller.domain.mailbox import Mailbox
from mail_controller.domain.address import EmailAddress

_USER_ROW = {"id": 5, "email": "alice@example.com", "quota_bytes": 0,
             "active": True, "created_at": None, "domain_id": 1}


def test_list_users_returns_mailbox_entities():
    cur = FakeCursor(rows=[_USER_ROW])
    assert repo.list_users(cur) == [Mailbox.from_row(_USER_ROW)]
    assert "password" not in cur.all_sql.lower()


def test_create_user_binds_email_and_hash():
    cur = FakeCursor(rows=[{"id": 7}, _USER_ROW])  # domain lookup, then INSERT RETURNING
    mailbox = Mailbox(email=EmailAddress("alice@example.com"), quota_bytes=0, active=True)
    result = repo.create_user(cur, mailbox, "{ARGON2ID}$hash")
    assert "alice@example.com" in cur.all_sql_params()
    assert "{ARGON2ID}$hash" in cur.all_sql_params()
    assert result == Mailbox.from_row(_USER_ROW)
```

Also add this helper method to `FakeCursor` (so the assertions above work):

```python
    def all_sql_params(self):
        vals = []
        for _, p in self.executed:
            if isinstance(p, dict):
                vals.extend(p.values())
        return vals
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `tests/.venv/bin/python -m pytest tests/test_repository_sql.py -k "users_returns_mailbox or create_user_binds" -q`
Expected: FAIL — `create_user` signature/return mismatch.

- [ ] **Step 3: Update the repository functions**

Add `from mail_controller.domain.mailbox import Mailbox` and `from mail_controller.domain.address import EmailAddress` at the top of `repository.py`, then:

```python
def list_users(cur, domain=None, term=None) -> list[Mailbox]:
    clauses, params = [], {}
    if domain:
        clauses.append("domain_id = (SELECT id FROM domains WHERE domain = %(d)s)")
        params["d"] = domain.value if isinstance(domain, DomainName) else domain
    if term:
        clauses.append("email ILIKE %(flt)s")
        params["flt"] = f"%{term}%"
    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    cur.execute(f"SELECT {_USER_COLS} FROM users{where} ORDER BY email", params)
    return [Mailbox.from_row(r) for r in cur.fetchall()]


def get_user(cur, email: EmailAddress) -> Mailbox | None:
    cur.execute(f"SELECT {_USER_COLS} FROM users WHERE email = %(e)s", {"e": email.value})
    row = cur.fetchone()
    return Mailbox.from_row(row) if row else None


def create_user(cur, mailbox: Mailbox, password_hash: str) -> Mailbox:
    domain = mailbox.email.domain.value
    cur.execute("SELECT id FROM domains WHERE domain = %(d)s", {"d": domain})
    row = cur.fetchone()
    if not row:
        raise UnprocessableError(msg="Domain does not exist", detail={"domain": domain})
    domain_id = row["id"]
    try:
        cur.execute(
            f"INSERT INTO users (email, domain_id, password, quota_bytes, active) "
            f"VALUES (%(e)s, %(did)s, %(p)s, %(q)s, %(a)s) RETURNING {_USER_COLS}",
            {"e": mailbox.email.value, "did": domain_id, "p": password_hash,
             "q": mailbox.quota_bytes, "a": mailbox.active},
        )
    except errors.ForeignKeyViolation:
        raise UnprocessableError(msg="Referenced domain does not exist", detail={"email": mailbox.email.value})
    except errors.UniqueViolation:
        raise ConflictError(msg="User already exists", detail={"email": mailbox.email.value})
    return Mailbox.from_row(cur.fetchone())


def update_user(cur, email: EmailAddress, quota_bytes, active) -> Mailbox | None:
    cur.execute(
        f"UPDATE users SET "
        f"quota_bytes = COALESCE(%(q)s, quota_bytes), "
        f"active = COALESCE(%(a)s, active) "
        f"WHERE email = %(e)s RETURNING {_USER_COLS}",
        {"e": email.value, "q": quota_bytes, "a": active},
    )
    row = cur.fetchone()
    return Mailbox.from_row(row) if row else None
```

`set_user_password` and `delete_user` keep their signatures, but change their email
parameter binding to accept an `EmailAddress`: bind `email.value`. Update them:

```python
def set_user_password(cur, email: EmailAddress, password_hash) -> bool:
    cur.execute("UPDATE users SET password = %(p)s WHERE email = %(e)s",
                {"p": password_hash, "e": email.value})
    return cur.rowcount > 0


def delete_user(cur, email: EmailAddress) -> dict | None:
    cur.execute("DELETE FROM users WHERE email = %(e)s", {"e": email.value})
    if cur.rowcount == 0:
        return None
    cur.execute("DELETE FROM forwardings WHERE source = %(e)s OR destination = %(e)s", {"e": email.value})
    forwardings_deleted = cur.rowcount
    cur.execute("DELETE FROM sender_login_maps WHERE login_email = %(e)s OR allowed_sender = %(e)s", {"e": email.value})
    sender_logins_deleted = cur.rowcount
    return {"forwardings_deleted": forwardings_deleted, "sender_logins_deleted": sender_logins_deleted}
```

Update the existing `delete_user` cascade tests in `test_repository_sql.py` to pass
`EmailAddress("alice@example.com")` instead of the raw string, and assert binding on
`"alice@example.com"` (the `.value`).

- [ ] **Step 4: Run the tests**

Run: `tests/.venv/bin/python -m pytest tests/test_repository_sql.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add mail_controller/db/repository.py tests/test_repository_sql.py
git commit -m "refactor(repo): users read/create/delete speak Mailbox + EmailAddress"
```

### Task 9: forwardings repository → entities

**Files:**
- Modify: `mail_controller/db/repository.py` (`list_forwardings`, `create_forwarding`)
- Test: `tests/test_repository_sql.py`

**Interfaces:**
- Consumes: `Forwarding` (Task 4), `EmailAddress`, `DomainName`.
- Produces: `list_forwardings(cur, source=None, domain=None, term=None) -> list[Forwarding]`; `create_forwarding(cur, fwd: Forwarding) -> Forwarding`.

- [ ] **Step 1: Write the failing tests** (append to `tests/test_repository_sql.py`)

```python
from mail_controller.domain.forwarding import Forwarding

_FWD_ROW = {"id": 3, "source": "a@example.com", "destination": "b@elsewhere.test",
            "keep_copy": False, "active": True, "created_at": None}


def test_list_forwardings_returns_entities():
    cur = FakeCursor(rows=[_FWD_ROW])
    assert repo.list_forwardings(cur) == [Forwarding.from_row(_FWD_ROW)]


def test_create_forwarding_binds_values_and_returns_entity():
    cur = FakeCursor(rows=[_FWD_ROW])
    fwd = Forwarding(source=EmailAddress("a@example.com"),
                     destination=EmailAddress("b@elsewhere.test"), keep_copy=False)
    result = repo.create_forwarding(cur, fwd)
    assert "a@example.com" in cur.all_sql_params()
    assert result == Forwarding.from_row(_FWD_ROW)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `tests/.venv/bin/python -m pytest tests/test_repository_sql.py -k forwarding -q`
Expected: FAIL — return type / signature mismatch.

- [ ] **Step 3: Update the repository functions**

Add `from mail_controller.domain.forwarding import Forwarding` at the top, then:

```python
def list_forwardings(cur, source=None, domain=None, term=None) -> list[Forwarding]:
    clauses, params = [], {}
    if source:
        clauses.append("source = %(src)s")
        params["src"] = source.value if isinstance(source, EmailAddress) else source
    if domain:
        clauses.append("split_part(source, '@', 2) = %(dom)s")
        params["dom"] = domain.value if isinstance(domain, DomainName) else domain
    if term:
        clauses.append("(source ILIKE %(flt)s OR destination ILIKE %(flt)s)")
        params["flt"] = f"%{term}%"
    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    cur.execute(f"SELECT {_FWD_COLS} FROM forwardings{where} ORDER BY source, destination", params)
    return [Forwarding.from_row(r) for r in cur.fetchall()]


def create_forwarding(cur, fwd: Forwarding) -> Forwarding:
    try:
        cur.execute(
            f"INSERT INTO forwardings (source, destination, keep_copy) "
            f"VALUES (%(s)s, %(d)s, %(k)s) RETURNING {_FWD_COLS}",
            {"s": fwd.source.value, "d": fwd.destination.value, "k": fwd.keep_copy},
        )
    except errors.UniqueViolation:
        raise ConflictError(msg="Forwarding already exists",
                            detail={"source": fwd.source.value, "destination": fwd.destination.value})
    return Forwarding.from_row(cur.fetchone())
```

`delete_forwarding` is unchanged.

- [ ] **Step 4: Run the tests**

Run: `tests/.venv/bin/python -m pytest tests/test_repository_sql.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add mail_controller/db/repository.py tests/test_repository_sql.py
git commit -m "refactor(repo): forwardings read/create speak Forwarding entity"
```

### Task 10: sender_logins repository → entities

**Files:**
- Modify: `mail_controller/db/repository.py` (`list_sender_logins`, `create_sender_login`)
- Test: `tests/test_repository_sql.py`

**Interfaces:**
- Consumes: `SenderLogin` (Task 5), `EmailAddress`, `DomainName`.
- Produces: `list_sender_logins(cur, domain=None, term=None) -> list[SenderLogin]`; `create_sender_login(cur, grant: SenderLogin) -> SenderLogin`.

- [ ] **Step 1: Write the failing tests** (append to `tests/test_repository_sql.py`)

```python
from mail_controller.domain.sender_login import SenderLogin

_SLM_ROW = {"id": 9, "login_email": "ops@example.com", "allowed_sender": "boss@example.com",
            "active": True, "created_at": None}


def test_list_sender_logins_returns_entities():
    cur = FakeCursor(rows=[_SLM_ROW])
    assert repo.list_sender_logins(cur) == [SenderLogin.from_row(_SLM_ROW)]


def test_create_sender_login_binds_values_and_returns_entity():
    cur = FakeCursor(rows=[_SLM_ROW])
    grant = SenderLogin(login_email=EmailAddress("ops@example.com"),
                        allowed_sender=EmailAddress("boss@example.com"))
    result = repo.create_sender_login(cur, grant)
    assert "ops@example.com" in cur.all_sql_params()
    assert result == SenderLogin.from_row(_SLM_ROW)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `tests/.venv/bin/python -m pytest tests/test_repository_sql.py -k sender_login -q`
Expected: FAIL — return type / signature mismatch.

- [ ] **Step 3: Update the repository functions**

Add `from mail_controller.domain.sender_login import SenderLogin` at the top, then:

```python
def list_sender_logins(cur, domain=None, term=None) -> list[SenderLogin]:
    clauses, params = [], {}
    if domain:
        clauses.append("split_part(allowed_sender, '@', 2) = %(d)s")
        params["d"] = domain.value if isinstance(domain, DomainName) else domain
    if term:
        clauses.append("(login_email ILIKE %(flt)s OR allowed_sender ILIKE %(flt)s)")
        params["flt"] = f"%{term}%"
    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    cur.execute(
        f"SELECT {_SLM_COLS} FROM sender_login_maps{where} "
        f"ORDER BY allowed_sender, login_email",
        params,
    )
    return [SenderLogin.from_row(r) for r in cur.fetchall()]


def create_sender_login(cur, grant: SenderLogin) -> SenderLogin:
    try:
        cur.execute(
            f"INSERT INTO sender_login_maps (login_email, allowed_sender) "
            f"VALUES (%(l)s, %(a)s) RETURNING {_SLM_COLS}",
            {"l": grant.login_email.value, "a": grant.allowed_sender.value},
        )
    except errors.UniqueViolation:
        raise ConflictError(msg="Sender-login grant already exists",
                            detail={"login_email": grant.login_email.value,
                                    "allowed_sender": grant.allowed_sender.value})
    return SenderLogin.from_row(cur.fetchone())
```

`delete_sender_login` is unchanged.

- [ ] **Step 4: Run the tests**

Run: `tests/.venv/bin/python -m pytest tests/test_repository_sql.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add mail_controller/db/repository.py tests/test_repository_sql.py
git commit -m "refactor(repo): sender-logins read/create speak SenderLogin entity"
```

### Task 11: audit repository → entities

**Files:**
- Modify: `mail_controller/db/repository.py` (`list_audit`)
- Test: `tests/test_repository_sql.py`

**Interfaces:**
- Consumes: `AuditEntry` (Task 6).
- Produces: `list_audit(cur, login=None, event_type=None, since=None, until=None, limit=100) -> list[AuditEntry]`.

- [ ] **Step 1: Write the failing test** (append to `tests/test_repository_sql.py`)

```python
from mail_controller.domain.audit import AuditEntry

_AUDIT_ROW = {"id": 1, "event_type": "auth", "success": True, "login": "a@example.com",
              "src_ip": "10.0.0.1", "host": "mx1", "sender": None, "recipient": None,
              "message_id": None, "queue_id": None, "score": None, "msg": "ok",
              "pid": 1, "timestamp": None}


def test_list_audit_returns_entities():
    cur = FakeCursor(rows=[_AUDIT_ROW])
    assert repo.list_audit(cur, limit=10) == [AuditEntry.from_row(_AUDIT_ROW)]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `tests/.venv/bin/python -m pytest tests/test_repository_sql.py -k list_audit_returns -q`
Expected: FAIL — returns list of dicts, not `AuditEntry`.

- [ ] **Step 3: Update the function**

Add `from mail_controller.domain.audit import AuditEntry` at the top, then change the
final line of `list_audit` from `return cur.fetchall()` to:

```python
    return [AuditEntry.from_row(r) for r in cur.fetchall()]
```

(The clause-building body of `list_audit` is unchanged.)

- [ ] **Step 4: Run the tests**

Run: `tests/.venv/bin/python -m pytest tests/test_repository_sql.py -q`
Expected: PASS (existing `list_audit` SQL-shape tests still pass).

- [ ] **Step 5: Commit**

```bash
git add mail_controller/db/repository.py tests/test_repository_sql.py
git commit -m "refactor(repo): audit read speaks AuditEntry entity"
```

---

## Stage 4 — Routes + context use entities

### Task 12: `Context.filter_readable` accepts a domain accessor

**Files:**
- Modify: `mail_controller/api/context.py` (`filter_readable`)
- Test: `tests/test_authorization.py`

**Interfaces:**
- Produces: `Context.filter_readable(rows: list, domain_fn: Callable[[Any], str | None]) -> list` — keeps a row when `domain_fn(row)` is readable, or when it is `None` and the identity has `*` read.

- [ ] **Step 1: Write the failing test** (append to `tests/test_authorization.py`)

```python
from mail_controller.api.context import Context
from mail_controller.domain.permission import Permission, PermissionAction
from mail_controller.domain.identity import Identity


def _ctx_with_scope(scope):
    perm = Permission(scope, PermissionAction.READ)
    ident = Identity(id="t", hmac_hex="x" * 64, allowed_cidrs=[], permissions=[perm])
    return Context(remote_ip="127.0.0.1", identity=ident)


def test_filter_readable_uses_domain_accessor():
    ctx = _ctx_with_scope("example.com")
    rows = [{"d": "example.com"}, {"d": "other.test"}]
    visible = ctx.filter_readable(rows, lambda r: r["d"])
    assert visible == [{"d": "example.com"}]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `tests/.venv/bin/python -m pytest tests/test_authorization.py -k filter_readable_uses_domain_accessor -q`
Expected: FAIL — current `filter_readable` takes a `domain_key` string and calls `row.get(...)`.

- [ ] **Step 3: Rewrite `filter_readable`**

In `mail_controller/api/context.py`, replace `filter_readable` (remove the
`domain_key`/`domain_of`/`InvalidRequestError` logic) with:

```python
    def filter_readable(self, rows: list, domain_fn) -> list:
        out: list = []
        for row in rows:
            domain = domain_fn(row)
            if domain is None:
                if self._has_star_read():
                    out.append(row)
                continue
            if self.identity.allows(domain, PermissionAction.READ):
                out.append(row)
        return out
```

Remove the now-unused `domain_of` import and the `InvalidRequestError` import from
`context.py` if they are no longer referenced.

- [ ] **Step 4: Run the test**

Run: `tests/.venv/bin/python -m pytest tests/test_authorization.py -q`
Expected: PASS. (Other authorization tests that called the old signature must be
updated in this step to pass an accessor; update them to `lambda r: r["domain"]`-style
closures matching their row shape.)

- [ ] **Step 5: Commit**

```bash
git add mail_controller/api/context.py tests/test_authorization.py
git commit -m "refactor(api): filter_readable takes a domain accessor"
```

### Task 13: domain routes use entities

**Files:**
- Modify: `mail_controller/api/routes.py` (`list_domains`, `create_domain`, `get_domain`, `update_domain`, `delete_domain`)

**Interfaces:**
- Consumes: `Domain`, `DomainName`, repo domain functions (Task 7), `filter_readable` accessor (Task 12).

- [ ] **Step 1: Update imports**

In `routes.py`, add `from mail_controller.domain.domain import Domain` and
`from mail_controller.domain.address import DomainName, EmailAddress`. (Keep the old
`from mail_controller.domain.address import normalize_email, normalize_domain, domain_of`
import for now — other routes still use it until their tasks land.)

- [ ] **Step 2: Rewrite the domain routes**

```python
@api.route("/api/domains", methods=["GET"])
def list_domains() -> Response:
    ctx = Context.authenticate()
    term = query_str("filter", default=None)
    db = Database.get_from_global_context()
    with db.transaction() as cur:
        rows = repo.list_domains(cur, term=term)
    visible = ctx.filter_readable(rows, lambda d: d.name.value)
    return build_response(200, data=[d.to_dict() for d in visible])


@api.route("/api/domains", methods=["POST"])
def create_domain() -> Response:
    ctx = Context.authenticate()
    body = json_body()
    name = DomainName.parse(json_body_field(body, "domain"))
    ctx.require(name.value, PermissionAction.WRITE)
    dkim_selector = json_body_field(body, "dkim_selector", required=False) or "default"
    active = json_body_field(body, "active", required=False)
    active = True if active is None else bool(active)
    entity = Domain(name=name, dkim_selector=dkim_selector, active=active)
    db = Database.get_from_global_context()
    with db.transaction() as cur:
        row = repo.create_domain(cur, entity)
    return build_response(201, data=row.to_dict())


@api.route("/api/domains/<domain>", methods=["GET"])
def get_domain(domain: str) -> Response:
    name = DomainName.parse(domain)
    ctx = Context.authenticate()
    ctx.require(name.value, PermissionAction.READ)
    db = Database.get_from_global_context()
    with db.transaction() as cur:
        row = repo.get_domain(cur, name)
    if not row:
        raise ResourceNotFoundError(msg="Domain not found", detail={"domain": name.value})
    return build_response(200, data=row.to_dict())


@api.route("/api/domains/<domain>", methods=["PATCH"])
def update_domain(domain: str) -> Response:
    name = DomainName.parse(domain)
    ctx = Context.authenticate()
    ctx.require(name.value, PermissionAction.WRITE)
    body = json_body()
    dkim_selector = json_body_field(body, "dkim_selector", required=False)
    active = json_body_field(body, "active", required=False)
    db = Database.get_from_global_context()
    with db.transaction() as cur:
        row = repo.update_domain(cur, name, dkim_selector,
                                 None if active is None else bool(active))
    if not row:
        raise ResourceNotFoundError(msg="Domain not found", detail={"domain": name.value})
    return build_response(200, data=row.to_dict())


@api.route("/api/domains/<domain>", methods=["DELETE"])
def delete_domain(domain: str) -> Response:
    name = DomainName.parse(domain)
    ctx = Context.authenticate()
    ctx.require(name.value, PermissionAction.WRITE)
    db = Database.get_from_global_context()
    with db.transaction() as cur:
        ok = repo.delete_domain(cur, name.value)
    if not ok:
        raise ResourceNotFoundError(msg="Domain not found", detail={"domain": name.value})
    return build_response(200, data={"domain": name.value, "deleted": True})
```

- [ ] **Step 3: Verify import compiles**

Run: `tests/.venv/bin/python -c "import mail_controller.api.routes"`
Expected: no output, exit 0.

- [ ] **Step 4: Run the full unit suite**

Run: `make test`
Expected: PASS (no regressions).

- [ ] **Step 5: Commit**

```bash
git add mail_controller/api/routes.py
git commit -m "refactor(api): domain routes use Domain/DomainName entities"
```

### Task 14: user routes use entities

**Files:**
- Modify: `mail_controller/api/routes.py` (`list_users`, `create_user`, `get_user`, `update_user`, `set_password`, `delete_user`)

**Interfaces:**
- Consumes: `Mailbox`, `EmailAddress`, `DomainName`, repo user functions (Task 8).

- [ ] **Step 1: Rewrite the user routes**

```python
@api.route("/api/users", methods=["GET"])
def list_users() -> Response:
    ctx = Context.authenticate()
    domain = query_str("domain", default=None)
    term = query_str("filter", default=None)
    dom = DomainName.parse(domain) if domain else None
    db = Database.get_from_global_context()
    with db.transaction() as cur:
        rows = repo.list_users(cur, domain=dom, term=term)
    visible = ctx.filter_readable(rows, lambda m: m.email.domain.value)
    return build_response(200, data=[m.to_dict() for m in visible])


@api.route("/api/users", methods=["POST"])
def create_user() -> Response:
    ctx = Context.authenticate()
    body = json_body()
    email = EmailAddress.parse(json_body_field(body, "email"))
    ctx.require(email.domain.value, PermissionAction.WRITE)
    password = json_body_field(body, "password")
    quota_bytes = json_body_field(body, "quota_bytes", required=False, cast_fn=int) or 0
    active = json_body_field(body, "active", required=False)
    active = True if active is None else bool(active)
    conf = Config.get_from_global_context()
    pw_hash = hash_password(password, conf.password_scheme)
    mailbox = Mailbox(email=email, quota_bytes=quota_bytes, active=active)
    db = Database.get_from_global_context()
    with db.transaction() as cur:
        row = repo.create_user(cur, mailbox, pw_hash)
    return build_response(201, data=row.to_dict())


@api.route("/api/users/<email>", methods=["GET"])
def get_user(email: str) -> Response:
    addr = EmailAddress.parse(email)
    ctx = Context.authenticate()
    ctx.require(addr.domain.value, PermissionAction.READ)
    db = Database.get_from_global_context()
    with db.transaction() as cur:
        row = repo.get_user(cur, addr)
    if not row:
        raise ResourceNotFoundError(msg="User not found", detail={"email": addr.value})
    return build_response(200, data=row.to_dict())


@api.route("/api/users/<email>", methods=["PATCH"])
def update_user(email: str) -> Response:
    addr = EmailAddress.parse(email)
    ctx = Context.authenticate()
    ctx.require(addr.domain.value, PermissionAction.WRITE)
    body = json_body()
    quota_bytes = json_body_field(body, "quota_bytes", required=False, cast_fn=int)
    active = json_body_field(body, "active", required=False)
    db = Database.get_from_global_context()
    with db.transaction() as cur:
        row = repo.update_user(cur, addr, quota_bytes,
                               None if active is None else bool(active))
    if not row:
        raise ResourceNotFoundError(msg="User not found", detail={"email": addr.value})
    return build_response(200, data=row.to_dict())
```

For `set_password` and `delete_user` routes, change the email handling to
`addr = EmailAddress.parse(email)` and pass `addr` to `repo.set_user_password` /
`repo.delete_user`, using `addr.domain.value` in `ctx.require(...)` and `addr.value`
in error details. Keep the rest of each route (including `delete_user`'s
`{**result}` cascade-count response) unchanged.

- [ ] **Step 2: Verify import compiles**

Run: `tests/.venv/bin/python -c "import mail_controller.api.routes"`
Expected: exit 0.

- [ ] **Step 3: Run the full unit suite**

Run: `make test`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add mail_controller/api/routes.py
git commit -m "refactor(api): user routes use Mailbox/EmailAddress entities"
```

### Task 15: forwarding routes use entities

**Files:**
- Modify: `mail_controller/api/routes.py` (`list_forwardings`, `create_forwarding`, `delete_forwarding`)

**Interfaces:**
- Consumes: `Forwarding`, `EmailAddress`, `DomainName`, repo forwarding functions (Task 9).

- [ ] **Step 1: Rewrite the forwarding routes**

```python
@api.route("/api/forwardings", methods=["GET"])
def list_forwardings() -> Response:
    ctx = Context.authenticate()
    source = query_str("source", default=None)
    domain = query_str("domain", default=None)
    term = query_str("filter", default=None)
    src = EmailAddress.parse(source) if source else None
    dom = DomainName.parse(domain) if domain else None
    db = Database.get_from_global_context()
    with db.transaction() as cur:
        rows = repo.list_forwardings(cur, source=src, domain=dom, term=term)
    visible = ctx.filter_readable(rows, lambda f: f.source.domain.value)
    return build_response(200, data=[f.to_dict() for f in visible])


@api.route("/api/forwardings", methods=["POST"])
def create_forwarding() -> Response:
    ctx = Context.authenticate()
    body = json_body()
    source = EmailAddress.parse(json_body_field(body, "source"))
    destination = EmailAddress.parse(json_body_field(body, "destination"))
    ctx.require(source.domain.value, PermissionAction.WRITE)
    keep_copy = json_body_field(body, "keep_copy", required=False)
    keep_copy = False if keep_copy is None else bool(keep_copy)
    fwd = Forwarding(source=source, destination=destination, keep_copy=keep_copy)
    db = Database.get_from_global_context()
    with db.transaction() as cur:
        row = repo.create_forwarding(cur, fwd)
    return build_response(201, data=row.to_dict())
```

For `delete_forwarding`, the route lists forwardings to find the target by id; update
the `domain_of(target["source"])` call (target is now a `Forwarding` entity) to
`ctx.require(target.source.domain.value, PermissionAction.WRITE)` and match by
`target.id == fid`.

- [ ] **Step 2: Verify import compiles**

Run: `tests/.venv/bin/python -c "import mail_controller.api.routes"`
Expected: exit 0.

- [ ] **Step 3: Run the full unit suite**

Run: `make test`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add mail_controller/api/routes.py
git commit -m "refactor(api): forwarding routes use Forwarding entity"
```

### Task 16: sender-login routes use entities

**Files:**
- Modify: `mail_controller/api/routes.py` (`list_sender_logins`, `create_sender_login`, `delete_sender_login`)

**Interfaces:**
- Consumes: `SenderLogin`, `EmailAddress`, `DomainName`, repo sender-login functions (Task 10).

- [ ] **Step 1: Rewrite the sender-login routes**

```python
@api.route("/api/sender-logins", methods=["GET"])
def list_sender_logins() -> Response:
    ctx = Context.authenticate()
    domain = query_str("domain", default=None)
    term = query_str("filter", default=None)
    dom = DomainName.parse(domain) if domain else None
    db = Database.get_from_global_context()
    with db.transaction() as cur:
        rows = repo.list_sender_logins(cur, domain=dom, term=term)
    visible = ctx.filter_readable(rows, lambda s: s.allowed_sender.domain.value)
    return build_response(200, data=[s.to_dict() for s in visible])


@api.route("/api/sender-logins", methods=["POST"])
def create_sender_login() -> Response:
    ctx = Context.authenticate()
    body = json_body()
    login_email = EmailAddress.parse(json_body_field(body, "login_email"))
    allowed_sender = EmailAddress.parse(json_body_field(body, "allowed_sender"))
    ctx.require(allowed_sender.domain.value, PermissionAction.WRITE)
    grant = SenderLogin(login_email=login_email, allowed_sender=allowed_sender)
    db = Database.get_from_global_context()
    with db.transaction() as cur:
        row = repo.create_sender_login(cur, grant)
    return build_response(201, data=row.to_dict())
```

For `delete_sender_login`, update the target lookup (now a `SenderLogin` entity) to
match by `target.id == sid` and authorize with
`ctx.require(target.allowed_sender.domain.value, PermissionAction.WRITE)`.

- [ ] **Step 2: Verify import compiles**

Run: `tests/.venv/bin/python -c "import mail_controller.api.routes"`
Expected: exit 0.

- [ ] **Step 3: Run the full unit suite**

Run: `make test`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add mail_controller/api/routes.py
git commit -m "refactor(api): sender-login routes use SenderLogin entity"
```

### Task 17: audit route uses the accessor

**Files:**
- Modify: `mail_controller/api/routes.py` (`list_audit`)

**Interfaces:**
- Consumes: `AuditEntry` (Task 11), `AuditEntry.login_domain()`.

- [ ] **Step 1: Rewrite the audit route serialization + filter**

```python
@api.route("/api/audit", methods=["GET"])
def list_audit() -> Response:
    ctx = Context.authenticate()
    login = query_str("login", default=None)
    event_type = query_str("event_type", default=None)
    since = query_date("since", default=None)
    until = query_date("until", default=None)
    limit = query_int("limit", default=100, min_val=1, max_val=1000)
    db = Database.get_from_global_context()
    with db.transaction() as cur:
        rows = repo.list_audit(cur, login=login, event_type=event_type,
                               since=since, until=until, limit=limit)
    visible = ctx.filter_readable(rows, lambda a: a.login_domain())
    return build_response(200, data=[a.to_dict() for a in visible])
```

- [ ] **Step 2: Verify import compiles**

Run: `tests/.venv/bin/python -c "import mail_controller.api.routes"`
Expected: exit 0.

- [ ] **Step 3: Run the full unit suite**

Run: `make test`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add mail_controller/api/routes.py
git commit -m "refactor(api): audit route serializes AuditEntry + login_domain accessor"
```

---

## Stage 5 — Remove the old free functions + final verification

### Task 18: delete `normalize_email`/`normalize_domain`/`domain_of`

**Files:**
- Modify: `mail_controller/domain/address.py` (remove the three functions)
- Modify: `mail_controller/api/routes.py`, `mail_controller/api/context.py` (drop now-unused imports)

**Interfaces:**
- Produces: `address.py` containing only `DomainName` and `EmailAddress`.

- [ ] **Step 1: Confirm there are no remaining callers**

Run: `grep -rn "normalize_email\|normalize_domain\|domain_of" mail_controller/ | grep -v "tests/.venv"`
Expected: no matches (every caller migrated in Stages 3–4). If any remain, migrate
them to the value objects before proceeding.

- [ ] **Step 2: Remove the functions and dead imports**

Delete `normalize_email`, `normalize_domain`, and `domain_of` from `address.py`.
Remove the `from mail_controller.domain.address import normalize_email, normalize_domain, domain_of`
import from `routes.py`. If `address.py` no longer uses `InvalidRequestError`, remove
that import too.

- [ ] **Step 3: Verify imports compile**

Run: `tests/.venv/bin/python -c "import mail_controller.api.routes; import mail_controller.domain.address"`
Expected: exit 0.

- [ ] **Step 4: Run the full unit suite**

Run: `make test`
Expected: PASS.

- [ ] **Step 5: Run the integration suite (proves the JSON contract held)**

Run: `make itest`
Expected: PASS — all integration tests green, confirming the response shape is
unchanged end-to-end.

- [ ] **Step 6: Commit**

```bash
git add mail_controller/domain/address.py mail_controller/api/routes.py mail_controller/api/context.py
git commit -m "refactor(domain): remove free address functions; value objects only"
```

---

## Self-Review

**Spec coverage:**
- Value objects (`DomainName`, `EmailAddress`, `parse` vs trusted ctor, `.domain`) → Task 1. ✓
- Entities with `from_row`/`to_dict`, optional server fields, no `password` on Mailbox → Tasks 2–6. ✓
- `AuditEntry.login_domain()` → Task 6, used in Task 17. ✓
- Full domain layer: repo reads return entities, creates accept entities, updates take explicit fields → Tasks 7–11. ✓
- `create_user(cur, mailbox, password_hash)` (password separate) → Task 8. ✓
- `delete_user` keeps cascade-count return → Task 8 (repo) + Task 14 (route). ✓
- Routes parse with value objects, serialize `to_dict()`, no validation try/except → Tasks 13–17. ✓
- `filter_readable` accessor signature → Task 12, used by every list route. ✓
- `ValidationError` → 400 via existing `app.py` handler (no route try/except) → relied on in Tasks 13–17. ✓
- JSON contract preserved → round-trip tests (Tasks 2–6) + integration run (Task 18). ✓
- Old free functions removed last → Task 18. ✓
- No schema changes; SQL stays parameterized; bind `.value` → Tasks 7–11. ✓

**Placeholder scan:** No TBD/TODO; every code step contains full code. ✓

**Type consistency:** `from_row`/`to_dict` present on every entity; repo returns the
matching entity type; routes call `.to_dict()` on returns and `.parse()`/`.value` on
inputs; `filter_readable(rows, domain_fn)` signature matches all five list-route
accessors. ✓
