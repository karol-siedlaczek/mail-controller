# Per-Entity Permission Actions Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace coarse `read`/`write` permission actions with per-entity actions (`read_domain`, `write_domain`, `read_user`, …, `read_audit`, `read_metrics`) so token scopes can express fine-grained intent.

**Architecture:** Three layers change in sequence. (1) The domain layer (`PermissionAction` enum + `Permission.allows`) gains the new actions *additively* so its logic is independently testable. (2) The API layer (context, helpers, routes) is rewired to the per-entity actions and all configs that flow through routes are migrated. (3) The legacy `read`/`write` enum members are removed, completing the breaking change. Keeping the change additive through Tasks 1–2 lets every task end with a green `make test`.

**Tech Stack:** Python 3, frozen dataclasses, Flask blueprint, Typer CLI, pytest. Auth model: `Identity` → `Permission(scope, action)`; `Permission.allows(domain, action)` = action gate + scope gate (fnmatch glob, `*` = all).

## Global Constraints

- Spec: `docs/superpowers/specs/2026-06-25-per-entity-permission-actions-design.md` — every task implicitly conforms to it.
- Config syntax stays `<*|domain_pattern>:<action>`. `scope:*` = full control over scope.
- **BREAKING:** no compatibility shim for legacy `:read`/`:write`. By end of Task 3 they must fail `Permission.from_string` validation.
- `write_<entity>` implies `read_<entity>` (computed generically from value strings, not enumerated per entity).
- `read_audit` and `read_metrics` are read-only (no write counterpart) and satisfy only themselves.
- SQL stays fully parameterized (unaffected here, but do not regress).
- User manages git: only `git add`/`git commit` the files each step names; never push.
- Unit tests: `make test` (runs `pytest -m "not integration"` in `tests/`). Integration: `make itest` (docker compose postgres:16). Single test: `cd tests && .venv/bin/python -m pytest <file>::<test> -v`.

---

## File Structure

- `mail_controller/domain/permission.py` — `PermissionAction` enum + `Permission.allows`/`allows_action`. (Tasks 1, 3)
- `mail_controller/api/context.py` — `_has_star(action)` (renamed from `_has_star_read`), new `require_action(action)`. (Task 2)
- `mail_controller/api/helpers.py` — `filter_rows_to_readable` gains `action` param. (Task 2)
- `mail_controller/api/routes.py` — per-entity action at every `require`/filter call site; metrics gate; `scope_metrics`. (Task 2)
- `tests/test_permission.py` — per-entity action tests + legacy-rejection guard. (Tasks 1, 3)
- `tests/test_authorization.py` — filter/require call sites migrated to per-entity. (Task 2)
- `tests/test_metrics.py` — fake ctx `_has_star(action)`. (Task 2)
- `tests/test_routes.py`, `tests/config.test.yaml` — seed configs migrated. (Task 2)
- `tests/test_identity.py`, `tests/test_config.py` — legacy config strings migrated. (Task 3)
- `README.md` — permission examples + audit note. (Task 3)

---

## Task 1: Domain layer — add per-entity actions (additive)

**Files:**
- Modify: `mail_controller/domain/permission.py`
- Test: `tests/test_permission.py`

**Interfaces:**
- Consumes: nothing new.
- Produces:
  - `PermissionAction` members: `ANY="*"`, `READ="read"`, `WRITE="write"` (legacy, removed in Task 3), `READ_DOMAIN="read_domain"`, `WRITE_DOMAIN="write_domain"`, `READ_USER="read_user"`, `WRITE_USER="write_user"`, `READ_FORWARDING="read_forwarding"`, `WRITE_FORWARDING="write_forwarding"`, `READ_SENDER_LOGIN="read_sender_login"`, `WRITE_SENDER_LOGIN="write_sender_login"`, `READ_AUDIT="read_audit"`, `READ_METRICS="read_metrics"`.
  - `Permission.allows_action(self, action: PermissionAction) -> bool` — action gate only.
  - `Permission.allows(self, domain: str, action: PermissionAction) -> bool` — action gate + unchanged scope gate.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_permission.py`:

```python
def test_parse_per_entity_action():
    perm = p("example.com:write_domain")
    assert perm.scope == "example.com"
    assert perm.action == PermissionAction.WRITE_DOMAIN


def test_write_entity_implies_read_same_entity():
    perm = p("example.com:write_forwarding")
    assert perm.allows("example.com", PermissionAction.WRITE_FORWARDING)
    assert perm.allows("example.com", PermissionAction.READ_FORWARDING)


def test_write_entity_does_not_imply_other_entity():
    perm = p("example.com:write_forwarding")
    assert not perm.allows("example.com", PermissionAction.READ_USER)
    assert not perm.allows("example.com", PermissionAction.WRITE_USER)


def test_read_entity_does_not_imply_write():
    perm = p("example.com:read_user")
    assert perm.allows("example.com", PermissionAction.READ_USER)
    assert not perm.allows("example.com", PermissionAction.WRITE_USER)


def test_any_satisfies_every_entity_action():
    perm = p("example.com:*")
    for action in (PermissionAction.READ_DOMAIN, PermissionAction.WRITE_DOMAIN,
                   PermissionAction.READ_AUDIT, PermissionAction.READ_METRICS):
        assert perm.allows("example.com", action)


def test_read_audit_and_metrics_satisfy_only_themselves():
    assert p("*:read_audit").allows("x.test", PermissionAction.READ_AUDIT)
    assert not p("*:read_audit").allows("x.test", PermissionAction.READ_DOMAIN)
    assert p("*:read_metrics").allows("x.test", PermissionAction.READ_METRICS)
    assert not p("*:read_metrics").allows("x.test", PermissionAction.READ_AUDIT)


def test_per_entity_glob_scope():
    perm = p("*.example.com:write_user")
    assert perm.allows("a.example.com", PermissionAction.WRITE_USER)
    assert perm.allows("a.example.com", PermissionAction.READ_USER)
    assert not perm.allows("example.com", PermissionAction.WRITE_USER)
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd tests && .venv/bin/python -m pytest test_permission.py -v`
Expected: the new tests FAIL with `AttributeError: WRITE_DOMAIN` (enum members don't exist yet). Existing tests still PASS.

- [ ] **Step 3: Add the per-entity enum members**

In `mail_controller/domain/permission.py`, replace the enum body (keep `ANY`/`READ`/`WRITE`, keep `values()`):

```python
class PermissionAction(Enum):
    ANY = "*"
    READ = "read"      # legacy — removed in the cleanup task
    WRITE = "write"    # legacy — removed in the cleanup task
    READ_DOMAIN = "read_domain"
    WRITE_DOMAIN = "write_domain"
    READ_USER = "read_user"
    WRITE_USER = "write_user"
    READ_FORWARDING = "read_forwarding"
    WRITE_FORWARDING = "write_forwarding"
    READ_SENDER_LOGIN = "read_sender_login"
    WRITE_SENDER_LOGIN = "write_sender_login"
    READ_AUDIT = "read_audit"
    READ_METRICS = "read_metrics"

    @classmethod
    def values(cls) -> list[str]:
        return [item.value for item in cls]
```

- [ ] **Step 4: Add `allows_action` and refactor `allows`**

In `mail_controller/domain/permission.py`, replace the current `allows` method with:

```python
    def allows_action(self, action: "PermissionAction") -> bool:
        # ANY satisfies every action.
        if self.action == PermissionAction.ANY:
            return True
        # Exact match.
        if self.action == action:
            return True
        # Legacy generic write ⇒ read (removed with READ/WRITE in the cleanup task).
        if self.action == PermissionAction.WRITE and action == PermissionAction.READ:
            return True
        # Per-entity: write_<entity> implies read_<entity>.
        return (self.action.value.startswith("write_")
                and action.value == "read_" + self.action.value[len("write_"):])

    def allows(self, domain: str, action: "PermissionAction") -> bool:
        # Action gate.
        if not self.allows_action(action):
            return False
        # Scope gate: "*", exact domain, or glob pattern (fnmatch).
        if self.scope == "*" or self.scope == domain.lower():
            return True
        return fnmatch.fnmatch(domain.lower(), self.scope.lower())
```

- [ ] **Step 5: Run the full permission suite to verify it passes**

Run: `cd tests && .venv/bin/python -m pytest test_permission.py -v`
Expected: PASS (new per-entity tests + all legacy tests).

- [ ] **Step 6: Run the whole unit suite (nothing else should break)**

Run: `make test`
Expected: PASS (legacy actions still work; additive change).

- [ ] **Step 7: Commit**

```bash
git add mail_controller/domain/permission.py tests/test_permission.py
git commit -m "feat(domain): add per-entity permission actions (additive)"
```

---

## Task 2: API layer wired to per-entity actions

**Files:**
- Modify: `mail_controller/api/context.py`
- Modify: `mail_controller/api/helpers.py`
- Modify: `mail_controller/api/routes.py`
- Modify: `tests/test_authorization.py`
- Modify: `tests/test_metrics.py`
- Modify: `tests/test_routes.py`
- Modify: `tests/config.test.yaml`

**Interfaces:**
- Consumes: `PermissionAction.*` and `Permission.allows`/`allows_action` from Task 1.
- Produces:
  - `Context._has_star(self, action: PermissionAction) -> bool` (replaces `_has_star_read`).
  - `Context.require_action(self, action: PermissionAction) -> None` — raises `PermissionDeniedError` if no permission's action gate satisfies `action` (scope-independent; for non-domain surfaces like metrics).
  - `helpers.filter_rows_to_readable(ctx, rows, domain_fn, action: PermissionAction)` — new required `action` arg.
  - Route→action wiring per the spec's mapping table.

- [ ] **Step 1: Migrate the authorization tests (RED)**

Rewrite `tests/test_authorization.py` so every `filter_rows_to_readable` call passes an explicit `action`, `require` calls use per-entity actions, and identity scopes use per-entity strings. Apply these exact edits:

- `test_require_write_allowed`: perms `["example.com:write_domain"]`; call `_ctx(ident).require("example.com", PermissionAction.WRITE_DOMAIN)`.
- `test_require_write_denied_for_read_only`: perms `["example.com:read_domain"]`; call `.require("example.com", PermissionAction.WRITE_DOMAIN)`.
- `test_require_denied_wrong_domain`: perms `["example.com:write_domain"]`; call `.require("other.com", PermissionAction.WRITE_DOMAIN)`.
- `test_filter_readable_by_domain_field`: perms `["example.com:read_domain"]`; call `filter_rows_to_readable(_ctx(ident), rows, lambda r: r["domain"], PermissionAction.READ_DOMAIN)`.
- `test_filter_readable_by_email_field`: perms `["example.com:read_user"]`; call `filter_rows_to_readable(_ctx(ident), rows, lambda r: r["email"].rsplit("@", 1)[1], PermissionAction.READ_USER)`.
- `test_filter_audit_null_login_requires_star`: star perms `["*:read_audit"]`, scoped perms `["example.com:read_audit"]`; both `filter_rows_to_readable(..., _login_domain, PermissionAction.READ_AUDIT)`.
- `test_filter_audit_malformed_login`: same as above — star `["*:read_audit"]`, scoped `["example.com:read_audit"]`, both calls add `PermissionAction.READ_AUDIT`.
- `_ctx_with_scope`: `perm = Permission(scope, PermissionAction.READ_DOMAIN)`.
- `test_filter_readable_uses_domain_accessor`: call `filter_rows_to_readable(ctx, rows, lambda r: r["d"], PermissionAction.READ_DOMAIN)`.
- Leave the authentication tests (`test_authenticate_*`) unchanged except their identity perms — change `["example.com:read"]` to `["example.com:read_domain"]` in `test_authenticate_resolves_identity_and_ip`, `test_authenticate_missing_header_raises`, `test_authenticate_bad_token_raises`.

- [ ] **Step 2: Run the authorization tests to verify they fail**

Run: `cd tests && .venv/bin/python -m pytest test_authorization.py -v`
Expected: FAIL — `filter_rows_to_readable()` takes 3 positional args but 4 given (the `action` param doesn't exist yet); `_ctx(...).require` denials may also misbehave.

- [ ] **Step 3: Update `helpers.filter_rows_to_readable` to take an `action`**

In `mail_controller/api/helpers.py`, replace the function:

```python
def filter_rows_to_readable(
    ctx, rows: list[T], domain_fn: Callable[[T], str | None], action: PermissionAction
) -> list[T]:
    """Keep only rows whose domain the identity may access with `action`.

    `domain_fn` extracts a row's domain (or None for domain-less rows, e.g. audit
    entries with no login). Domain-less rows are visible only to a "*"-scope holder
    of `action`.
    """
    out: list[T] = []
    for row in rows:
        domain = domain_fn(row)
        if domain is None:
            if ctx._has_star(action):
                out.append(row)
            continue
        if ctx.identity.allows(domain, action):
            out.append(row)
    return out
```

(The `from mail_controller.domain.permission import PermissionAction` import already exists at the top of the file.)

- [ ] **Step 4: Update `Context` — rename `_has_star_read`, add `require_action`**

In `mail_controller/api/context.py`, replace `_has_star_read` with `_has_star(action)` and add `require_action`:

```python
    def require_action(self, action: PermissionAction) -> None:
        # Gate a non-domain-scoped surface (e.g. metrics): the identity must hold
        # at least one permission whose action satisfies `action`, regardless of scope.
        if not any(p.allows_action(action) for p in self.identity.permissions):
            raise PermissionDeniedError(
                detail={"identity": self.identity.id, "action": action.value}
            )

    def _has_star(self, action: PermissionAction) -> bool:
        # A "*"-scope permission grants `action` regardless of domain. Reuses
        # Permission.allows so the action/scope rule lives in one place.
        return any(p.scope == "*" and p.allows(domain="*", action=action)
                   for p in self.identity.permissions)
```

- [ ] **Step 5: Wire each route to its per-entity action**

In `mail_controller/api/routes.py`, replace `PermissionAction.READ`/`PermissionAction.WRITE` at each call site and add the `action` arg to every `filter_rows_to_readable` call, per this mapping:

- `domain_list` (line ~115): `filter_rows_to_readable(ctx, domains, lambda d: d.name.value, PermissionAction.READ_DOMAIN)`
- `domain_create` (~124): `ctx.require(domain_name.value, PermissionAction.WRITE_DOMAIN)`
- `domain_get` (~141): `ctx.require(name.value, PermissionAction.READ_DOMAIN)`
- `domain_update` (~154): `ctx.require(name.value, PermissionAction.WRITE_DOMAIN)`
- `domain_delete` (~171): `ctx.require(name.value, PermissionAction.WRITE_DOMAIN)`
- `user_list` (~194): `filter_rows_to_readable(ctx, rows, lambda m: m.email.domain.value, PermissionAction.READ_USER)`
- `user_create` (~203): `ctx.require(email.domain.value, PermissionAction.WRITE_USER)`
- `user_get` (~221): `ctx.require(addr.domain.value, PermissionAction.READ_USER)`
- `user_update` (~234): `ctx.require(addr.domain.value, PermissionAction.WRITE_USER)`
- `user_update_password` (~251): `ctx.require(addr.domain.value, PermissionAction.WRITE_USER)`
- `user_delete` (~268): `ctx.require(addr.domain.value, PermissionAction.WRITE_USER)`
- `forwarding_list` (~295): `filter_rows_to_readable(ctx, rows, lambda f: f.source.domain.value, PermissionAction.READ_FORWARDING)`
- `forwarding_create` (~305): `ctx.require(source.domain.value, PermissionAction.WRITE_FORWARDING)`
- `forwarding_delete` (~324): `ctx.require(target.source.domain.value, PermissionAction.WRITE_FORWARDING)`
- `sender_login_list` (~343): `filter_rows_to_readable(ctx, rows, lambda s: s.allowed_sender.domain.value, PermissionAction.READ_SENDER_LOGIN)`
- `sender_login_create` (~353): `ctx.require(allowed_sender.domain.value, PermissionAction.WRITE_SENDER_LOGIN)`
- `sender_login_delete` (~370): `ctx.require(target.allowed_sender.domain.value, PermissionAction.WRITE_SENDER_LOGIN)`
- `audit_list` (~397): `filter_rows_to_readable(ctx, rows, lambda a: a.login_domain(), PermissionAction.READ_AUDIT)`

- [ ] **Step 6: Gate `/api/metrics` and update `scope_metrics`**

In `mail_controller/api/routes.py` `metrics()`, add the gate immediately after authentication:

```python
def metrics() -> Response:
    ctx = Context.authenticate()
    ctx.require_action(PermissionAction.READ_METRICS)
    since = datetime.now(timezone.utc) - timedelta(minutes=5)
```

In `scope_metrics`, change the star check and the per-domain read check to `READ_METRICS`:

```python
    star = ctx._has_star(PermissionAction.READ_METRICS)

    def visible(dom):
        if not dom:
            return star
        return star or ctx.identity.allows(dom, PermissionAction.READ_METRICS)
```

- [ ] **Step 7: Update the metrics fake context**

In `tests/test_metrics.py`, rename the fake method so it matches the new helper:

```python
class _FakeCtx:
    def __init__(self, star, readable):
        self._star = star
        self.identity = _FakeIdentity(readable)

    def _has_star(self, action):
        return self._star
```

(`_FakeIdentity.allows(self, dom, action)` already ignores `action`; no change needed.)

- [ ] **Step 8: Migrate the route-test seed config**

In `tests/test_routes.py` `client` fixture, change the two permission strings:

```python
        "    permissions: [\"*:*\"]\n"
...
        "    permissions: [\"other.com:read_domain\"]\n"
```

(`admin` `*:*` keeps full control; `ro` reads only `other.com` domains — still gets an empty list for the `example.com` store and 403 on create.)

- [ ] **Step 9: Migrate the integration seed config**

In `tests/config.test.yaml`, replace the permission lines:

```yaml
identities:
  - id: admin
    allowed_cidrs: ["0.0.0.0/0", "::/0"]
    permissions: ["*:*"]
  - id: artform
    allowed_cidrs: ["0.0.0.0/0", "::/0"]
    permissions: ["artform.test:*"]
  - id: reader
    allowed_cidrs: ["0.0.0.0/0", "::/0"]
    permissions: ["artform.test:read_domain", "artform.test:read_user"]
  - id: blocked
    allowed_cidrs: ["10.255.255.255/32"]
    permissions: ["*:*"]
```

(`reader` needs both `read_domain` (lists `/api/domains`) and `read_user` (lists `/api/users?domain=...`), per `test_per_domain_authorization` and `test_list_filtered_to_readable`. `admin` `*:*` includes `read_metrics`, so `test_metrics_endpoint` passes.)

- [ ] **Step 10: Run the unit suite**

Run: `make test`
Expected: PASS (`test_authorization.py`, `test_metrics.py`, `test_routes.py` green; legacy-config tests in `test_identity.py`/`test_config.py` still green because legacy actions remain until Task 3).

- [ ] **Step 11: Run the integration suite**

Run: `make itest`
Expected: PASS — including `test_per_domain_authorization`, `test_list_filtered_to_readable`, `test_metrics_endpoint`.

- [ ] **Step 12: Commit**

```bash
git add mail_controller/api/context.py mail_controller/api/helpers.py mail_controller/api/routes.py \
        tests/test_authorization.py tests/test_metrics.py tests/test_routes.py tests/config.test.yaml
git commit -m "feat(api): route authorization uses per-entity permission actions"
```

---

## Task 3: Remove legacy `read`/`write` (complete the breaking change)

**Files:**
- Modify: `mail_controller/domain/permission.py`
- Modify: `tests/test_permission.py`
- Modify: `tests/test_identity.py`
- Modify: `tests/test_config.py`
- Modify: `README.md`

**Interfaces:**
- Consumes: everything from Tasks 1–2.
- Produces: `PermissionAction` without `READ`/`WRITE`; `Permission.from_string` rejects `:read`/`:write` (regex is derived from `PermissionAction.values()`, so removal is automatic); `allows_action` without the legacy generic line.

- [ ] **Step 1: Add the breaking-change guard + migrate legacy parse tests (RED)**

In `tests/test_permission.py`:

- Replace `test_parse_write` body to use a per-entity action:

```python
def test_parse_write():
    perm = p("example.com:write_domain")
    assert perm.scope == "example.com"
    assert perm.action == PermissionAction.WRITE_DOMAIN
```

- Replace `test_parse_star_write`:

```python
def test_parse_star_write():
    perm = p("*:write_user")
    assert perm.scope == "*"
    assert perm.action == PermissionAction.WRITE_USER
```

- Replace `test_write_implies_read`, `test_read_does_not_imply_write`, `test_star_scope_matches_any_domain`, `test_glob_scope`, `test_exact_scope_no_cross_domain` to use per-entity actions (these duplicate the Task 1 tests; rewrite them to the `*_domain` variants):

```python
def test_write_implies_read():
    perm = p("example.com:write_domain")
    assert perm.allows("example.com", PermissionAction.READ_DOMAIN)
    assert perm.allows("example.com", PermissionAction.WRITE_DOMAIN)


def test_read_does_not_imply_write():
    perm = p("example.com:read_domain")
    assert perm.allows("example.com", PermissionAction.READ_DOMAIN)
    assert not perm.allows("example.com", PermissionAction.WRITE_DOMAIN)


def test_star_scope_matches_any_domain():
    perm = p("*:read_domain")
    assert perm.allows("anything.test", PermissionAction.READ_DOMAIN)


def test_glob_scope():
    perm = p("*.example.com:write_domain")
    assert perm.allows("a.example.com", PermissionAction.WRITE_DOMAIN)
    assert not perm.allows("example.com", PermissionAction.WRITE_DOMAIN)


def test_exact_scope_no_cross_domain():
    perm = p("example.com:write_domain")
    assert not perm.allows("other.com", PermissionAction.WRITE_DOMAIN)
```

- Add the guard test:

```python
def test_legacy_generic_actions_rejected():
    with pytest.raises(ValidationError):
        p("example.com:read")
    with pytest.raises(ValidationError):
        p("example.com:write")
```

- [ ] **Step 2: Run permission tests to verify the guard fails**

Run: `cd tests && .venv/bin/python -m pytest test_permission.py::test_legacy_generic_actions_rejected -v`
Expected: FAIL — `:read`/`:write` still parse (the enum still has `READ`/`WRITE`).

- [ ] **Step 3: Remove legacy enum members and the legacy `allows_action` line**

In `mail_controller/domain/permission.py`:

- Delete the `READ = "read"` and `WRITE = "write"` lines from `PermissionAction`.
- Delete the legacy line in `allows_action`:

```python
        # Legacy generic write ⇒ read (removed with READ/WRITE in the cleanup task).
        if self.action == PermissionAction.WRITE and action == PermissionAction.READ:
            return True
```

`allows_action` now ends with the ANY check, exact match, and the per-entity `write_*`⇒`read_*` rule only.

- [ ] **Step 4: Migrate remaining legacy config strings in tests**

In `tests/test_identity.py`:
- `_identity` default perms: `["*:write"]` → `["*:*"]`.
- `test_missing_token_env`: `"permissions": ["*:read"]` → `["*:*"]`.
- `test_allows_delegates_to_permissions`:

```python
def test_allows_delegates_to_permissions(monkeypatch):
    ident = _identity(monkeypatch, perms=["example.com:read_domain"])
    assert ident.allows("example.com", PermissionAction.READ_DOMAIN)
    assert not ident.allows("example.com", PermissionAction.WRITE_DOMAIN)
    assert not ident.allows("other.com", PermissionAction.READ_DOMAIN)
```

In `tests/test_config.py`:
- `test_load_ok`: `permissions: ["*:write"]` → `["*:*"]`.
- `test_duplicate_identity_id`: both `["*:write"]` and `["*:read"]` → `["*:*"]`.

- [ ] **Step 5: Update README permission docs**

In `README.md`, replace the legacy examples (lines ~154–165) and the audit note (line ~262):

- `- "*:write"` → `- "*:*"`
- `- "example.com:write"` → `- "example.com:*"`
- `- "*.example.com:read"` → `- "*.example.com:read_domain"`
- `- "*:read"` → `- "*:read_audit"`
- Audit note: `Audit rows with no \`login\` (no domain) require \`*:read\`.` → `Audit rows with no \`login\` (no domain) require \`*:read_audit\`.`

Add a short note near the permissions section listing the valid actions: `read_domain`, `write_domain`, `read_user`, `write_user`, `read_forwarding`, `write_forwarding`, `read_sender_login`, `write_sender_login`, `read_audit`, `read_metrics`, and `*` (all). Mention `write_<entity>` implies `read_<entity>`, and that `:read`/`:write` are no longer valid (breaking change).

- [ ] **Step 6: Verify no legacy references remain**

Run: `grep -rn "PermissionAction\.\(READ\|WRITE\)\b\|:read\"\|:write\"\|:read'\|:write'" --include=*.py --include=*.yaml --include=*.md mail_controller tests README.md`
Expected: no matches (the only `read_`/`write_` strings remaining are per-entity). If any match appears, fix it before committing.

- [ ] **Step 7: Run the full unit suite**

Run: `make test`
Expected: PASS.

- [ ] **Step 8: Run the integration suite**

Run: `make itest`
Expected: PASS.

- [ ] **Step 9: Commit**

```bash
git add mail_controller/domain/permission.py tests/test_permission.py \
        tests/test_identity.py tests/test_config.py README.md
git commit -m "feat(domain)!: remove legacy read/write actions; per-entity only

BREAKING CHANGE: permission configs using ':read'/':write' must migrate to
per-entity actions (e.g. ':read_domain', ':write_user') or ':*' for full control."
```

---

## Self-Review

**Spec coverage:**
- Action set (11 members incl. `read_audit`/`read_metrics`) → Task 1 Step 3. ✓
- `allows` semantics (ANY / exact / generic write⇒read) → Task 1 Step 4. ✓
- Route→action mapping (every route) → Task 2 Step 5. ✓
- `filter_rows_to_readable` action param → Task 2 Step 3. ✓
- `_has_star(action)` → Task 2 Step 4. ✓
- `READ_METRICS` gating (single gate for the surface) → Task 2 Step 6 (`require_action` + `scope_metrics`). ✓
- `token_scope` iterates new action set → no code change needed (already iterates `[a for a in PermissionAction if a != ANY]`); covered by integration. ✓
- Scope format unchanged + breaking change (no shim) → Task 3 (remove members, guard test, README). ✓
- Testing (permission, authorization, metrics, integration, config migration) → Tasks 1–3. ✓

**Placeholder scan:** No TBD/TODO; every code/edit step shows concrete content or exact old→new strings.

**Type consistency:** `allows_action`/`allows` signatures, `_has_star(action)`, `require_action(action)`, and `filter_rows_to_readable(..., action)` are used identically wherever referenced. Enum value strings match the spec table exactly.

---

## Execution Handoff

Plan complete and saved to `docs/superpowers/plans/2026-06-25-per-entity-permission-actions.md`. Two execution options:

1. **Subagent-Driven (recommended)** — I dispatch a fresh subagent per task, review between tasks, fast iteration.
2. **Inline Execution** — Execute tasks in this session using executing-plans, batch execution with checkpoints.

Which approach?
