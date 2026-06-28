# Per-Entity Permission Actions — Design

**Date:** 2026-06-25
**Status:** Approved (design); breaking change accepted
**Area:** `mail_controller/domain/permission.py`, `mail_controller/api/{context,helpers,routes}.py`

## Problem

Authorization currently uses three coarse actions:

```python
class PermissionAction(Enum):
    ANY = "*"
    READ = "read"
    WRITE = "write"
```

A permission like `example.com:read` grants read on **every** entity type
(domains, users, forwardings, sender-logins, audit, metrics) under that scope.
There is no way to grant, say, "may read forwardings but not mailboxes" or
"may read audit logs only". We want actions to be **per entity** so that scopes
can express fine-grained intent.

## Goal

Replace generic `read`/`write` with per-entity actions, keeping the existing
`scope:action` config syntax, the `write ⇒ read` convenience, and the `*`
wildcard meaning "all actions".

## Action Set

`PermissionAction` becomes:

| Value                 | Gates                                  | Read-only |
|-----------------------|----------------------------------------|-----------|
| `*` (`ANY`)           | everything                             | —         |
| `read_domain`         | domain reads                           | —         |
| `write_domain`        | domain writes (⇒ `read_domain`)        | —         |
| `read_user`           | mailbox reads                          | —         |
| `write_user`          | mailbox writes (⇒ `read_user`)         | —         |
| `read_forwarding`     | forwarding reads                       | —         |
| `write_forwarding`    | forwarding writes (⇒ `read_forwarding`)| —         |
| `read_sender_login`   | sender-login reads                     | —         |
| `write_sender_login`  | sender-login writes (⇒ `read_sender_login`) | —    |
| `read_audit`          | audit log reads                        | yes       |
| `read_metrics`        | `/api/metrics`                         | yes       |

The generic `read` and `write` values are **removed**. `audit` and `metrics`
have no write counterpart (they are read-only surfaces).

## Semantics — `Permission.allows(domain, action)`

The scope gate is unchanged (`*`, exact lowercase match, or `fnmatch` glob).
The action gate becomes:

1. `ANY` (`*`) satisfies every action.
2. Exact match: `self.action == action`.
3. Generic write⇒read: a `write_<entity>` permission satisfies the matching
   `read_<entity>` action.

Rule 3 is computed generically from the value strings, not enumerated per
entity, so adding a new entity later needs no change to `allows`:

```python
def _implies(held: PermissionAction, wanted: PermissionAction) -> bool:
    if held == wanted:
        return True
    # write_X implies read_X
    return (held.value.startswith("write_")
            and wanted.value == "read_" + held.value[len("write_"):])
```

`read_audit` and `read_metrics` only satisfy themselves (no write form exists,
so rule 3 never fires for them).

## Route → Action Mapping

Single-resource routes call `ctx.require(domain, <action>)`; list routes pass a
read action to `filter_rows_to_readable`.

| Route                                   | Action               |
|-----------------------------------------|----------------------|
| `GET /api/domains`                      | `READ_DOMAIN` (filter) |
| `POST /api/domains`                     | `WRITE_DOMAIN`       |
| `GET /api/domains/<d>`                  | `READ_DOMAIN`        |
| `PATCH /api/domains/<d>`                | `WRITE_DOMAIN`       |
| `DELETE /api/domains/<d>`               | `WRITE_DOMAIN`       |
| `GET /api/users`                        | `READ_USER` (filter) |
| `POST /api/users`                       | `WRITE_USER`         |
| `GET /api/users/<e>`                    | `READ_USER`          |
| `PATCH /api/users/<e>`                  | `WRITE_USER`         |
| `POST /api/users/<e>/password`          | `WRITE_USER`         |
| `DELETE /api/users/<e>`                 | `WRITE_USER`         |
| `GET /api/forwardings`                  | `READ_FORWARDING` (filter) |
| `POST /api/forwardings`                 | `WRITE_FORWARDING`   |
| `DELETE /api/forwardings/<id>`          | `WRITE_FORWARDING`   |
| `GET /api/sender-logins`                | `READ_SENDER_LOGIN` (filter) |
| `POST /api/sender-logins`               | `WRITE_SENDER_LOGIN` |
| `DELETE /api/sender-logins/<id>`        | `WRITE_SENDER_LOGIN` |
| `GET /api/audit`                        | `READ_AUDIT` (filter) |
| `GET /api/metrics`                      | `READ_METRICS` (gate + filter) |

`/api/token/scope`, `/api/token/identity`, `/api/version`, `/ping` stay
authentication-only (no per-action gate).

### Metrics gating

`/api/metrics` currently authenticates but applies no action gate; rows are
read-filtered via `scope_metrics`. New behaviour:

- The endpoint requires `READ_METRICS` to return any body. Because metrics are
  not domain-scoped as a whole, the gate is "does the identity hold
  `read_metrics` for any scope it can match". If not → `PermissionDeniedError`.
- Per-domain count filtering inside `scope_metrics` continues to use the
  per-entity **read** actions of the corresponding counters. Decision: metrics
  aggregate across entity types, so a single `READ_METRICS` holder sees all
  counters for the scopes it can match; we do **not** cross-filter each counter
  by its own entity read action. `READ_METRICS` is the one gate for the metrics
  surface. (Simplest model; avoids a token needing five separate read grants to
  see a useful metrics page.)

## Helper / Context Changes

### `filter_rows_to_readable` gains an `action` parameter

```python
def filter_rows_to_readable(ctx, rows, domain_fn, action: PermissionAction):
    ...
    if domain is None:
        if ctx._has_star(action):
            out.append(row)
        continue
    if ctx.identity.allows(domain, action):
        out.append(row)
```

Each list route passes its own read action (`READ_DOMAIN`, `READ_USER`, …,
`READ_AUDIT`).

### `Context._has_star_read` → `_has_star(action)`

Domain-less rows (e.g. audit entries with a null/malformed login) are visible
only to a holder of a `*`-scope permission that satisfies the **requested**
action:

```python
def _has_star(self, action: PermissionAction) -> bool:
    return any(p.scope == "*" and p.allows(domain="*", action=action)
               for p in self.identity.permissions)
```

`scope_metrics` uses `_has_star(PermissionAction.READ_METRICS)` and gates its
counters with `READ_METRICS` (see Metrics gating above).

### `token_scope`

`token_scope` already iterates `[a for a in PermissionAction if a != ANY]`, so
it automatically reports the new per-entity actions. The response shape stays
`{action_value: [domains...]}`. Read-only actions (`read_audit`,
`read_metrics`) are domain-keyed the same way — `allows(domain, read_audit)`
reports the scopes where audit is readable.

## Config Syntax & Breaking Change

Syntax is unchanged: `<*|domain_pattern>:<action>`.

Examples:

```
example.com:write_forwarding     # write+read forwardings for example.com
example.com:read_user            # read mailboxes for example.com
*:read_audit                     # read all audit logs
example.com:*                    # full control over example.com
*:*                              # superuser
```

**BREAKING:** existing configs using `:read` or `:write` will fail
`Permission.from_string` validation at startup (the regex is built from
`PermissionAction.values()`, which no longer contains `read`/`write`). There is
**no compatibility shim**. Operators must rewrite permissions to the per-entity
form before deploying. A token that previously held `example.com:write` (full
read+write over the domain) is equivalent to `example.com:*`.

`Permission.from_string` needs no structural change — it already derives its
allowed-action list from `PermissionAction.values()`, so the new enum members
flow through automatically. The error message likewise lists current values.

## Testing

- **`test_permission.py`** — rewrite the action cases:
  - `write_<e>` satisfies `read_<e>` (per entity); does **not** satisfy a
    different entity's read.
  - `read_<e>` does not satisfy `write_<e>` or any other entity.
  - `*` (`ANY`) satisfies every per-entity action.
  - `read_audit` / `read_metrics` satisfy only themselves.
  - `from_string` rejects legacy `:read` / `:write` (breaking-change guard).
  - scope glob behaviour unchanged.
- **`test_authorization.py`** — `filter_rows_to_readable` calls take the new
  `action` arg; `require` cases use per-entity actions. `_has_star` null-login
  audit cases pass `READ_AUDIT`.
- **`test_metrics.py`** — `scope_metrics` honours `READ_METRICS`; a token
  without `read_metrics` is denied the endpoint.
- **`test_integration.py`** — seed identities with per-entity scopes; assert a
  `read_forwarding`-only token can list forwardings but is 403 on mailbox
  writes, etc. Update any seed config using `:read`/`:write`.
- Update sample/seed configs and any docs/ADR referencing `:read`/`:write`.

## Out of Scope

- No per-action audit/metrics write surfaces.
- No backward-compatibility shim for legacy `read`/`write` values.
- No change to scope (glob) matching, HMAC auth, or CIDR checks.
