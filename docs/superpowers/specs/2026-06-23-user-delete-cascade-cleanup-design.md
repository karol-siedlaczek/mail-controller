# User-delete cascade cleanup — design

**Date:** 2026-06-23
**Repo:** mail-controller (`mail_controller/`, `mailctl.py`)
**Schema source of truth:** `docker-images-homelab/images/mail-server/sql/schema.sql`

## Problem

`forwardings.source` / `forwardings.destination` and
`sender_login_maps.login_email` / `sender_login_maps.allowed_sender` store
**text addresses**, not foreign keys to `users`. They must stay text: a
forwarding source is frequently an alias-only address with no mailbox
(`info@`, `postmaster@`, catch-all), and destinations/allowed-senders are
often external addresses. There is intentionally no FK and no
`ON DELETE CASCADE`.

Consequence: deleting a user via `DELETE FROM users` leaves dangling
references in those four columns — forwardings and send-as grants that point
at, or originate from, an address that no longer exists.

## Goal

When `delete_user` removes a mailbox, atomically remove every row that
references that address across all four columns, in the same transaction, and
report to the caller how many rows the cascade removed.

## Decisions (resolved during brainstorming)

1. **Cleanup belongs in the application** (mail-controller / `mail_admin_rw`),
   not in a DB trigger. Single writer, single audit trail.
2. **Scope = all four references.** Delete every row where the address appears
   in `forwardings.source`, `forwardings.destination`,
   `sender_login_maps.login_email`, or `sender_login_maps.allowed_sender`.
   Every such row is functionally dead once the user is gone (mail bounces /
   grant references a non-existent identity), so there is no scenario where the
   cascade removes a still-working row.
3. **Cascade is privileged.** Authorization is unchanged: `WRITE` on the
   deleted user's own domain. The cascade then removes referencing rows
   regardless of which domain "owns" them (mirrors SQL `ON DELETE CASCADE`).
   Rationale: leaving dangling rows in the DB only because they belong to
   another domain defeats the purpose; the only side effect is reduced
   visibility for the other domain's admin, which the existing `audit_logs`
   trail and the single `mail_admin_rw` writer already cover.

## Components

### 1. `mail_controller/db/repository.py` — `delete_user(cur, email)`

Change return type from `bool` to `dict | None`.

```
DELETE FROM users WHERE email = %(e)s
    rowcount == 0  →  return None          # nothing existed; no cascade

DELETE FROM forwardings
    WHERE source = %(e)s OR destination = %(e)s          → fwd_n  (cur.rowcount)
DELETE FROM sender_login_maps
    WHERE login_email = %(e)s OR allowed_sender = %(e)s   → slm_n  (cur.rowcount)

return {"forwardings_deleted": fwd_n, "sender_logins_deleted": slm_n}
```

- Fully parameterized (`%(e)s`), consistent with the rest of the module.
- User row is deleted **first** purely to gate the 404 / no-op cleanly: if the
  user does not exist we return `None` and touch nothing else.
- No FK between these tables means delete order is irrelevant to integrity;
  the route's single `db.transaction()` makes the whole operation atomic.

### 2. `mail_controller/api/routes.py` — `delete_user` route

```
result = repo.delete_user(cur, email)
if result is None:
    raise ResourceNotFoundError(msg="User not found", detail={"email": email})
return build_response(200, data={"email": email, "deleted": True, **result})
```

Authorization line unchanged: `ctx.require(domain_of(email), WRITE)`.

### 3. `mailctl.py`

No code change. `user rm` calls `CmdResult.render_and_exit` with no explicit
`columns`, and `_filter_data` returns the full data dict when `columns` is
empty, so the new `forwardings_deleted` / `sender_logins_deleted` fields render
automatically (table and `--format json`). Operators who pass `--columns`
explicitly opt into a narrower view.

## Testing

### Unit — `tests/test_repository_sql.py` (FakeCursor, no real DB)
- Extend `FakeCursor` so `rowcount` can be scripted per `execute()` (queue of
  values) instead of a single fixed value.
- `delete_user` issues a `forwardings` DELETE filtered on both `source` and
  `destination`, parameterized by the email.
- `delete_user` issues a `sender_login_maps` DELETE filtered on both
  `login_email` and `allowed_sender`, parameterized by the email.
- When the `users` DELETE reports `rowcount == 0`, `delete_user` returns `None`
  and issues **no** cascade DELETEs.
- On success, returns `{"forwardings_deleted": n, "sender_logins_deleted": m}`
  matching the scripted rowcounts.

### Integration — `tests/test_integration.py` (real stack)
- Create a user, plus: a forwarding with the user as `source`, a forwarding
  with the user as `destination`, a sender-login with the user as
  `login_email`, and one with the user as `allowed_sender`.
- `DELETE /api/users/<email>` → 200; response carries `forwardings_deleted`
  and `sender_logins_deleted` with the expected counts.
- Subsequent `GET`/list confirms those forwardings and sender-logins are gone.

## Out of scope

- Changing `source`/`destination` to `user_id` (rejected — breaks alias-only
  forwardings and the Postfix pgsql lookup contract).
- DB-level triggers or `ON DELETE CASCADE`.
- Cleanup on **domain** delete (separate concern; not requested here).
