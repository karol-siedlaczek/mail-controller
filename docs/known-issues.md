# Known issues — low-priority bug backlog

Found during the 2026-06-28 application bug hunt. These are real but low-impact;
deferred from the critical/medium fix plan
(`docs/superpowers/plans/2026-06-28-bug-fixes.md`). Each entry notes the agreed
approach where one was decided.

## 1. `json_body_field` boolean coercion accepts truthy strings
- **Where:** `mail_controller/api/routes.py` (`bool(active)` / `bool(keep_copy)` pattern, lines ~127, 213, 252, 322) via `validators.json_body_field`.
- **Problem:** A client sending a JSON string `"active": "false"` (instead of the JSON boolean `false`) yields `bool("false") == True`. `query_bool` validates such values; the JSON-body path does not. The `mailctl` CLI sends real JSON booleans, so only foreign/hand-rolled clients are affected.
- **Suggested fix:** Add a `cast_fn` (or a `json_body_bool` helper) that parses booleans with the same accepted-values logic as `query_bool`, and use it for `active`/`keep_copy`.

## 2. Existence oracle in delete endpoints (404 before permission check)
- **Where:** `mail_controller/api/routes.py` — `forwarding_delete` (~line 339) and `sender_login_delete` (~line 392).
- **Problem:** Both look up the target and raise `ResourceNotFoundError` (404) *before* `ctx.require(...)`. A caller without permission on the target's domain gets 403 when the id exists and 404 when it does not, disclosing existence of ids in domains they cannot access.
- **Suggested fix:** Decide the order policy. Simplest: keep behavior (low impact, only reveals integer-id existence), or return 404 in both cases for unauthorized callers (uniform response) — note this requires care not to leak via timing.

## 3. `query_int` / `query_str` treat a falsy `default` as "no default"
- **Where:** `mail_controller/api/validators.py` — `query_str` (~line 46), `query_int` (~line 91): `elif default: return default`.
- **Problem:** A caller passing `default=0` or `default=""` gets `None` instead of the supplied default, because the guard tests truthiness rather than `is not None`. Latent — no current caller passes a falsy default (`audit` uses `default=100`).
- **Suggested fix:** Change `elif default:` to `elif default is not None:` in both helpers.

## 4. bcrypt silently truncates passwords > 72 bytes
- **Where:** `mail_controller/security/password.py` (`hash_password` ~line 19, `verify_password` ~line 34) for the BLF-CRYPT scheme.
- **Problem:** bcrypt ignores bytes past 72, so two distinct long passwords sharing a 72-byte prefix authenticate interchangeably.
- **Decided approach:** **Reject passwords longer than 72 bytes** with a clear validation error at hash time. Do NOT pre-hash (e.g. SHA-256-then-bcrypt) — Dovecot reads these hashes and also truncates at 72, so pre-hashing would break verification compatibility. Rejecting is the only safe option that keeps Dovecot parity.
- **Suggested fix:** In `hash_password`, when scheme is BLF-CRYPT and `len(password.encode("utf-8")) > 72`, raise `ValidationError`. Add a unit test in `tests/test_password.py`.

## 5. `Require.one_of` / `not_one_of` crash on non-string allowed values
- **Where:** `mail_controller/validation/require.py:213` and `:226` — `", ".join(allowed_values)`.
- **Problem:** On the error branch, if `allowed_values` contains non-strings (e.g. integer identity ids passed in `config.py` ~line 106), the join raises `TypeError`, masking the intended `ValidationError`.
- **Suggested fix:** `", ".join(str(v) for v in allowed_values)` in both methods.

## 6. `~/.mailctl` permission check rejects safer modes
- **Where:** `mailctl.py` (settings-file load, the `mode != 0o600` check).
- **Problem:** Exactly `0o600` is required; a stricter `0o400` (read-only) is rejected with "expected 600". Errs safe but is over-strict.
- **Suggested fix:** Reject only if group/other bits are set, e.g. `if mode & 0o077:` instead of `mode != 0o600`.
