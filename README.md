# mail-admin

A management companion for the `mail-server` image: a small Flask + gunicorn
HTTP API plus a `mailctl` CLI that perform RBAC-checked CRUD over the mail
server's **external PostgreSQL** database — `domains`, `users`, `forwardings`,
`sender_login_maps` — and read `audit_logs`. It is modelled on
[cert-hub](https://github.com/karol-siedlaczek/cert-hub) (Flask + gunicorn API,
Typer + Rich thin-client CLI, HMAC bearer auth with per-identity RBAC).

`mail-admin` and `mail-server` are deliberately decoupled: their **only shared
surface is the PostgreSQL schema** (owned by `mail-server`'s `sql/schema.sql`)
and the `{SCHEME}`-prefixed password format that Dovecot reads. `mail-admin`
never touches the mail daemons, the mail store, or the DKIM key files.

## Quick start

Generate the HMAC value for a token and add it to the server env first:

```bash
python mailctl.py token gen-hmac
# Follow the prompts; copy the TOKEN_<ID>_HMAC=<hex> line to the server env.
```

Run the API container:

```bash
docker run -d \
  -e HMAC_KEY_B64="$(openssl rand -base64 32)" \
  -e TOKEN_ADMIN_HMAC="<hex-from-gen-hmac>" \
  -e PG_HOST=postgres \
  -e PG_DBNAME=mail \
  -e PG_USER=mailadmin \
  -e PG_PASSWORD=<password> \
  -v /path/to/config.yaml:/config/config.yaml:ro \
  -p 8080:8080 \
  registry.siedlaczek.com.pl/mail-admin:latest
```

Or via Docker Compose alongside `mail-server`:

```yaml
services:
  mail-admin:
    image: registry.siedlaczek.com.pl/mail-admin:latest
    restart: unless-stopped
    ports:
      - "8080:8080"
    environment:
      HMAC_KEY_B64: <base64-key>
      TOKEN_ADMIN_HMAC: <hex-from-gen-hmac>
      PG_HOST: postgres
      PG_DBNAME: mail
      PG_USER: mailadmin
      PG_PASSWORD__FILE: /run/secrets/mailadmin_password
      PASSWORD_SCHEME: ARGON2ID
    secrets:
      - mailadmin_password
    volumes:
      - ./config.yaml:/config/config.yaml:ro
```

## Configuration

### Environment variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `HMAC_KEY_B64` | — (required) | Base64-encoded key (≥32 bytes decoded). Verifies each identity's `TOKEN_<ID>_HMAC`. Generate: `openssl rand -base64 32`. |
| `TOKEN_<ID>_HMAC` | — | Per-identity HMAC hex: `HMAC-SHA256(raw-token, key)`. One variable per identity declared in `config.yaml`. |
| `CONF_FILE` | `/config/config.yaml` | Path to the identities + settings file (must be mounted). |
| `PG_HOST` | — (required) | External Postgres host. |
| `PG_PORT` | `5432` | Postgres port. |
| `PG_DBNAME` | — (required) | Postgres database. |
| `PG_USER` | — (required) | Login role with the `mail_admin_rw` group role (see Database role). |
| `PG_PASSWORD` / `PG_PASSWORD__FILE` | — | Password for `PG_USER`. `PG_PASSWORD__FILE` is read from a file (Docker secrets). |
| `PASSWORD_SCHEME` | `ARGON2ID` | Hashing scheme for new passwords. Supported: `ARGON2ID`, `BLF-CRYPT`. |
| `LOG_LEVEL` | `INFO` | Log verbosity: `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`. |
| `LOGS_DIR` | `/logs` | Directory for log files. |

`HMAC_KEY_B64`, `PG_HOST`, `PG_DBNAME`, and `PG_USER` are required; the
container will refuse to start if they are absent.

### config.yaml

Mount a `config.yaml` at `CONF_FILE` (default `/config/config.yaml`) declaring
the identities the API will accept. Each identity has an `id`, a list of
allowed source CIDRs, and a list of `<domain-pattern>:<action>` permissions:

```yaml
identities:
  - id: admin
    allowed_cidrs: ["10.0.0.0/8", "127.0.0.1/32"]
    permissions: ["*:write"]
  - id: artform
    allowed_cidrs: ["10.20.0.0/16"]
    permissions: ["artformstudio.pl:write"]
```

## Database role

`mail-server`'s `sql/schema.sql` creates a NOLOGIN group role `mail_admin_rw`
with full CRUD on the four management tables and SELECT on `audit_logs`:

```sql
-- created by sql/schema.sql (excerpt):
CREATE ROLE mail_admin_rw NOLOGIN;
GRANT SELECT, INSERT, UPDATE, DELETE
  ON domains, users, forwardings, sender_login_maps TO mail_admin_rw;
GRANT SELECT ON audit_logs TO mail_admin_rw;
GRANT USAGE, SELECT ON SEQUENCE
  domains_id_seq, users_id_seq, forwardings_id_seq, sender_login_maps_id_seq
  TO mail_admin_rw;
```

After applying the schema, the operator creates a login role and grants it the
group:

```sql
CREATE ROLE mailadmin LOGIN PASSWORD '...';
GRANT mail_admin_rw TO mailadmin;
```

Set `PG_USER=mailadmin` and `PG_PASSWORD` (or `PG_PASSWORD__FILE`) accordingly.

## Authentication & authorization

**Token format:** `Authorization: Bearer <id>.<token>`

A request authenticates when:
1. `<id>` resolves to an identity declared in `config.yaml`.
2. `HMAC-SHA256(token, key) == TOKEN_<ID>_HMAC` (where `key` is the decoded
   `HMAC_KEY_B64`).
3. The source IP is inside one of the identity's `allowed_cidrs`.

**Permissions** are `<domain-pattern>:<action>`, where `action` is `read` or
`write`. `write` implies create/update/delete and also implies `read`. The
pattern may be `*` (full admin) or a glob like `*.example.com`.

Every request resolves to a **target domain** and is checked against the
identity's permissions:

| Resource | Domain resolved |
|----------|----------------|
| domain `d` | `d` |
| user `local@d` | `d` |
| forwarding (source `s@d`) | `d` (source domain) |
| sender_login (`allowed_sender a@d`) | `d` |
| audit row | domain of its `login` (rows with no domain require `*:read`) |

## API surface

Base URL: `http://<host>:8080`

### Unauthenticated

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/ping` | Liveness probe; returns `pong`. |
| `GET` | `/api/version` | Name, version, Python version. |

### Token introspection (authenticated)

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/token/identity` | Current identity: id, allowed CIDRs, permissions. |
| `GET` | `/api/token/scope` | Permissions list for the current identity. |

### Domains

| Method | Path | Body / query | Description |
|--------|------|-------------|-------------|
| `GET` | `/api/domains` | — | List domains (filtered to readable). |
| `POST` | `/api/domains` | `{domain, dkim_selector?, active?}` | Create a domain. Returns 201. |
| `GET` | `/api/domains/<domain>` | — | Get a domain. |
| `PATCH` | `/api/domains/<domain>` | `{dkim_selector?, active?}` | Update dkim_selector / active. |
| `DELETE` | `/api/domains/<domain>` | — | Delete a domain. |

### Users (mailboxes)

| Method | Path | Body / query | Description |
|--------|------|-------------|-------------|
| `GET` | `/api/users` | `?domain=` | List mailboxes (filtered to readable). |
| `POST` | `/api/users` | `{email, password, quota_bytes?, active?}` | Create a mailbox. Password is hashed server-side and never returned. Returns 201. |
| `GET` | `/api/users/<email>` | — | Get a mailbox (password hash is never returned). |
| `PATCH` | `/api/users/<email>` | `{quota_bytes?, active?}` | Update quota / active. |
| `POST` | `/api/users/<email>/password` | `{password}` | Set / reset a password. |
| `DELETE` | `/api/users/<email>` | — | Delete a mailbox. |

### Forwardings

| Method | Path | Body / query | Description |
|--------|------|-------------|-------------|
| `GET` | `/api/forwardings` | `?source=&domain=` | List forwardings (filtered to readable). |
| `POST` | `/api/forwardings` | `{source, destination, keep_copy?}` | Create a forwarding. Returns 201. |
| `DELETE` | `/api/forwardings/<id>` | — | Delete a forwarding by integer id. |

### Sender-logins (send-as grants)

| Method | Path | Body / query | Description |
|--------|------|-------------|-------------|
| `GET` | `/api/sender-logins` | `?domain=` | List send-as grants (filtered to readable). |
| `POST` | `/api/sender-logins` | `{login_email, allowed_sender}` | Grant: `login_email` may send as `allowed_sender`. Returns 201. |
| `DELETE` | `/api/sender-logins/<id>` | — | Revoke a grant by integer id. |

### Audit log

| Method | Path | Body / query | Description |
|--------|------|-------------|-------------|
| `GET` | `/api/audit` | `?login=&event_type=&since=&limit=` | Read audit log (filtered to readable; default limit 100, max 1000). |

**Error responses** follow the standard envelope:
`{msg, detail, code, timestamp}`. Schema violations surface as `422`, UNIQUE
conflicts as `409 Conflict`, missing domain FK as `422`, missing resources as
`404`, auth failures as `401`/`403`.

## CLI (`mailctl`)

`mailctl` is a Typer + Rich thin client over the API. It ships inside the image
at `/app/mailctl.py` and can also be run standalone (only needs `requests`,
`typer`, `rich`).

### Command tree

```
mailctl [--api-url URL] [--token TOKEN] [--format FORMAT]
  domain  list|add|show|set|rm
  user    list|add|show|passwd|set|rm
  forward list|add|rm
  sendas  list|grant|revoke
  audit   [--login LOGIN] [--type EVENT_TYPE] [--since SINCE] [--limit N]
  token   identity|scope|gen-hmac
  version
```

### Settings resolution

Settings are resolved in this order (highest priority first):

1. CLI flags (`--api-url`, `--token`, `--log-file`, `--log-level`).
2. Environment variables: `MAILADMIN_API_URL`, `MAILADMIN_TOKEN`,
   `MAILADMIN_LOG_FILE`, `MAILADMIN_LOG_LEVEL`.
3. `~/.mailctl` file (must have mode **600**). Key-value format:

```ini
API_URL=http://mail-admin.internal:8080
TOKEN=admin.my-secret-token
LOG_FILE=/var/log/mailctl.log
LOG_LEVEL=INFO
```

Output formats via `-f`: `table` (default), `json`, `kv`, `value`.
Column selection via `-c`/`--column` (repeatable).
Passwords are never echoed; they are read via a confirm prompt when omitted.

### Example session

```bash
# Add a domain
mailctl domain add artformstudio.pl --dkim-selector default

# Create a mailbox (password prompted)
mailctl user add info@artformstudio.pl

# Forward mail, keeping a local copy
mailctl forward add newsletter@artformstudio.pl archive@example.com --keep-copy

# Grant send-as
mailctl sendas grant info@artformstudio.pl noreply@artformstudio.pl

# Generate a TOKEN_<ID>_HMAC line for a new identity
mailctl token gen-hmac --id artform --hmac-key-b64 "$(openssl rand -base64 32)"

# Read the last 20 audit entries for a login
mailctl audit --login info@artformstudio.pl --limit 20

# JSON output
mailctl domain list -f json
```

## Build & test

```bash
make -C images/mail-admin build   # build Docker image
make -C images/mail-admin test    # run unit tests (pytest)
make -C images/mail-admin itest   # run integration tests (postgres:16 + compose)
make -C images/mail-admin lint    # ruff + mypy
```

Tests live in `images/mail-admin/tests/`.

## CI / publishing

No workflow changes required. Push a `mail-admin/vX.Y.Z` tag to trigger the
existing pipeline:

```bash
git tag mail-admin/v0.1.0
git push origin mail-admin/v0.1.0
```

The pipeline builds a multi-arch (`linux/amd64`, `linux/arm64`) image and pushes
the following tags to `registry.siedlaczek.com.pl`:

- `mail-admin:<version>` (e.g. `mail-admin:0.1.0`)
- `mail-admin:<major.minor>` (e.g. `mail-admin:0.1`)
- `mail-admin:latest`
- `mail-admin:<short-sha>`

No build variants. To rebuild an existing tag, move and force-push it:

```bash
git tag -f mail-admin/v0.1.0
git push -f origin mail-admin/v0.1.0
```
