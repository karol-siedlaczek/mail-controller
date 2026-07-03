# Mail Controller

A management companion for the `mail-server` image from the [mail-server](https://github.com/karol-siedlaczek/mail-server) repo. It exposes a Flask + gunicorn HTTP API plus a `mailctl` CLI that perform RBAC-checked CRUD over that mail server's **external PostgreSQL** database - `domains`, `users`, `forwardings`, `sender_login_maps` - and read `audit_logs`.

## Development
### 1) Requirements
- Python `3.12+`
- A reachable PostgreSQL database with the `mail-server` schema applied and a login role holding `mail_admin_rw` (see [Database role](#database-role))

### 2) Install dependencies
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 3) Environment configuration
Minimal setup:
```bash
export HMAC_KEY_B64="<HMAC_KEY>"      # Generate key using: openssl rand -base64 32
export TOKEN_ADMIN_HMAC="<hex_hmac>"  # Per-identity token HMAC, see: python mailctl.py token gen-hmac
export PG_HOST="127.0.0.1"
export PG_DBNAME="mail"
export PG_USER="mailadmin"
export PG_PASSWORD="<password>"
```

For local development it is also recommended to change environments that point to files or directories, because default values are predefined for docker container, e. g.:
```bash
export CONF_FILE="$(pwd)/config.yaml"
export LOGS_DIR="$(pwd)/logs"
```

### 4) Start the application
```bash
gunicorn wsgi:app -c gunicorn.conf.py
```

Quick test:
```bash
curl -s http://127.0.0.1:8080/ping
```

## Production
### Docker (`docker run`)
Build image:
```bash
docker build -t mail-controller:latest .
```

Run container:
```bash
docker run -d \
  --name mail-controller \
  -p 8080:8080 \
  -e HMAC_KEY_B64="<HMAC_KEY>" \
  -e TOKEN_ADMIN_HMAC="<hex_hmac>" \
  -e PG_HOST="postgres" \
  -e PG_DBNAME="mail-server" \
  -e PG_USER="mail-controller_user" \
  -e PG_PASSWORD="<password>" \
  -e CONF_FILE="/config/config.yaml" \
  -e LOGS_DIR="/logs" \
  -v "$(pwd)/config.yaml:/config/config.yaml:ro" \
  -v "$(pwd)/logs:/logs" \
  mail-controller:latest
```

Stop and remove:
```bash
docker stop mail-controller && docker rm mail-controller
```

### Docker Compose
Example `compose.yml` (alongside `mail-server`):
```yaml
services:
  mail-controller:
    image: registry.siedlaczek.com.pl/mail-controller:latest
    container_name: mail-controller
    restart: unless-stopped
    ports:
      - "8080:8080"
    environment:
      HMAC_KEY_B64: ${HMAC_KEY_B64}
      TOKEN_ADMIN_HMAC: ${TOKEN_ADMIN_HMAC}
      PG_HOST: postgres
      PG_DBNAME: mail
      PG_USER: mail-controller_user
      PG_PASSWORD__FILE: /run/secrets/mail-controller_password
      PASSWORD_SCHEME: ARGON2ID
    secrets:
      - mail-controller_password
    volumes:
      - ./config.yaml:/config/config.yaml:ro
      - ./logs:/logs
```

Set required environment:
```bash
export HMAC_KEY_B64="<HMAC_KEY>"
export TOKEN_ADMIN_HMAC="<hex_hmac>"
```

Build and start:
```bash
docker compose up -d
```

Check logs:
```bash
docker compose logs -f mail-controller
```

Stop:
```bash
docker compose down
```

## Environments
| Key | Type | Required | Default | Description |
|:----|:-----|:---------|:--------|:------------|
| `GUNICORN_BIND_IP` | `string` | :x: | `0.0.0.0` | Gunicorn bind IP |
| `GUNICORN_BIND_PORT` | `number` | :x: | `8080` | Gunicorn bind port |
| `GUNICORN_WORKERS` | `number` | :x: | `1` | Number of Gunicorn workers |
| `GUNICORN_THREADS` | `number` | :x: | `4` | Threads per Gunicorn worker |
| `GUNICORN_TIMEOUT` | `number` | :x: | `60` | Request timeout in seconds |
| `LOG_LEVEL` | `string` | :x: | `INFO` | Log level (`DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`) |
| `LOGS_DIR` | `string` | :x: | `/logs` | Application logs directory (`app.log`) |
| `CONF_FILE` | `string` | :x: | `/config/config.yaml` | Path to YAML config with identities and settings |
| `HMAC_KEY_B64` | `string` | :heavy_check_mark: | - | Base64 HMAC key (minimum 32 bytes after decoding), used to verify each identity's `TOKEN_<ID>_HMAC`. Generate: `openssl rand -base64 32` |
| `TOKEN_<ID>_HMAC` | `string` | :x: | - | Token HMAC-SHA256 (hex) for identity `<ID>` from `config.yaml`. One variable per declared identity; not strictly required to start, but you want at least one identity |
| `PG_HOST` | `string` | :heavy_check_mark: | - | External Postgres host |
| `PG_PORT` | `number` | :x: | `5432` | Postgres port |
| `PG_DBNAME` | `string` | :heavy_check_mark: | - | Postgres database name |
| `PG_USER` | `string` | :heavy_check_mark: | - | Login role holding the `mail_admin_rw` group role (see [Database role](#database-role)) |
| `PG_PASSWORD` | `string` | :x: | - | Password for `PG_USER` |
| `PG_PASSWORD__FILE` | `string` | :x: | - | Path to a file containing the password for `PG_USER` (Docker secrets); alternative to `PG_PASSWORD` |
| `PASSWORD_SCHEME` | `string` | :x: | `ARGON2ID` | Hashing scheme for new mailbox passwords (`ARGON2ID`, `BLF-CRYPT`) |
| `TRUSTED_PROXY_HOPS` | `number` | :x: | `0` | Number of trusted reverse-proxy hops (integer ≥ 0). `0` ignores `X-Forwarded-For` and uses the direct TCP peer for the IP allowlist (`allowed_cidrs`) — spoof-safe. Trusts only the N rightmost `X-Forwarded-For` entries. |

`HMAC_KEY_B64`, `PG_HOST`, `PG_DBNAME`, and `PG_USER` are required; the container will refuse to start if they are absent.

> **Behind a reverse proxy** (nginx/HAProxy), set `TRUSTED_PROXY_HOPS` to the number of proxies in front of mail-controller (usually `1`). If left at the default `0`, the IP allowlist sees the proxy's IP instead of the client's and rejects legitimate requests (fails closed). Never set it higher than the actual proxy count, or clients could spoof `X-Forwarded-For`.

## Configuration
`CONF_FILE` is a YAML file defining the identities (`identities`) the API will accept.

Example:
```yaml
identities:
  - id: "admin"
    allowed_cidrs:
      - "10.0.0.0/8"
      - "127.0.0.1/32"
    permissions:
      - "*:*"
  - id: "example"
    allowed_cidrs:
      - "10.20.0.0/16"
    permissions:
      - "example.com:*"
      - "*.example.com:read_domain"
  - id: "reader"
    allowed_cidrs:
      - "0.0.0.0/0"
    permissions:
      - "*:read_audit"
```

### Field meanings

- `identities[].id` - identity identifier used in token format `Bearer <id>.<token>` (must match `^[A-Za-z_0-9]+$`).
- `identities[].allowed_cidrs` - CIDR list allowed to make requests for this identity (IPv4 or IPv6).
- `identities[].permissions` - permission entries in `"<scope>:<action>"` format, where:
  - `scope` - `*` (full admin), an exact domain matched case-insensitively (e. g. `example.com`), or a `*.<domain>` wildcard matching exactly one label below it (e. g. `*.example.com` matches `a.example.com` but not `example.com` or `a.b.example.com`).
  - `action` - one of the per-entity actions, or `*` (all actions for the scope):
    - `read_domain` / `write_domain`
    - `read_user` / `write_user`
    - `read_forwarding` / `write_forwarding`
    - `read_sender_login` / `write_sender_login`
    - `read_audit` (read-only)
    - `read_metrics` (read-only; gates `/api/metrics`)
    - each `write_<entity>` implies `read_<entity>`.
  - **Breaking change:** the legacy generic `read` / `write` actions are no longer valid; migrate to the per-entity actions above (or `*` for full control over a scope).

If you have identities such as `admin` and `example`, you must provide following environments:
```ini
TOKEN_ADMIN_HMAC="<hex_hmac>"
TOKEN_EXAMPLE_HMAC="<hex_hmac>"
```

### How to generate `HMAC_KEY_B64`
```bash
openssl rand -base64 32
```

### How to generate `TOKEN_<ID>_HMAC`
Use the built-in CLI command:
```bash
# Variables can be provided by flags (use --help to show) or by prompt if any required variable is missing
python mailctl.py token gen-hmac --id admin --hmac-key-b64 "$HMAC_KEY_B64"
```

CLI will print a ready-to-use value:
```ini
TOKEN_ADMIN_HMAC=<hex_hmac>
```

## Database role
`mail-server`'s `sql/schema.sql` creates a NOLOGIN group role `mail-server_admin` with full CRUD on the four management tables and SELECT on `audit_logs`:

```sql
CREATE ROLE "mail-server-admin" NOLOGIN;
GRANT SELECT, INSERT, UPDATE, DELETE
  ON domains, users, forwardings, sender_login_maps TO 'mail-server-admin';
GRANT SELECT ON audit_logs TO 'mail-server-admin';
GRANT USAGE, SELECT ON SEQUENCE
  domains_id_seq, users_id_seq, forwardings_id_seq, sender_login_maps_id_seq
  TO 'mail-server-admin';
```

After applying the schema, the operator creates a login role and grants it the group:

```sql
CREATE ROLE mail_admin LOGIN PASSWORD '...';
GRANT 'mail-server-admin_user' TO "mail-server_admin";
```

Set `PG_USER=mail-server-admin_user` and `PG_PASSWORD` (or `PG_PASSWORD__FILE`) accordingly.

## API
Required authorization header:
```http
Authorization: Bearer <identity_id>.<token_raw>
```

A request authenticates when:
1. `<identity_id>` resolves to an identity declared in `config.yaml`.
2. `HMAC-SHA256(token_raw, key) == TOKEN_<ID>_HMAC` (where `key` is the decoded `HMAC_KEY_B64`).
3. The source IP is inside one of the identity's `allowed_cidrs`.

Every request resolves to a **target domain** (the domain of the resource) and is authorized against the identity's permissions: `write` implies create/update/delete and also implies `read`.

Endpoints:
| Method | Endpoint | Auth required | Body | Query params | Description |
|:-------|:---------|:--------------|:-----|:-------------|:------------|
| `GET` | `/ping` | :x: | - | - | Liveness probe; returns `pong` |
| `GET` | `/api/version` | :x: | - | - | Returns app metadata (name, author, app version, Python version). |
| `GET` | `/api/token/identity` | :heavy_check_mark: | - | - | Current identity: id, allowed CIDRs and permissions |
| `GET` | `/api/token/scope` | :heavy_check_mark: | - | - | Permission list for the current identity |
| `GET` | `/api/domains` | :heavy_check_mark: | - | - | List domains (filtered to those the identity can read) |
| `POST` | `/api/domains` | :heavy_check_mark: | `{domain, dkim_selector?, active?}` | - | Create a domain (→ `201`) |
| `GET` | `/api/domains/<domain>` | :heavy_check_mark: | - | - | Get a single domain |
| `PATCH` | `/api/domains/<domain>` | :heavy_check_mark: | `{dkim_selector?, active?}` | - | Update a domain's DKIM selector and/or active flag |
| `DELETE` | `/api/domains/<domain>` | :heavy_check_mark: | - | - | Delete a domain |
| `GET` | `/api/users` | :heavy_check_mark: | - | `domain` | List mailboxes (optionally filtered by domain) |
| `POST` | `/api/users` | :heavy_check_mark: | `{email, password, quota_bytes?, active?}` | - | Create a mailbox (password hashed server-side, → `201`) |
| `GET` | `/api/users/<email>` | :heavy_check_mark: | - | - | Get a single mailbox |
| `PATCH` | `/api/users/<email>` | :heavy_check_mark: | `{quota_bytes?, active?}` | - | Update a mailbox's quota and/or active flag |
| `POST` | `/api/users/<email>/password` | :heavy_check_mark: | `{password}` | - | Set/reset a mailbox password |
| `DELETE` | `/api/users/<email>` | :heavy_check_mark: | - | - | Delete a mailbox |
| `GET` | `/api/forwardings` | :heavy_check_mark: | - | `source`, `domain` | List forwardings (optionally filtered by source/domain) |
| `POST` | `/api/forwardings` | :heavy_check_mark: | `{source, destination, keep_copy?}` | - | Create a forwarding from `source` to `destination` (→ `201`) |
| `GET` | `/api/forwardings/<id>` | :heavy_check_mark: | - | - | Get a single forwarding by id |
| `PATCH` | `/api/forwardings/<id>` | :heavy_check_mark: | `{source?, destination?, keep_copy?, active?}` | - | Update a forwarding's source, destination, keep-copy and/or active flag |
| `DELETE` | `/api/forwardings/<id>` | :heavy_check_mark: | - | - | Delete a forwarding by id |
| `GET` | `/api/sender-logins` | :heavy_check_mark: | - | `domain` | List send-as grants (optionally filtered by domain) |
| `POST` | `/api/sender-logins` | :heavy_check_mark: | `{login_email, allowed_sender}` | - | Grant `login_email` permission to send as `allowed_sender` (→ `201`) |
| `DELETE` | `/api/sender-logins/<id>` | :heavy_check_mark: | - | - | Revoke a send-as grant by id |
| `GET` | `/api/audit` | :heavy_check_mark: | - | `login`, `event_type`, `since`, `limit` | Read the audit log (filtered to readable rows) |

Notes:
- `password` is hashed server-side and never returned; the password hash is never included in any user response.
- `/api/audit`: `limit` defaults to `100`, max `1000`. Audit rows with no `login` (no domain) require `*:read_audit`.
- **Error responses** follow the standard envelope: `{method, http_code, http_status, path, message, detail, data, timestamp}`. Schema violations and missing-domain FK surface as `422`, UNIQUE conflicts as `409`, missing resources as `404`, auth failures as `401`/`403`.
- Deleting a domain that still has mailboxes is rejected with `409` (the foreign key from `users` blocks it); remove the mailboxes first. Deleting a mailbox cascades: forwardings and send-as grants referencing that address are removed too.

Examples:
```bash
curl -s \
  -H "Authorization: Bearer admin.my-raw-token" \
  "http://127.0.0.1:8080/api/domains"

curl -s \
  -X POST \
  -H "Authorization: Bearer admin.my-raw-token" \
  -H "Content-Type: application/json" \
  -d '{"domain": "artformstudio.pl", "dkim_selector": "default"}' \
  "http://127.0.0.1:8080/api/domains"
```

## CLI (`mailctl.py`)
`mailctl` is a Typer + Rich thin client over the API. It ships inside the image at `/app/mailctl.py` and can also be run standalone (needs `requests`, `typer`, `rich`).

Command tree:
```text
mailctl
├── version                         Show app/CLI versions and author
├── token                           Manage token identity
│   ├── identity                    Show current identity (allowed CIDRs, permissions)
│   ├── scope                       List permissions for the current identity
│   └── gen-hmac                    Generate a TOKEN_<ID>_HMAC value for server configuration
├── domain                          Manage domains
│   ├── list                        List domains readable by the current identity
│   ├── add                         Create a domain
│   ├── show                        Show a single domain
│   ├── set                         Update a domain's DKIM selector and/or active flag
│   └── rm                          Delete a domain
├── user                            Manage mailboxes
│   ├── list                        List mailboxes (optionally filtered by domain)
│   ├── add                         Create a mailbox (password prompted if omitted)
│   ├── show                        Show a single mailbox
│   ├── passwd                      Set/reset a mailbox password
│   ├── set                         Update a mailbox's quota and/or active flag
│   └── rm                          Delete a mailbox
├── forward                         Manage forwardings
│   ├── list                        List forwardings (optionally filtered by source/domain)
│   ├── add                         Create a forwarding from source to destination
│   ├── show                        Show a single forwarding by id
│   ├── set                         Update a forwarding's source, destination, keep-copy and/or active flag
│   └── rm                          Delete a forwarding by id
├── sendas                          Manage send-as grants
│   ├── list                        List send-as grants (optionally filtered by domain)
│   ├── grant                       Grant a login the right to send as another address
│   └── revoke                      Revoke a send-as grant by id
└── audit                           Read the audit log (optionally filtered)
```
Run `mailctl --help`, or `mailctl <group> --help` / `mailctl <group> <command> --help`, to see all options for each command.

Each subcommand accepts `-t/--timeout` (default `10`), `-f/--format` (`table` (default), `json`, `kv`, `value`) and `-c/--column` (repeatable). Passwords are never echoed; they are read via a confirm prompt when omitted.

- **Delete/revoke confirmation:** `domain rm`, `user rm`, `forward rm` and `sendas revoke` prompt for a `[y/N]` confirmation before acting. Pass `-y/--yes` to skip it (for automation). In a non-interactive shell the command aborts unless `--yes` is given, so it never deletes unattended by accident.
- **Quota display:** `user` commands render `quota` in human-readable units (`B`/`KB`/`MB`/`GB`/`TB`, `0` shown as `unlimited`). Pass `--raw-quota` to show the raw `quota_bytes` integer instead. Input quotas (`--quota`) still accept a unit, e. g. `256MB`, `2GB`.
- **Single-record layout:** commands that act on one record (`add`, `show`, `set`, `rm`, `user password`, `sendas grant/revoke`) render the `table` format vertically as a two-column `Field` / `Value` table, one row per field. `list` commands keep the classic horizontal table (one column per field). `json`/`kv`/`value` output is unaffected.

Example usage:
```bash
export MAILCTL_API_URL="http://127.0.0.1:8080"
export MAILCTL_TOKEN="admin.my-raw-token"

# Add a domain
mailctl domain add example.com --dkim-selector default

# Create a mailbox (password prompted)
mailctl user add info@example.com

# Forward mail, keeping a local copy
mailctl forward add info@example.com example@gmail.com --keep-copy

# Inspect then update a forwarding (e. g. stop keeping a local copy)
mailctl forward show 42
mailctl forward set 42 --no-keep-copy

# Grant send-as
mailctl sendas grant info@example.com noreply@example.com

# Read the last 20 audit entries for a login
mailctl audit --login info@example.com --limit 20

# JSON output
mailctl domain list -f json
```

Settings are resolved in this order (highest priority first):

1. CLI flags (`--api-url`, `--token`, `--log-file`, `--log-level`).
2. Environment variables: `MAILCTL_API_URL`, `MAILCTL_TOKEN`, `MAILCTL_LOG_FILE`, `MAILCTL_LOG_LEVEL`.
3. `~/.mailctl` file (must have `600` permissions, `chmod 600 ~/.mailctl`):

```ini
API_URL=http://127.0.0.1:8080
TOKEN=admin.my-secret-token
LOG_FILE=/var/log/mailctl.log
LOG_LEVEL=INFO
```

## Build & test
A `Makefile` wraps the common build and test entrypoints. Run them from the repo root with `make <target>`:

| Target | Description |
|:-------|:------------|
| `make build` | Build the Docker image (tagged `mail-controller:test` by default) |
| `make venv` | Create the test virtualenv in `tests/.venv` and install `tests/requirements.txt` (other targets depend on it) |
| `make test` | Run the unit tests (`pytest`, no Docker) — everything not marked `integration` |
| `make itest` | Run the integration tests: build the image, bring up the compose stack (`tests/compose.test.yml` with `postgres:16`), run the `integration` tests, then tear the stack down |
| `make lint` | Validate `docker compose config` and `py_compile` of `mailctl.py`, `wsgi.py`, `gunicorn.conf.py` and the `mail_controller` package |
| `make clean` | Tear down the compose stack and remove the virtualenv and pytest cache |

`IMAGE`, `PYTEST` and `PYTEST_FLAGS` can be overridden on the command line, e. g. `make build IMAGE=mail-controller:dev`. The integration tests apply a vendored copy of the `mail-server` schema (`tests/schema.sql`, which declares the `mail_admin_rw` role — see [Database role](#database-role)).

## Recommendations
- Store `HMAC_KEY_B64` and all `TOKEN_<ID>_HMAC` values in a secret manager.
- Restrict `allowed_cidrs` to trusted source networks.
- Use `PG_PASSWORD__FILE` (Docker secrets) instead of `PG_PASSWORD` in production.
- Keep `CONF_FILE` and `LOGS_DIR` on persistent storage.
- Put a reverse proxy (Nginx/HAProxy) in front of the app (the app trusts `X-Forwarded-*` for one proxy).
- Validate config before restart:
```bash
gunicorn wsgi:app --check-config
```

## Notes
- Application logs are written to `${LOGS_DIR}/app.log`; gunicorn access and error logs go to stdout/stderr.
- This project manages the `mail-server` image maintained in the [mail-server](https://github.com/karol-siedlaczek/mail-server) repo. `mail-controller` and `mail-server` are deliberately decoupled: their **only shared surface is the PostgreSQL schema** (owned by `mail-server`'s `sql/schema.sql`) and the `{SCHEME}`-prefixed password format Dovecot reads. `mail-controller` never touches the mail daemons, the mail store, or the DKIM key files.

## Publishing Docker image

The CI/CD pipeline (`.github/workflows/docker-publish.yml`) builds and pushes the Docker image only when a git tag matching `v*` is pushed.

Push without tag (no image build):
```bash
git add .
git commit -m "your message"
git push origin main
```

Push with tag (triggers image build and push):
```bash
git add .
git commit -m "your message"
git push origin main
git tag v1.0.1
git push origin v1.0.1
```

It builds a multi-arch (`linux/amd64`, `linux/arm64`) image and pushes the following tags to `registry.siedlaczek.com.pl`:
- `mail-controller:1.0.1`
- `mail-controller:1.0`
- `mail-controller:latest`
- `mail-controller:<short-sha>`

To rebuild an existing tag, move and force-push it:
```bash
git tag -f v1.0.1
git push -f origin v1.0.1
```
