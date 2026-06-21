-- ⚠️ VENDORED TEST FIXTURE — NOT the source of truth.
-- This is a copy of the mail-server image's sql/schema.sql, kept here only so
-- the standalone integration tests can stand up a Postgres with the real
-- tables + the mail_admin_rw role. The authoritative schema lives in the
-- mail-server image (docker-images-homelab: images/mail-server/sql/schema.sql).
-- If that schema changes, refresh this copy.
--
-- mail-server schema (idempotent). Apply with:
--   psql "$DSN" -v ON_ERROR_STOP=1 -f sql/schema.sql
-- Safe to re-run: every object uses IF NOT EXISTS or a guarded DO block.
-- Column names follow the operator's Postgres migration (source/destination
-- forwardings, full-email users.email). See the design spec for the contract.

-- ── domains ────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS domains (
  id            bigserial PRIMARY KEY,
  domain        text UNIQUE NOT NULL,                 -- lowercase fqdn
  dkim_selector text   NOT NULL DEFAULT 'default',    -- selector published in DNS
  active        boolean NOT NULL DEFAULT true,
  created_at    timestamptz NOT NULL DEFAULT now()
);

-- ── users ──────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
  id          bigserial PRIMARY KEY,
  email       text UNIQUE NOT NULL,                   -- full lowercase addr == SASL login
  domain_id   bigint NOT NULL REFERENCES domains(id),
  password    text   NOT NULL,                        -- scheme-prefixed: {ARGON2ID}.. / {MD5-CRYPT}..
  quota_bytes bigint NOT NULL DEFAULT 0,              -- 0 = unlimited
  active      boolean NOT NULL DEFAULT true,
  created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS users_domain_id_idx ON users (domain_id);

-- ── forwardings ────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS forwardings (
  id          bigserial PRIMARY KEY,
  source      text NOT NULL,                          -- address mail arrives for
  destination text NOT NULL,                          -- where it is sent (1:N via rows)
  keep_copy   boolean NOT NULL DEFAULT false,         -- also deliver locally?
  active      boolean NOT NULL DEFAULT true,
  created_at  timestamptz NOT NULL DEFAULT now(),
  UNIQUE (source, destination)
);
CREATE INDEX IF NOT EXISTS forwardings_source_active_idx
  ON forwardings (source) WHERE active;

-- ── sender_login_maps (send-as delegation grants) ──────────────────────────
CREATE TABLE IF NOT EXISTS sender_login_maps (
  id             bigserial PRIMARY KEY,
  login_email    text NOT NULL,                       -- SASL login that is allowed to...
  allowed_sender text NOT NULL,                       -- ...send AS this address
  active         boolean NOT NULL DEFAULT true,
  created_at     timestamptz NOT NULL DEFAULT now(),
  UNIQUE (login_email, allowed_sender)
);
CREATE INDEX IF NOT EXISTS sender_login_maps_allowed_sender_active_idx
  ON sender_login_maps (allowed_sender) WHERE active;

-- ── audit_logs (full: auth + delivery + send) ──────────────────────────────
CREATE TABLE IF NOT EXISTS audit_logs (
  id          bigserial PRIMARY KEY,
  event_type  text NOT NULL,                          -- 'auth' | 'delivery' | 'send'
  success     boolean,                                -- auth outcome (null for delivery/send)
  login       text,                                   -- authenticated SASL user (if any)
  src_ip      inet,                                   -- real remote IP
  host        text,                                   -- this mail host
  sender      text,                                   -- envelope FROM (send/delivery)
  recipient   text,                                   -- envelope RCPT (send/delivery)
  message_id  text,
  queue_id    text,                                   -- Postfix queue-id, correlation key
  score       real,                                   -- Rspamd score (optional, send)
  msg         text,                                   -- free text / failure reason
  pid         int,
  "timestamp" timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS audit_logs_timestamp_idx ON audit_logs ("timestamp");
CREATE INDEX IF NOT EXISTS audit_logs_login_idx     ON audit_logs (login);

-- ── least-privilege roles ──────────────────────────────────────────────────
-- NOLOGIN group roles; the operator GRANTs them to the actual login roles
-- supplied via PG_USER / PG_AUDIT_USER and sets their passwords out-of-band.
-- CREATE ROLE has no IF NOT EXISTS, so guard each in a DO block for idempotency.
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'mail_ro') THEN
    CREATE ROLE mail_ro NOLOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'mail_audit') THEN
    CREATE ROLE mail_audit NOLOGIN;
  END IF;
END
$$;

-- mail_ro: SELECT on the lookup tables (Postfix pgsql maps + Dovecot passdb/userdb)
GRANT SELECT ON domains, users, forwardings, sender_login_maps TO mail_ro;

-- mail_audit: INSERT on audit_logs (+ usage of its id sequence for serial PK)
GRANT INSERT ON audit_logs TO mail_audit;
GRANT USAGE, SELECT ON SEQUENCE audit_logs_id_seq TO mail_audit;

-- mail_admin_rw: read-write management role used by the mail-admin image.
-- NOLOGIN group role; the operator GRANTs it to the actual PG_USER login role.
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'mail_admin_rw') THEN
    CREATE ROLE mail_admin_rw NOLOGIN;
  END IF;
END
$$;

-- full CRUD on the four management tables...
GRANT SELECT, INSERT, UPDATE, DELETE
  ON domains, users, forwardings, sender_login_maps TO mail_admin_rw;
-- ...read-only on the audit log...
GRANT SELECT ON audit_logs TO mail_admin_rw;
-- ...and USAGE on the id sequences so INSERT ... RETURNING id works.
GRANT USAGE, SELECT ON SEQUENCE
  domains_id_seq, users_id_seq, forwardings_id_seq, sender_login_maps_id_seq
  TO mail_admin_rw;
