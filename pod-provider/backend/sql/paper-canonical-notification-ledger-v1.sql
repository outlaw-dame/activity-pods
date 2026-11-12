-- Canonical notification record + leased delivery work (v1).
-- Run as a migration administrator; never with the application's login.
-- The durable notification record is written BEFORE acknowledging Kafka.
-- An activity emitted to a Pod inbox is an idempotently-addressed projection
-- of this record, not the sole copy of the notification.
CREATE SCHEMA IF NOT EXISTS paper_notification_ledger;
REVOKE ALL ON SCHEMA paper_notification_ledger FROM PUBLIC;

CREATE TABLE IF NOT EXISTS paper_notification_ledger.intents (
  intent_key bytea PRIMARY KEY CHECK (octet_length(intent_key)=32),
  intent_id text NOT NULL CHECK (length(intent_id) BETWEEN 1 AND 512),
  payload_sha256 bytea NOT NULL CHECK (octet_length(payload_sha256)=32),
  notification_kind text NOT NULL CHECK (length(notification_kind) BETWEEN 1 AND 64),
  source_protocol text NOT NULL CHECK (source_protocol IN ('activitypub','atproto','activitypods')),
  recipient_count integer NOT NULL CHECK (recipient_count BETWEEN 0 AND 64),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE IF NOT EXISTS paper_notification_ledger.deliveries (
  intent_key bytea NOT NULL REFERENCES paper_notification_ledger.intents(intent_key),
  recipient_key bytea NOT NULL CHECK (octet_length(recipient_key)=32),
  recipient_webid text NOT NULL CHECK (length(recipient_webid) BETWEEN 1 AND 2048),
  activity_json jsonb NOT NULL,
  state text NOT NULL DEFAULT 'pending'
    CHECK (state IN ('pending','leased','delivered','dead')),
  attempts integer NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 8),
  next_attempt_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  lease_token uuid,
  lease_until timestamptz,
  delivered_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (intent_key,recipient_key),
  CHECK ((state='leased') = (lease_token IS NOT NULL AND lease_until IS NOT NULL))
);

CREATE INDEX IF NOT EXISTS paper_notifications_due_pending
  ON paper_notification_ledger.deliveries (next_attempt_at, created_at)
  WHERE state='pending';
CREATE INDEX IF NOT EXISTS paper_notifications_due_lease
  ON paper_notification_ledger.deliveries (lease_until, created_at)
  WHERE state='leased';

CREATE TABLE IF NOT EXISTS paper_notification_ledger.quarantine (
  intent_key bytea NOT NULL,
  recipient_key bytea NOT NULL,
  reason_code text NOT NULL CHECK (reason_code ~ '^[A-Z][A-Z0-9_]{0,63}$'),
  failed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  attempts integer NOT NULL CHECK (attempts BETWEEN 1 AND 8),
  PRIMARY KEY(intent_key,recipient_key),
  FOREIGN KEY(intent_key,recipient_key)
    REFERENCES paper_notification_ledger.deliveries(intent_key,recipient_key)
);

-- Deploy login roles separately, with secrets injected by the secret manager.
-- The NOLOGIN role cannot authenticate or be confused with the DB owner.
DO $roles$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='paper_notification_runtime') THEN
    CREATE ROLE paper_notification_runtime NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION;
  END IF;
END $roles$;
GRANT USAGE ON SCHEMA paper_notification_ledger TO paper_notification_runtime;
REVOKE ALL ON ALL TABLES IN SCHEMA paper_notification_ledger FROM PUBLIC;
GRANT SELECT, INSERT ON paper_notification_ledger.intents TO paper_notification_runtime;
GRANT SELECT, INSERT, UPDATE ON paper_notification_ledger.deliveries TO paper_notification_runtime;
GRANT SELECT, INSERT ON paper_notification_ledger.quarantine TO paper_notification_runtime;
-- Never grant CREATE/ALTER/DELETE/TRUNCATE or schema ownership to the login.
-- Only the DB migration administrator is allowed to alter this schema.
