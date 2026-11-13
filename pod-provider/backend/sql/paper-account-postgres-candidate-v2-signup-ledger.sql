-- Disposable, non-activated extension to the unified account candidate from PR #138.
-- This is an operation journal attached to the existing account row, NOT a
-- second account table or login/identity authority. Apply after candidate v1.
BEGIN;
CREATE TABLE paper_account_candidate.signup_operations (
  operation_id uuid PRIMARY KEY,
  provider_id text NOT NULL CHECK (length(provider_id) BETWEEN 8 AND 255),
  account_id uuid NOT NULL,
  app_client_id text NOT NULL CHECK (length(app_client_id) BETWEEN 1 AND 2048),
  hmac_key_version smallint NOT NULL CHECK (hmac_key_version BETWEEN 1 AND 255),
  idempotency_hmac bytea NOT NULL CHECK (octet_length(idempotency_hmac) = 32),
  request_hmac bytea NOT NULL CHECK (octet_length(request_hmac) = 32),
  state text NOT NULL DEFAULT 'reserved'
    CHECK (state IN ('reserved','reconciliation_required')),
  generation bigint NOT NULL DEFAULT 1 CHECK (generation > 0),
  may_have_side_effects boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  changed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  FOREIGN KEY (provider_id, account_id)
    REFERENCES paper_account_candidate.accounts(provider_id, account_id)
    ON DELETE RESTRICT,
  UNIQUE (provider_id, account_id),
  UNIQUE (provider_id, app_client_id, hmac_key_version, idempotency_hmac),
  CHECK (state = 'reserved' OR may_have_side_effects)
);
CREATE INDEX signup_reconciliation_queue
  ON paper_account_candidate.signup_operations(provider_id, changed_at, operation_id)
  WHERE state = 'reconciliation_required';
REVOKE ALL ON paper_account_candidate.signup_operations FROM PUBLIC;
COMMIT;
