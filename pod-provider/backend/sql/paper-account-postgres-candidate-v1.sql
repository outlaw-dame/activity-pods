-- Paper / ActivityPods non-activated PostgreSQL account lifecycle candidate.
-- NEVER use as an authentication, Solid-OIDC, WebID or credential authority.
-- Requires an explicit single-authority migration and revocation cutover.
BEGIN;
CREATE SCHEMA paper_account_candidate;
REVOKE ALL ON SCHEMA paper_account_candidate FROM PUBLIC;

CREATE TABLE paper_account_candidate.accounts (
  account_id uuid PRIMARY KEY,
  provider_id text NOT NULL CHECK (length(provider_id) BETWEEN 8 AND 255),
  username_key text COLLATE "C" NOT NULL CHECK (
    length(username_key) BETWEEN 2 AND 64 AND
    username_key ~ '^[a-z0-9][a-z0-9_-]*$'
  ),
  webid text,
  state text NOT NULL DEFAULT 'reserved'
    CHECK (state IN ('reserved','provisioning','ready','suspended','deleting','deleted')),
  generation bigint NOT NULL DEFAULT 1 CHECK (generation > 0),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  changed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  UNIQUE (provider_id, username_key),
  UNIQUE (provider_id, webid),
  UNIQUE (provider_id, account_id),
  CHECK (webid IS NULL OR (length(webid) BETWEEN 8 AND 2048 AND webid ~ '^https://[^[:space:]]+$')),
  CHECK ((state = 'reserved' AND webid IS NULL) OR state <> 'reserved')
);
CREATE INDEX account_provider_lifecycle ON paper_account_candidate.accounts
  (provider_id,state,account_id) WHERE state IN ('provisioning','suspended','deleting');

CREATE TABLE paper_account_candidate.transitions (
  account_id uuid NOT NULL REFERENCES paper_account_candidate.accounts(account_id),
  operation_id uuid NOT NULL,
  previous_generation bigint NOT NULL CHECK (previous_generation > 0),
  next_generation bigint NOT NULL CHECK (next_generation = previous_generation + 1),
  kind text NOT NULL CHECK (kind IN ('attach_webid','transition_state')),
  payload_digest text NOT NULL CHECK (payload_digest ~ '^[0-9a-f]{64}$'),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (account_id, operation_id),
  UNIQUE (account_id,next_generation)
);
REVOKE ALL ON ALL TABLES IN SCHEMA paper_account_candidate FROM PUBLIC;
COMMIT;
