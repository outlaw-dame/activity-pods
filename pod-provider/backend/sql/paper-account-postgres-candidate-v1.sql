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
  -- Exactly one canonical identity. ActivityPub actor ID is the same WebID;
  -- ATProto DID and repository are mandatory before a READY account.
  webid text,
  activitypub_actor_uri text,
  atproto_did text,
  atproto_handle text,
  atproto_pds_url text,
  atproto_repo_initialized boolean NOT NULL DEFAULT false,
  state text NOT NULL DEFAULT 'reserved'
    CHECK (state IN ('reserved','provisioning','ready','suspended','deleting','deleted')),
  generation bigint NOT NULL DEFAULT 1 CHECK (generation > 0),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  changed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  UNIQUE (provider_id, username_key),
  UNIQUE (provider_id, webid),
  UNIQUE (provider_id, account_id),
  UNIQUE (atproto_did),
  CHECK (webid IS NULL OR (length(webid) BETWEEN 8 AND 2048 AND webid ~ '^https://[^[:space:]]+
);
CREATE INDEX account_provider_lifecycle ON paper_account_candidate.accounts
  (provider_id,state,account_id) WHERE state IN ('provisioning','suspended','deleting');

CREATE TABLE paper_account_candidate.transitions (
  account_id uuid NOT NULL REFERENCES paper_account_candidate.accounts(account_id),
  operation_id uuid NOT NULL,
  previous_generation bigint NOT NULL CHECK (previous_generation > 0),
  next_generation bigint NOT NULL CHECK (next_generation = previous_generation + 1),
  kind text NOT NULL CHECK (kind IN ('bind_unified_identity','transition_state')),
  payload_digest text NOT NULL CHECK (payload_digest ~ '^[0-9a-f]{64}$'),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (account_id, operation_id),
  UNIQUE (account_id,next_generation)
);
REVOKE ALL ON ALL TABLES IN SCHEMA paper_account_candidate FROM PUBLIC;
COMMIT;
)),
  CHECK (activitypub_actor_uri IS NULL OR activitypub_actor_uri = webid),
  CHECK (atproto_did IS NULL OR atproto_did ~ '^did:plc:[a-z2-7]{24}
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
),
  CHECK (atproto_handle IS NULL OR length(atproto_handle) BETWEEN 3 AND 253),
  CHECK (atproto_pds_url IS NULL OR atproto_pds_url ~ '^https://[^[:space:]]+
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
),
  CHECK (
    (webid IS NULL AND activitypub_actor_uri IS NULL AND atproto_did IS NULL
      AND atproto_handle IS NULL AND atproto_pds_url IS NULL AND NOT atproto_repo_initialized)
    OR (webid IS NOT NULL AND activitypub_actor_uri = webid AND atproto_did IS NOT NULL
      AND atproto_handle IS NOT NULL AND atproto_pds_url IS NOT NULL AND atproto_repo_initialized)
  ),
  CHECK ((state = 'reserved') = (webid IS NULL))
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
