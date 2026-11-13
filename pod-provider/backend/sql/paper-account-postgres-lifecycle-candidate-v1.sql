-- Paper / ActivityPods unified account lifecycle -- DISPOSABLE CANDIDATE.
-- NOT connected to auth.signup, Solid-OIDC, SAI, PLC or the live PDS.
-- Execute only after reviewed backup/migration, single-writer and rollback gates.
-- This is operational state, NOT a replacement for WebID/RDF/Pod storage.
BEGIN;
CREATE SCHEMA paper_account_candidate;
CREATE TABLE paper_account_candidate.operations (
  operation_id uuid PRIMARY KEY,
  provider_id text NOT NULL CHECK (length(provider_id) BETWEEN 1 AND 255),
  app_client_id text NOT NULL CHECK (length(app_client_id) BETWEEN 1 AND 2048),
  -- Domain-separated HMAC-SHA-256 of the opaque app idempotency key,
  -- with a provider-held secret kept OUTSIDE the database. Never plain
  -- SHA-256: client keys can be short or guessable.
  idempotency_digest bytea NOT NULL CHECK (octet_length(idempotency_digest) = 32),
  -- Domain-separated HMAC-SHA-256 over the approved canonical request.
  -- No raw password, email, authorization header or bearer token is stored.
  -- The key version and rotation protocol are required at activation.
  request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
  username_key text NOT NULL CHECK (
    length(username_key) BETWEEN 1 AND 128 AND username_key = lower(username_key)
  ),
  -- Optional HMAC-SHA-256, provider-keyed, of verified normalized email.
  -- Plain SHA-256 on low-entropy emails is reversible by guessing; do not use.
  verified_email_hmac bytea CHECK (
    verified_email_hmac IS NULL OR octet_length(verified_email_hmac) = 32
  ),
  state text NOT NULL DEFAULT 'reserved' CHECK (
    state IN ('reserved', 'account_created', 'identities_ready',
              'completed', 'needs_reconciliation')
  ),
  -- Lease expiration is a FAIL-CLOSED reconciliation trigger, never authority
  -- to mint another DID or create the same username a second time.
  lease_token uuid NOT NULL,
  lease_expires_at timestamptz NOT NULL,
  canonical_webid text,
  activitypub_actor_id text,
  atproto_did text,
  pds_repo_root_cid text,
  pds_repo_rev text,
  -- Digest of verified signed PDS commit evidence from a future real PDS
  -- implementation. A boolean repoInitialized is NOT that evidence.
  signed_repo_proof_digest bytea CHECK (
    signed_repo_proof_digest IS NULL OR octet_length(signed_repo_proof_digest) = 32
  ),
  version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CONSTRAINT complete_requires_real_identity CHECK (
    state <> 'completed' OR (
      canonical_webid ~ '^https://[^/[:space:]]+/.+' AND
      activitypub_actor_id = canonical_webid AND
      atproto_did ~ '^did:plc:[a-z2-7]{24}$' AND
      length(pds_repo_root_cid) >= 30 AND
      pds_repo_root_cid <> 'bafyreigenesisplaceholder' AND
      length(pds_repo_rev) > 1 AND
      signed_repo_proof_digest IS NOT NULL
    )
  ),
  -- A per-provider application idempotency key cannot point at two accounts.
  CONSTRAINT operations_idempotency_unique UNIQUE
    (provider_id, app_client_id, idempotency_digest),
  -- Never release the name merely because a lease timed out or a client
  -- disappeared; manual reconciliation/explicit deletion is required.
  CONSTRAINT operations_provider_username_unique UNIQUE
    (provider_id, username_key)
);
CREATE UNIQUE INDEX operations_provider_verified_email_unique
  ON paper_account_candidate.operations(provider_id, verified_email_hmac)
  WHERE verified_email_hmac IS NOT NULL;
CREATE INDEX operations_reconciliation_idx
  ON paper_account_candidate.operations(updated_at, operation_id)
  WHERE state = 'needs_reconciliation';
REVOKE ALL ON SCHEMA paper_account_candidate FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA paper_account_candidate FROM PUBLIC;
COMMIT;
