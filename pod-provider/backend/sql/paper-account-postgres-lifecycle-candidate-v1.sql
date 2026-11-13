-- Paper / ActivityPods unified account candidate -- DISPOSABLE, NON-ACTIVATED.
-- PostgreSQL owns operational account reservation; Jena owns Solid/RDF.
-- This schema does not replace Solid-OIDC, SAI, the PLC directory or a PDS.
-- A schema change here is NOT a reviewed production migration.
BEGIN;
CREATE SCHEMA paper_account_candidate;

CREATE TABLE paper_account_candidate.operations (
  operation_id uuid PRIMARY KEY,
  -- Legacy account migration deliberately uses a separate future workflow.
  operation_kind text NOT NULL DEFAULT 'new_signup' CHECK (operation_kind = 'new_signup'),
  provider_id text NOT NULL CHECK (length(provider_id) BETWEEN 1 AND 255),
  app_client_id text NOT NULL CHECK (length(app_client_id) BETWEEN 1 AND 2048),
  -- Provider-keyed, domain-separated HMAC-SHA256 of client idempotency key.
  idempotency_digest bytea NOT NULL CHECK (octet_length(idempotency_digest) = 32),
  -- Provider-keyed, domain-separated HMAC-SHA256 of approved request.
  request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
  username_key text NOT NULL CHECK (
    length(username_key) BETWEEN 1 AND 128 AND username_key = lower(username_key)
  ),
  verified_email_hmac bytea CHECK (
    verified_email_hmac IS NULL OR octet_length(verified_email_hmac) = 32
  ),
  state text NOT NULL DEFAULT 'reserved' CHECK (
    state IN ('reserved','account_created','identities_ready',
              'completed','needs_reconciliation')
  ),
  -- Expiry is a reconciliation trigger, NEVER permission to mint another DID.
  lease_token uuid NOT NULL,
  lease_expires_at timestamptz NOT NULL,
  canonical_webid text,
  activitypub_actor_id text,
  atproto_did text,
  pds_repo_root_cid text,
  pds_repo_rev text,
  signed_repo_proof_digest bytea CHECK (
    signed_repo_proof_digest IS NULL OR octet_length(signed_repo_proof_digest) = 32
  ),
  -- Must derive from independent configured PDS XRPC+PLC document verification.
  pds_sync_proof_digest bytea CHECK (
    pds_sync_proof_digest IS NULL OR octet_length(pds_sync_proof_digest) = 32
  ),
  -- Verifies real Solid/SAI/Pod resource readiness via the canonical
  -- ActivityPods auth.awaitBootstrapComplete action before completion.
  -- This is an operational proof, never a second authorization authority.
  solid_bootstrap_proof_digest bytea CHECK (
    solid_bootstrap_proof_digest IS NULL OR octet_length(solid_bootstrap_proof_digest) = 32
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
      signed_repo_proof_digest IS NOT NULL AND
      pds_sync_proof_digest IS NOT NULL AND
      solid_bootstrap_proof_digest IS NOT NULL
    )
  ),
  CONSTRAINT operations_idempotency_unique UNIQUE
    (provider_id,app_client_id,idempotency_digest),
  CONSTRAINT operations_provider_username_unique UNIQUE
    (provider_id,username_key)
);
CREATE UNIQUE INDEX operations_provider_verified_email_unique
  ON paper_account_candidate.operations(provider_id,verified_email_hmac)
  WHERE verified_email_hmac IS NOT NULL;
CREATE INDEX operations_reconciliation_idx
  ON paper_account_candidate.operations(updated_at,operation_id)
  WHERE state = 'needs_reconciliation';

-- Immutable initial signed v3 repository CAR is small and bounded.
-- Future record/blob blocks belong in a separate PDS blockstore (object storage),
-- not in the account ledger; do not build an unbounded content table here.
CREATE TABLE paper_account_candidate.signed_genesis (
  operation_id uuid PRIMARY KEY REFERENCES paper_account_candidate.operations(operation_id)
    ON UPDATE RESTRICT ON DELETE RESTRICT,
  did text NOT NULL UNIQUE CHECK (did ~ '^did:plc:[a-z2-7]{24}$'),
  root_cid text NOT NULL CHECK (root_cid ~ '^bafy[a-z2-7]{24,}$'),
  repo_rev text NOT NULL CHECK (length(repo_rev) BETWEEN 12 AND 64),
  signing_key_did text NOT NULL CHECK (
    signing_key_did ~ '^did:key:z[1-9A-HJ-NP-Za-km-z]{30,160}$'
  ),
  car_bytes bytea NOT NULL CHECK (octet_length(car_bytes) BETWEEN 32 AND 262144),
  car_sha256 bytea NOT NULL CHECK (octet_length(car_sha256) = 32),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

-- Storage-level referential integrity even when direct SQL is attempted.
-- This is not itself a cryptographic verifier: app roles must NOT have
-- direct table writes; authorization + signature verification live upstream.
CREATE FUNCTION paper_account_candidate.verify_completed_genesis()
RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
  IF NEW.state = 'completed' AND NOT EXISTS (
    SELECT 1 FROM paper_account_candidate.signed_genesis AS g
    WHERE g.operation_id = NEW.operation_id
      AND g.did = NEW.atproto_did
      AND g.root_cid = NEW.pds_repo_root_cid
      AND g.repo_rev = NEW.pds_repo_rev
      AND g.car_sha256 = NEW.signed_repo_proof_digest
  ) THEN
    RAISE EXCEPTION 'Completed account lacks matching immutable signed genesis'
      USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END $$;
CREATE CONSTRAINT TRIGGER operations_complete_verified_genesis
AFTER INSERT OR UPDATE ON paper_account_candidate.operations
DEFERRABLE INITIALLY IMMEDIATE FOR EACH ROW
EXECUTE FUNCTION paper_account_candidate.verify_completed_genesis();

REVOKE ALL ON SCHEMA paper_account_candidate FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA paper_account_candidate FROM PUBLIC;
COMMIT;
