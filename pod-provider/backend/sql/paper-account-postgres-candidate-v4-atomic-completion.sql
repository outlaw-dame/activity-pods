-- DISPOSABLE ONLY. Reviewed production signup release stays closed.
-- Apply after candidate v1 + v2 + v3. No second account table or identity.
-- The single PostgreSQL transaction promotes the already fenced account and
-- signup operation together, only after exact signed-head, projection and
-- canonical SAI consent locks. This is NOT a production deployment migration.
BEGIN;
ALTER TABLE paper_account_candidate.signup_operations
  DROP CONSTRAINT signup_operations_state_check;
ALTER TABLE paper_account_candidate.signup_operations
  ADD CONSTRAINT signup_operations_state_check
  CHECK (state IN ('reserved','reconciliation_required','evidence_sealed','ready'));

-- Preserve immutable v3 evidence while transitioning to ready.
ALTER TABLE paper_account_candidate.signup_operations
  DROP CONSTRAINT signup_evidence_fields_check;
ALTER TABLE paper_account_candidate.signup_operations
  ADD CONSTRAINT signup_evidence_fields_check CHECK (
    (state IN ('evidence_sealed','ready')) =
    (evidence_digest IS NOT NULL AND evidence_commit_cid IS NOT NULL AND
     evidence_root_cid IS NOT NULL AND evidence_rev IS NOT NULL AND
     evidence_fence IS NOT NULL AND evidence_account_generation IS NOT NULL AND
     evidence_sealed_at IS NOT NULL)
  );

ALTER TABLE paper_account_candidate.signup_operations
  ADD COLUMN completion_at timestamptz,
  ADD COLUMN completion_account_generation bigint,
  ADD COLUMN completion_app_uri text COLLATE "C",
  ADD COLUMN completion_grant_uri text COLLATE "C",
  ADD COLUMN completion_consent_revision bigint,
  ADD COLUMN completion_proof_digest bytea,
  ADD CONSTRAINT signup_completion_fields_check CHECK (
    (state = 'ready') =
    (completion_at IS NOT NULL AND completion_account_generation IS NOT NULL AND
     completion_app_uri IS NOT NULL AND completion_grant_uri IS NOT NULL AND
     completion_consent_revision IS NOT NULL AND completion_proof_digest IS NOT NULL)
  ),
  ADD CONSTRAINT signup_completion_values_check CHECK (
    (completion_account_generation IS NULL OR completion_account_generation > evidence_account_generation) AND
    (completion_consent_revision IS NULL OR completion_consent_revision > 0) AND
    (completion_proof_digest IS NULL OR octet_length(completion_proof_digest)=32) AND
    (completion_app_uri IS NULL OR length(completion_app_uri) BETWEEN 8 AND 2048) AND
    (completion_grant_uri IS NULL OR length(completion_grant_uri) BETWEEN 8 AND 2048)
  );

-- Immutable reconciliation records cannot be deleted or reset by client
-- retries. Generic account.change(... ready) remains blocked for all journaled
-- new accounts. No duplicate secondary index: UNIQUE(provider_id,account_id)
-- already provides the exact one-row journal lookup.
REVOKE ALL ON paper_account_candidate.signup_operations FROM PUBLIC;
COMMIT;
