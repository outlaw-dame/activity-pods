-- Disposable non-activated extension; apply AFTER v1 and v2.
-- This modifies the EXISTING one-row signup journal, not the account
-- registry. Sealing preserves account.state='provisioning' and does not
-- authorize a ready transition or any external identity creation.
BEGIN;
ALTER TABLE paper_account_candidate.signup_operations
  DROP CONSTRAINT signup_operations_state_check;
ALTER TABLE paper_account_candidate.signup_operations
  ADD CONSTRAINT signup_operations_state_check
  CHECK (state IN ('reserved','reconciliation_required','evidence_sealed'));
ALTER TABLE paper_account_candidate.signup_operations
  ADD COLUMN evidence_digest bytea,
  ADD COLUMN evidence_commit_cid text COLLATE "C",
  ADD COLUMN evidence_root_cid text COLLATE "C",
  ADD COLUMN evidence_rev text COLLATE "C",
  ADD COLUMN evidence_fence bigint,
  ADD COLUMN evidence_account_generation bigint,
  ADD COLUMN evidence_sealed_at timestamptz,
  ADD CONSTRAINT signup_evidence_fields_check CHECK (
    (state='evidence_sealed') =
      (evidence_digest IS NOT NULL AND evidence_commit_cid IS NOT NULL AND
       evidence_root_cid IS NOT NULL AND evidence_rev IS NOT NULL AND
       evidence_fence IS NOT NULL AND evidence_account_generation IS NOT NULL AND
       evidence_sealed_at IS NOT NULL)
  ),
  ADD CONSTRAINT signup_evidence_format_check CHECK (
    (evidence_digest IS NULL OR octet_length(evidence_digest)=32) AND
    (evidence_commit_cid IS NULL OR evidence_commit_cid ~ '^bafyre[a-z2-7]{53}$') AND
    (evidence_root_cid IS NULL OR evidence_root_cid ~ '^bafyre[a-z2-7]{53}$') AND
    (evidence_rev IS NULL OR evidence_rev ~ '^[234567abcdefghij][234567abcdefghijklmnopqrstuvwxyz]{12}$') AND
    (evidence_fence IS NULL OR evidence_fence > 0) AND
    (evidence_account_generation IS NULL OR evidence_account_generation > 0)
  );
-- A partial work queue can enumerate only unsealed, uncertain operations.
-- Existing v2 signup_reconciliation_queue already has that predicate.
REVOKE ALL ON paper_account_candidate.signup_operations FROM PUBLIC;
COMMIT;
