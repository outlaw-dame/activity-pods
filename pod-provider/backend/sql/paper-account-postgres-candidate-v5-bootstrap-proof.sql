-- DISPOSABLE CANDIDATE. Apply after account v1-v4, repo proof and
-- canonical ATProto authority schema. No production migration or signup cutover.
-- Reuse the *same* provider account, operation journal, signed repository,
-- projection ledger and canonical consent; never create a shadow account.
BEGIN;

DO $roles$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_catalog.pg_roles
    WHERE rolname = 'paper_account_bootstrap_reader'
  ) THEN
    CREATE ROLE paper_account_bootstrap_reader
      NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
  END IF;
END
$roles$;

-- This role gets EXECUTE on one exact-key predicate. It cannot enumerate
-- accounts, read HMACs or grant evidence from tables, or write identities.
REVOKE ALL ON SCHEMA paper_account_candidate FROM PUBLIC;
GRANT USAGE ON SCHEMA paper_account_candidate TO paper_account_bootstrap_reader;

CREATE FUNCTION paper_account_candidate.current_bootstrap_proof(
  p_provider_id text,
  p_app_client_id text,
  p_hmac_key_version smallint,
  p_idempotency_hmac bytea,
  p_username text,
  p_webid text,
  p_actor_id text,
  p_atproto_did text,
  p_atproto_handle text,
  p_app_uri text
)
RETURNS TABLE (
  account_id uuid,
  grant_uri text,
  consent_revision bigint,
  account_generation bigint
)
LANGUAGE SQL STABLE SECURITY DEFINER
SET search_path = pg_catalog
AS $proof$
  SELECT a.account_id, c.grant_uri, c.revision, a.generation
  FROM paper_account_candidate.signup_operations AS s
  JOIN paper_account_candidate.accounts AS a
    ON a.provider_id = s.provider_id AND a.account_id = s.account_id
  JOIN paper_atproto_authority.identities AS i
    ON i.owner_webid = a.webid AND i.did = a.atproto_did
  JOIN paper_atproto_authority.consents AS c
    ON c.owner_webid = a.webid AND c.app_uri = s.completion_app_uri
  JOIN paper_atproto_repo_proof.repos AS r
    ON r.account_id = a.webid AND r.did = a.atproto_did
  JOIN paper_atproto_repo_proof.rdf_projection_jobs AS j
    ON j.account_id = r.account_id AND j.did = r.did
  JOIN paper_atproto_repo_proof.native_event_outbox AS o
    ON o.did = r.did AND o.commit_cid = s.evidence_commit_cid
  WHERE
    s.provider_id = p_provider_id
    AND s.app_client_id = p_app_client_id
    AND s.hmac_key_version = p_hmac_key_version
    AND s.idempotency_hmac = p_idempotency_hmac
    AND octet_length(p_idempotency_hmac) = 32
    AND a.username_key = p_username
    AND a.webid = p_webid
    AND a.activitypub_actor_uri = p_actor_id
    AND a.webid = a.activitypub_actor_uri
    AND a.atproto_did = p_atproto_did
    AND a.atproto_handle = p_atproto_handle
    AND s.completion_app_uri = p_app_uri
    AND s.state = 'ready' AND a.state = 'ready'
    AND s.completion_at IS NOT NULL
    AND s.completion_account_generation = a.generation
    AND s.evidence_account_generation = a.generation - 1
    AND s.evidence_sealed_at IS NOT NULL
    AND octet_length(s.evidence_digest) = 32
    AND octet_length(s.completion_proof_digest) = 32
    AND a.atproto_repo_initialized = TRUE
    AND i.state = 'active' AND i.managed = TRUE
    AND c.state = 'active'
    AND c.grant_uri = s.completion_grant_uri
    AND c.revision = s.completion_consent_revision
    AND r.head_cid = s.evidence_commit_cid
    AND r.root_cid = s.evidence_root_cid
    AND r.rev = s.evidence_rev
    AND j.head_cid = r.head_cid
    AND j.root_cid = r.root_cid
    AND j.rev = r.rev
    AND j.generation = r.generation
    AND j.state = 'applied'
    AND j.applied_at IS NOT NULL
    AND j.lease_epoch = s.evidence_fence
    AND o.rev = r.rev
    AND o.blocked_at IS NULL
    AND o.status IN ('pending', 'delivered')
  LIMIT 2;
$proof$;

REVOKE ALL ON FUNCTION paper_account_candidate.current_bootstrap_proof(
  text,text,smallint,bytea,text,text,text,text,text,text
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION paper_account_candidate.current_bootstrap_proof(
  text,text,smallint,bytea,text,text,text,text,text,text
) TO paper_account_bootstrap_reader;

-- No account/SAI/repo table privileges for the reader role. Provision a
-- dedicated least-privilege LOGIN and grant only this NOLOGIN role after
-- independent production DDL, role and backup/restore reviews.
REVOKE ALL ON paper_account_candidate.accounts FROM paper_account_bootstrap_reader;
REVOKE ALL ON paper_account_candidate.signup_operations FROM paper_account_bootstrap_reader;
REVOKE ALL ON paper_atproto_authority.identities FROM paper_account_bootstrap_reader;
REVOKE ALL ON paper_atproto_authority.consents FROM paper_account_bootstrap_reader;
REVOKE ALL ON paper_atproto_repo_proof.repos FROM paper_account_bootstrap_reader;
REVOKE ALL ON paper_atproto_repo_proof.rdf_projection_jobs FROM paper_account_bootstrap_reader;
REVOKE ALL ON paper_atproto_repo_proof.native_event_outbox FROM paper_account_bootstrap_reader;
COMMIT;
