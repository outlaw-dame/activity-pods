-- Local bootstrap worker only. A consumed provider reservation authorizes a
-- read of its immutable genesis. No app receives this database role.
BEGIN;
CREATE ROLE paper_provider_genesis_reader NOLOGIN NOSUPERUSER NOCREATEDB
  NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE FUNCTION paper_account_reservation_proof.read_provider_genesis(
  p_reservation uuid, p_operation uuid, p_did text
) RETURNS TABLE(webid text, handle text, pds_origin text, head_cid text,
  root_cid text, rev text, commit_block bytea, root_block bytea)
LANGUAGE sql STABLE STRICT SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
  SELECT a.webid, a.atproto_handle, a.atproto_pds_url, repo.head_cid,
    repo.root_cid, repo.rev, commit_bytes.block, root_bytes.block
  FROM paper_account_reservation_proof.reservations r
  JOIN paper_account_candidate.signup_operations s
    ON s.operation_id=r.v4_operation_id AND s.account_id=r.v4_account_id
    AND s.provider_id=r.v4_provider_id AND s.app_client_id=r.v4_app_client_id
    AND s.hmac_key_version=r.v4_hmac_key_version
    AND s.idempotency_hmac=r.v4_idempotency_hmac AND s.request_hmac=r.v4_request_hmac
  JOIN paper_account_candidate.accounts a ON a.provider_id=s.provider_id AND a.account_id=s.account_id
  JOIN paper_dataset_admin_proof.claims dataset
    ON dataset.reservation_id=r.reservation_id AND dataset.dataset=r.username
    AND dataset.owner_webid=a.webid AND dataset.state='created'
  JOIN paper_atproto_repo_proof.repos repo ON repo.did=a.atproto_did AND repo.account_id=a.webid
  JOIN paper_atproto_repo_proof.rdf_projection_jobs job ON job.account_id=repo.account_id
    AND (job.did,job.head_cid,job.root_cid,job.rev,job.generation)=
        (repo.did,repo.head_cid,repo.root_cid,repo.rev,repo.generation)
  JOIN paper_atproto_repo_proof.native_event_outbox event ON event.did=repo.did
    AND event.commit_cid=repo.head_cid AND event.rev=repo.rev
  JOIN paper_atproto_repo_proof.blocks commit_bytes ON commit_bytes.did=repo.did AND commit_bytes.cid=repo.head_cid
  JOIN paper_atproto_repo_proof.blocks root_bytes ON root_bytes.did=repo.did AND root_bytes.cid=repo.root_cid
  WHERE r.reservation_id=p_reservation AND s.operation_id=p_operation AND repo.did=p_did
    AND r.v4_bound_at IS NOT NULL AND r.signup_claimed_at IS NOT NULL
    AND r.state='side_effects_started' AND r.provider_id=s.provider_id||'/provider'
    AND r.username=a.username_key AND r.expected_webid=a.webid
    AND a.webid=a.provider_id||'/'||r.username AND a.activitypub_actor_uri=a.webid
    AND a.atproto_pds_url=a.provider_id AND a.atproto_repo_initialized
    AND s.state IN ('reconciliation_required','evidence_sealed') AND s.may_have_side_effects
    AND s.enrollment_state='consent_recorded' AND s.enrollment_app_uri=s.app_client_id
    AND a.state='provisioning' AND repo.generation=1 AND job.state<>'blocked'
    AND event.kind='at.commit.v1' AND event.blocked_at IS NULL;
$$;
REVOKE ALL ON FUNCTION paper_account_reservation_proof.read_provider_genesis(uuid,uuid,text) FROM PUBLIC;
GRANT USAGE ON SCHEMA paper_account_reservation_proof TO paper_provider_genesis_reader;
GRANT EXECUTE ON FUNCTION paper_account_reservation_proof.read_provider_genesis(uuid,uuid,text)
  TO paper_provider_genesis_reader;
COMMIT;
