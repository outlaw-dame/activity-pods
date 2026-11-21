-- Disposable provider-owned projection of the signed signup genesis. The
-- caller cannot select a job, extend a lease, write a receipt or grant rights.
BEGIN;
CREATE ROLE paper_provider_genesis_projector NOLOGIN NOSUPERUSER NOCREATEDB
  NOCREATEROLE NOREPLICATION NOBYPASSRLS;
ALTER TABLE paper_account_candidate.signup_operations
  ADD COLUMN provider_genesis_lease uuid,
  ADD COLUMN provider_genesis_rdf_digest bytea CHECK (provider_genesis_rdf_digest IS NULL OR
    (provider_genesis_lease IS NOT NULL AND octet_length(provider_genesis_rdf_digest)=32));
CREATE FUNCTION paper_account_reservation_proof.claim_provider_genesis(
  p_reservation uuid,p_operation uuid,p_did text,p_head text
) RETURNS TABLE(lease_owner uuid,lease_epoch bigint)
LANGUAGE sql VOLATILE STRICT SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
  WITH claimed AS (UPDATE paper_atproto_repo_proof.rdf_projection_jobs j
  SET state='leased',lease_epoch=j.lease_epoch+1,lease_owner=gen_random_uuid(),
    lease_until=clock_timestamp()+interval '90 seconds',attempt_count=j.attempt_count+1,
    updated_at=clock_timestamp()
  FROM paper_account_reservation_proof.read_provider_genesis(p_reservation,p_operation,p_did) g
  WHERE j.account_id=g.webid AND j.did=p_did AND j.head_cid=p_head AND g.head_cid=p_head
    AND j.root_cid=g.root_cid AND j.rev=g.rev AND j.generation=1
    AND j.attempt_count<8 AND j.lease_epoch<9223372036854775807
    AND ((j.state='pending' AND j.next_attempt_at<=clock_timestamp())
       OR (j.state='leased' AND j.lease_until<=clock_timestamp()))
  RETURNING j.lease_owner,j.lease_epoch)
  UPDATE paper_account_candidate.signup_operations s SET provider_genesis_lease=c.lease_owner
  FROM claimed c WHERE s.operation_id=p_operation AND s.provider_genesis_rdf_digest IS NULL
  RETURNING c.lease_owner,c.lease_epoch;
$$;
REVOKE ALL ON FUNCTION paper_account_reservation_proof.claim_provider_genesis(uuid,uuid,text,text) FROM PUBLIC;
GRANT USAGE ON SCHEMA paper_account_reservation_proof TO paper_provider_genesis_projector;
GRANT EXECUTE ON FUNCTION paper_account_reservation_proof.claim_provider_genesis(uuid,uuid,text,text)
  TO paper_provider_genesis_projector;
CREATE ROLE paper_provider_genesis_attestor NOLOGIN NOSUPERUSER NOCREATEDB
  NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE FUNCTION paper_account_reservation_proof.ack_provider_genesis(
  p_reservation uuid,p_operation uuid,p_did text,p_head text,p_lease uuid,p_epoch bigint,p_digest bytea
) RETURNS boolean
LANGUAGE plpgsql STRICT SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE proof record;
BEGIN
  IF octet_length(p_digest)<>32 OR p_epoch<1 THEN RETURN false; END IF;
  PERFORM 1 FROM paper_account_candidate.signup_operations s
    JOIN paper_account_candidate.accounts a ON a.account_id=s.account_id AND a.provider_id=s.provider_id
    JOIN paper_atproto_repo_proof.repos r ON r.account_id=a.webid AND r.did=p_did
    WHERE s.operation_id=p_operation AND s.provider_genesis_lease=p_lease
      AND s.provider_genesis_rdf_digest IS NULL FOR UPDATE OF s FOR SHARE OF r,a;
  IF NOT FOUND THEN RETURN false; END IF;
  SELECT * INTO proof FROM paper_account_reservation_proof.read_provider_genesis(p_reservation,p_operation,p_did);
  IF NOT FOUND OR proof.head_cid<>p_head THEN RETURN false; END IF;
  UPDATE paper_atproto_repo_proof.rdf_projection_jobs j
    SET state='applied',lease_owner=NULL,lease_until=NULL,applied_at=clock_timestamp(),updated_at=clock_timestamp()
    WHERE j.account_id=proof.webid AND j.did=p_did AND j.head_cid=p_head AND j.root_cid=proof.root_cid
      AND j.rev=proof.rev AND j.generation=1 AND j.state='leased' AND j.lease_owner=p_lease
      AND j.lease_epoch=p_epoch AND j.lease_until>clock_timestamp();
  IF NOT FOUND THEN RETURN false; END IF;
  UPDATE paper_account_candidate.signup_operations SET provider_genesis_rdf_digest=p_digest
    WHERE operation_id=p_operation;
  RETURN true;
END $$;
REVOKE ALL ON FUNCTION paper_account_reservation_proof.ack_provider_genesis(uuid,uuid,text,text,uuid,bigint,bytea) FROM PUBLIC;
GRANT USAGE ON SCHEMA paper_account_reservation_proof TO paper_provider_genesis_attestor;
GRANT EXECUTE ON FUNCTION paper_account_reservation_proof.ack_provider_genesis(uuid,uuid,text,text,uuid,bigint,bytea)
  TO paper_provider_genesis_attestor;
COMMIT;
