-- NONACTIVATED PostgreSQL 18 restricted signed-repository writer.
-- Apply ONLY to an isolated, disposable PG18 DB after schema.sql,
-- single-record-mutation.sql and paper-atproto-canonical-authority-v1.sql.
-- Not a production migration or a release of protected Solid/Fuseki storage.
BEGIN;

DO $roles$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles
                 WHERE rolname='paper_atproto_repo_writer') THEN
    CREATE ROLE paper_atproto_repo_writer NOLOGIN NOSUPERUSER
      NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
  END IF;
END $roles$;

-- This role is not the canonical identity importer or grant revoker.
-- A writer can read and lock current identity/consent, never alter them.
GRANT paper_atproto_authority_reader TO paper_atproto_repo_writer
  WITH INHERIT TRUE, SET FALSE, ADMIN FALSE;

REVOKE ALL ON SCHEMA paper_atproto_repo_proof FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA paper_atproto_repo_proof FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA paper_atproto_repo_proof FROM PUBLIC;
GRANT USAGE ON SCHEMA paper_atproto_repo_proof TO paper_atproto_repo_writer;
GRANT SELECT ON
  paper_atproto_repo_proof.repos,
  paper_atproto_repo_proof.blocks,
  paper_atproto_repo_proof.native_event_outbox,
  paper_atproto_repo_proof.rdf_projection_jobs,
  paper_atproto_repo_proof.record_mutations
  TO paper_atproto_repo_writer;

-- The signer-bearing write worker can only advance an existing repository
-- head. Genesis creation and identity import belong to a distinct
-- provider authority. A worker cannot directly mark an RDF projection
-- applied, ack outbox delivery, delete immutable blocks or mint grants.
GRANT UPDATE (head_cid,root_cid,rev,generation)
  ON paper_atproto_repo_proof.repos TO paper_atproto_repo_writer;
-- PostgreSQL SELECT ... FOR UPDATE requires UPDATE privilege on at least
-- one column. Grant only the inert housekeeping timestamp, NEVER state,
-- applied_at, head/root/rev, lease or generation. The signed writer
-- must lock this row before calling the guarded reset function.
GRANT UPDATE (updated_at)
  ON paper_atproto_repo_proof.rdf_projection_jobs TO paper_atproto_repo_writer;
GRANT INSERT (did,cid,block)
  ON paper_atproto_repo_proof.blocks TO paper_atproto_repo_writer;
GRANT INSERT (did,commit_cid,rev,kind)
  ON paper_atproto_repo_proof.native_event_outbox TO paper_atproto_repo_writer;
GRANT INSERT (did,commit_cid,previous_commit_cid,previous_root_cid,
  previous_rev,rev,action,path,previous_record_cid,record_cid,generation)
  ON paper_atproto_repo_proof.record_mutations TO paper_atproto_repo_writer;

-- PostgreSQL SELECT ... FOR SHARE requires an UPDATE privilege on at
-- least one column. Do NOT grant any canonical grant/identity UPDATE to the
-- signed writer. Instead expose exactly one read-only, row-locking SECURITY
-- DEFINER function. Its locks survive until the caller's transaction COMMIT;
-- the writer cannot escalate to regrant or mutate the underlying tables.
CREATE OR REPLACE FUNCTION paper_atproto_authority.lock_writer_consent(
  p_owner text, p_did text, p_app text, p_grant text, p_revision bigint)
RETURNS boolean
LANGUAGE SQL VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,pg_temp
AS $function$
  SELECT EXISTS (
    SELECT 1 FROM paper_atproto_authority.consents AS c
    JOIN paper_atproto_authority.identities AS i
      ON i.owner_webid=c.owner_webid
    WHERE c.owner_webid=p_owner AND c.app_uri=p_app
      AND c.grant_uri=p_grant AND c.state='active'
      AND c.revision=p_revision
      AND i.did=p_did AND i.state='active' AND i.managed=true
    FOR SHARE OF c,i
  )
$function$;
REVOKE ALL ON FUNCTION paper_atproto_authority.lock_writer_consent(
  text,text,text,text,bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION paper_atproto_authority.lock_writer_consent(
  text,text,text,text,bigint) TO paper_atproto_repo_writer;

-- The ONLY writer-accessible transition of a previously applied RDF
-- projection is a CAS reset to pending, referencing the exact signed-head
-- advance, new durable native event and immutable mutation history.
-- It cannot set state='applied'. The future projection worker needs a
-- separately restricted credential and an independently checked Jena CAS.
CREATE OR REPLACE FUNCTION paper_atproto_repo_proof.reset_after_signed_commit(
  p_account text, p_did text,
  p_new_commit text, p_new_root text, p_new_rev text, p_new_generation bigint,
  p_prior_commit text, p_prior_root text, p_prior_rev text, p_prior_generation bigint)
RETURNS TABLE (generation bigint,lease_epoch bigint)
LANGUAGE SQL
SECURITY DEFINER
SET search_path=pg_catalog,pg_temp
AS $function$
  UPDATE paper_atproto_repo_proof.rdf_projection_jobs AS j
  SET head_cid=p_new_commit, root_cid=p_new_root,
      rev=p_new_rev, generation=p_new_generation,
      state='pending', lease_owner=NULL, lease_until=NULL,
      attempt_count=0, next_attempt_at=pg_catalog.clock_timestamp(),
      last_error_code=NULL, applied_at=NULL,
      updated_at=pg_catalog.clock_timestamp()
  WHERE j.account_id=p_account AND j.did=p_did
    AND j.head_cid=p_prior_commit AND j.root_cid=p_prior_root
    AND j.rev=p_prior_rev AND j.generation=p_prior_generation
    AND j.state='applied'
    AND p_prior_generation >= 1
    AND p_new_generation=p_prior_generation+1
    AND EXISTS (
      SELECT 1 FROM paper_atproto_repo_proof.repos AS r
      WHERE r.account_id=p_account AND r.did=p_did
        AND r.head_cid=p_new_commit AND r.root_cid=p_new_root
        AND r.rev=p_new_rev AND r.generation=p_new_generation
    )
    AND EXISTS (
      SELECT 1 FROM paper_atproto_repo_proof.native_event_outbox AS e
      WHERE e.did=p_did AND e.commit_cid=p_new_commit
        AND e.rev=p_new_rev AND e.kind='at.commit.v1'
        AND e.status='pending' AND e.blocked_at IS NULL
    )
    AND EXISTS (
      SELECT 1 FROM paper_atproto_repo_proof.record_mutations AS m
      WHERE m.did=p_did AND m.commit_cid=p_new_commit
        AND m.previous_commit_cid=p_prior_commit
        AND m.previous_root_cid=p_prior_root AND m.previous_rev=p_prior_rev
        AND m.rev=p_new_rev AND m.generation=p_new_generation
    )
  RETURNING j.generation,j.lease_epoch
$function$;
-- All grants are changed in this SAME SQL transaction, leaving no window
-- where ordinary service accounts may invoke the security-definer function.
REVOKE ALL ON FUNCTION paper_atproto_repo_proof.reset_after_signed_commit(
  text,text,text,text,text,bigint,text,text,text,bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION paper_atproto_repo_proof.reset_after_signed_commit(
  text,text,text,text,text,bigint,text,text,text,bigint)
  TO paper_atproto_repo_writer;

COMMIT;
