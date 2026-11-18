-- DISPOSABLE ONLY. Binds a one-time coordinator reservation to the already
-- canonical v4 ActivityPods account/journal, then mirrors an attested ready
-- result. No new account authority, public signup, token or signer.
--
-- Apply ONLY after PG v4, repo, SAI and pre-account proof schemas exist.
-- Separate binder/finalizer NOLOGIN roles are never held by a user or client.
BEGIN;
ALTER TABLE paper_account_reservation_proof.reservations
  ADD COLUMN v4_provider_id text,
  ADD COLUMN v4_app_client_id text,
  ADD COLUMN v4_account_id uuid,
  ADD COLUMN v4_operation_id uuid,
  ADD COLUMN v4_hmac_key_version smallint,
  ADD COLUMN v4_idempotency_hmac bytea,
  ADD COLUMN v4_request_hmac bytea,
  ADD COLUMN v4_bound_at timestamptz,
  ADD CONSTRAINT v4_reservation_binding_atomic CHECK (
    (v4_bound_at IS NULL AND
      num_nonnulls(v4_provider_id,v4_app_client_id,v4_account_id,
        v4_operation_id,v4_hmac_key_version,v4_idempotency_hmac,v4_request_hmac)=0)
    OR
    (v4_bound_at IS NOT NULL AND
      num_nonnulls(v4_provider_id,v4_app_client_id,v4_account_id,
        v4_operation_id,v4_hmac_key_version,v4_idempotency_hmac,v4_request_hmac)=7)
  ),
  ADD CONSTRAINT v4_reservation_hmac_lengths CHECK (
    (v4_idempotency_hmac IS NULL OR octet_length(v4_idempotency_hmac)=32)
    AND (v4_request_hmac IS NULL OR octet_length(v4_request_hmac)=32)
  );
CREATE UNIQUE INDEX v4_reservation_one_account
  ON paper_account_reservation_proof.reservations(v4_provider_id,v4_account_id)
  WHERE v4_account_id IS NOT NULL;
CREATE UNIQUE INDEX v4_reservation_one_operation
  ON paper_account_reservation_proof.reservations(v4_provider_id,v4_operation_id)
  WHERE v4_operation_id IS NOT NULL;

CREATE ROLE paper_account_bridge_binder NOLOGIN
  NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE paper_account_bridge_finalizer NOLOGIN
  NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
GRANT USAGE ON SCHEMA paper_account_reservation_proof
  TO paper_account_bridge_binder,paper_account_bridge_finalizer;

-- App names must match their cryptographic scope; do not accept a caller's
-- assertion that an unrelated client or journal belongs to this reservation.
-- sha256(bytea) is built into PostgreSQL 18; no pgcrypto or superuser extension.
CREATE FUNCTION paper_account_reservation_proof.bind_v4_signup(
  p_reservation uuid, p_provider text, p_app_scope text,
  p_key_hash bytea, p_request_hash bytea,
  p_v4_provider text, p_v4_app text, p_v4_account uuid,
  p_v4_operation uuid, p_version smallint,
  p_v4_key_hmac bytea, p_v4_request_hmac bytea
) RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  r paper_account_reservation_proof.reservations%ROWTYPE;
  a paper_account_candidate.accounts%ROWTYPE;
  o paper_account_candidate.signup_operations%ROWTYPE;
  changed integer;
BEGIN
  IF p_reservation IS NULL OR p_provider IS NULL OR p_app_scope IS NULL OR
     p_key_hash IS NULL OR octet_length(p_key_hash)<>32 OR
     p_request_hash IS NULL OR octet_length(p_request_hash)<>32 OR
     p_v4_provider IS NULL OR p_v4_app IS NULL OR
     p_v4_account IS NULL OR p_v4_operation IS NULL OR
     p_version IS NULL OR p_v4_key_hmac IS NULL OR
     octet_length(p_v4_key_hmac)<>32 OR p_v4_request_hmac IS NULL OR
     octet_length(p_v4_request_hmac)<>32 OR
     length(p_v4_provider)>255 OR length(p_v4_app)>2048 OR
     p_provider<>p_v4_provider||'/provider' OR
     p_app_scope<>encode(sha256(convert_to('activitypods:approved-app:v1','UTF8') ||
       decode('00','hex') || convert_to(p_v4_app,'UTF8')),'hex') THEN
    RETURN false;
  END IF;
  SELECT * INTO r FROM paper_account_reservation_proof.reservations
    WHERE reservation_id=p_reservation AND provider_id=p_provider
      AND app_client_id=p_app_scope AND idempotency_hash=p_key_hash
      AND request_hash=p_request_hash FOR UPDATE;
  IF NOT FOUND OR r.state<>'side_effects_started' OR
     r.signup_claimed_at IS NOT NULL OR r.v4_bound_at IS NOT NULL OR
     r.lease_expires_at<=clock_timestamp() THEN
    RETURN false;
  END IF;
  SELECT * INTO a FROM paper_account_candidate.accounts
    WHERE provider_id=p_v4_provider AND account_id=p_v4_account FOR SHARE;
  IF NOT FOUND OR a.state<>'reserved' OR a.webid IS NOT NULL OR
     a.username_key<>r.username OR
     r.expected_webid<>p_v4_provider||'/'||a.username_key THEN
    RETURN false;
  END IF;
  SELECT * INTO o FROM paper_account_candidate.signup_operations
    WHERE provider_id=p_v4_provider AND account_id=p_v4_account
      AND operation_id=p_v4_operation AND app_client_id=p_v4_app
      AND hmac_key_version=p_version AND idempotency_hmac=p_v4_key_hmac
      AND request_hmac=p_v4_request_hmac FOR SHARE;
  IF NOT FOUND OR o.state<>'reserved' OR o.may_have_side_effects THEN
    RETURN false;
  END IF;
  UPDATE paper_account_reservation_proof.reservations
    SET v4_provider_id=p_v4_provider,v4_app_client_id=p_v4_app,
      v4_account_id=p_v4_account,v4_operation_id=p_v4_operation,
      v4_hmac_key_version=p_version,
      v4_idempotency_hmac=p_v4_key_hmac,v4_request_hmac=p_v4_request_hmac,
      v4_bound_at=clock_timestamp()
    WHERE reservation_id=p_reservation AND v4_bound_at IS NULL;
  GET DIAGNOSTICS changed=ROW_COUNT;
  RETURN changed=1;
END;
$$;

-- Do not accept a client-supplied "repoInitialized" Boolean, evidence digest,
-- WebID or DID. The existing v4 signed-CAR/hosted-PDS/Solid/SAI verifier
-- must have sealed the journal and committed the v4 ready CAS first.
-- This is an attested historical mirror, never login/session authorization.
CREATE FUNCTION paper_account_reservation_proof.reflect_v4_ready(
  p_reservation uuid, p_provider text, p_app_scope text,
  p_key_hash bytea, p_request_hash bytea
) RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  r paper_account_reservation_proof.reservations%ROWTYPE;
  a paper_account_candidate.accounts%ROWTYPE;
  o paper_account_candidate.signup_operations%ROWTYPE;
  ident paper_atproto_authority.identities%ROWTYPE;
  consent paper_atproto_authority.consents%ROWTYPE;
  event paper_atproto_repo_proof.native_event_outbox%ROWTYPE;
  blocked integer;
  head paper_atproto_repo_proof.repos%ROWTYPE;
  applied paper_atproto_repo_proof.rdf_projection_jobs%ROWTYPE;
  changed integer;
BEGIN
  IF p_reservation IS NULL OR p_provider IS NULL OR p_app_scope IS NULL OR
     p_key_hash IS NULL OR octet_length(p_key_hash)<>32 OR
     p_request_hash IS NULL OR octet_length(p_request_hash)<>32 THEN
    RETURN false;
  END IF;
  SELECT * INTO r FROM paper_account_reservation_proof.reservations
    WHERE reservation_id=p_reservation AND provider_id=p_provider
      AND app_client_id=p_app_scope AND idempotency_hash=p_key_hash
      AND request_hash=p_request_hash FOR UPDATE;
  IF NOT FOUND OR r.state<>'side_effects_started' OR
     r.signup_claimed_at IS NULL OR r.v4_bound_at IS NULL OR
     r.v4_account_id IS NULL OR r.v4_operation_id IS NULL THEN
    RETURN false;
  END IF;
  -- v4's own completion locks account then journal; match that order.
  SELECT * INTO a FROM paper_account_candidate.accounts
    WHERE provider_id=r.v4_provider_id AND account_id=r.v4_account_id FOR SHARE;
  IF NOT FOUND OR a.state<>'ready' OR a.username_key<>r.username OR
     a.webid<>r.expected_webid OR a.activitypub_actor_uri<>a.webid OR
     a.atproto_did IS NULL OR a.atproto_pds_url IS NULL OR
     a.atproto_repo_initialized IS DISTINCT FROM true THEN
    RETURN false;
  END IF;
  SELECT * INTO o FROM paper_account_candidate.signup_operations
    WHERE provider_id=r.v4_provider_id AND app_client_id=r.v4_app_client_id
      AND account_id=r.v4_account_id AND operation_id=r.v4_operation_id
      AND hmac_key_version=r.v4_hmac_key_version
      AND idempotency_hmac=r.v4_idempotency_hmac
      AND request_hmac=r.v4_request_hmac FOR SHARE;
  IF NOT FOUND OR o.state<>'ready' OR
     o.completion_proof_digest IS NULL OR
     o.completion_app_uri IS NULL OR
     o.completion_grant_uri IS NULL OR
     o.completion_consent_revision IS NULL OR
     o.evidence_digest IS NULL OR o.evidence_account_generation IS NULL OR
     o.may_have_side_effects IS DISTINCT FROM true THEN
    RETURN false;
  END IF;
  SELECT * INTO head FROM paper_atproto_repo_proof.repos
    WHERE account_id=a.webid AND did=a.atproto_did FOR SHARE;
  IF NOT FOUND OR head.head_cid<>o.evidence_commit_cid OR
     head.root_cid<>o.evidence_root_cid OR head.rev<>o.evidence_rev THEN
    RETURN false;
  END IF;
  SELECT * INTO applied FROM paper_atproto_repo_proof.rdf_projection_jobs
    WHERE account_id=a.webid AND did=a.atproto_did FOR SHARE;
  IF NOT FOUND OR applied.state<>'applied' OR applied.applied_at IS NULL OR
     applied.lease_epoch<>o.evidence_fence OR
     applied.head_cid<>head.head_cid OR applied.root_cid<>head.root_cid OR
     applied.rev<>head.rev OR applied.generation<>head.generation THEN
    RETURN false;
  END IF;
  SELECT * INTO ident FROM paper_atproto_authority.identities
    WHERE owner_webid=a.webid FOR SHARE;
  IF NOT FOUND OR ident.did<>a.atproto_did OR ident.state<>'active' OR
     ident.managed IS DISTINCT FROM true THEN
    RETURN false;
  END IF;
  SELECT * INTO consent FROM paper_atproto_authority.consents
    WHERE owner_webid=a.webid AND app_uri=o.completion_app_uri FOR SHARE;
  IF NOT FOUND OR consent.state<>'active' OR
     consent.grant_uri<>o.completion_grant_uri OR
     consent.revision<>o.completion_consent_revision THEN
    RETURN false;
  END IF;
  SELECT * INTO event FROM paper_atproto_repo_proof.native_event_outbox
    WHERE did=a.atproto_did AND commit_cid=head.head_cid FOR SHARE;
  IF NOT FOUND OR event.blocked_at IS NOT NULL OR
     event.status NOT IN ('pending','delivered') OR
     event.rev<>head.rev THEN
    RETURN false;
  END IF;
  SELECT count(*) INTO blocked FROM paper_atproto_repo_proof.native_event_outbox
    WHERE did=a.atproto_did AND status='pending' AND blocked_at IS NOT NULL;
  IF blocked>0 THEN RETURN false; END IF;
  -- Zero release rights: the digest is obtained exclusively from the
  -- v4 journal's independently attested, same-transaction completion.
  UPDATE paper_account_reservation_proof.reservations
    SET state='completed',completed_at=clock_timestamp(),
      activitypub_actor_id=a.activitypub_actor_uri,atproto_did=a.atproto_did,
      atproto_pds_url=a.atproto_pds_url,evidence_hash=o.completion_proof_digest
    WHERE reservation_id=p_reservation AND state='side_effects_started'
      AND v4_account_id=a.account_id;
  GET DIAGNOSTICS changed=ROW_COUNT;
  RETURN changed=1;
END;
$$;

-- Once the v4 authority extension is installed, the legacy structural-
-- digest-only completion path is disabled for ALL reservations. No unbound
-- reservation may bypass the verified v4 journal by presenting 32 arbitrary
-- bytes. The older standalone candidate tests keep their unextended proof
-- schema; this database exclusively uses the restricted v4 finalizer.
CREATE OR REPLACE FUNCTION paper_account_reservation_proof.complete(
  p_provider text, p_app text, p_key_hash bytea, p_reservation uuid, p_fence uuid,
  p_webid text, p_ap_actor text, p_did text, p_pds_url text, p_evidence bytea
) RETURNS boolean
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT false;
$$;

REVOKE ALL ON FUNCTION paper_account_reservation_proof.bind_v4_signup(
  uuid,text,text,bytea,bytea,text,text,uuid,uuid,smallint,bytea,bytea
) FROM PUBLIC;
REVOKE ALL ON FUNCTION paper_account_reservation_proof.reflect_v4_ready(
  uuid,text,text,bytea,bytea
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION paper_account_reservation_proof.bind_v4_signup(
  uuid,text,text,bytea,bytea,text,text,uuid,uuid,smallint,bytea,bytea
) TO paper_account_bridge_binder;
GRANT EXECUTE ON FUNCTION paper_account_reservation_proof.reflect_v4_ready(
  uuid,text,text,bytea,bytea
) TO paper_account_bridge_finalizer;
COMMIT;
