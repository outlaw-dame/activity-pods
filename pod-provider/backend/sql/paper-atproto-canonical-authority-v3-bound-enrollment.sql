-- NONACTIVATED PostgreSQL 18 migration: bind initial ATProto/Solid SAI
-- consent to the EXISTING ActivityPods account/signup enrollment journal and
-- independently fenced coordinator reservation. No new account authority.
-- Apply AFTER canonical authority v1/v2, candidate account v1-v4/v6, and
-- the account-reservation v4 bridge. Never apply to production without the
-- independently deployed provider coordinator and native-Jena attestor.
BEGIN;

-- Revoke the v2 synthetic, app/owner-selectable entry points from runtime
-- principals. Only the new journal-verified functions below can be executed
-- using issuer and attestor credentials. Other historical active consents,
-- reader and one-way revoker roles are unchanged.
REVOKE EXECUTE ON FUNCTION paper_atproto_authority.begin_owner_consent(
 text,text,text,uuid,bytea) FROM paper_atproto_consent_issuer;
REVOKE EXECUTE ON FUNCTION paper_atproto_authority.attest_owner_consent(
 text,text,text,uuid,text,bytea) FROM paper_atproto_consent_attestor;
REVOKE EXECUTE ON FUNCTION paper_atproto_authority.confirm_owner_consent(
 text,text,text,uuid,text,bytea) FROM paper_atproto_consent_attestor;

-- This restricted helper derives ALL identity, app and approval evidence from
-- the pre-existing account journal, its cryptographic reservation bridge and
-- current managed DID. An attacker cannot select a different WebID/app,
-- override a requirement digest, import an existing account or re-use another
-- operation. Caller holds a PG row lock while the inner DB CAS runs.
CREATE FUNCTION paper_atproto_authority.bound_signup_owner_scope(
 p_reservation uuid,p_operation uuid,p_phase text
) RETURNS TABLE(owner_webid text,did text,app_uri text,
                request_sha256 bytea,registration_uri text)
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $fn$
 SELECT a.webid,a.atproto_did,s.enrollment_app_uri,
   sha256(
     convert_to('paper:owner-consent:journal:v3:'||r.reservation_id::text,
       'UTF8') ||
     s.request_hmac ||
     convert_to(jsonb_build_array(
       s.provider_id,s.app_client_id,s.operation_id::text,
       a.account_id::text,a.webid,a.atproto_did,s.enrollment_app_uri,
       s.enrollment_requirements,s.enrollment_selection
     )::text,'UTF8')
   ),
   s.enrollment_registration_uri
 FROM paper_account_reservation_proof.reservations r
 JOIN paper_account_candidate.accounts a
   ON a.account_id=r.v4_account_id AND a.provider_id=r.v4_provider_id
 JOIN paper_account_candidate.signup_operations s
   ON s.operation_id=r.v4_operation_id AND s.account_id=a.account_id
   AND s.provider_id=a.provider_id AND s.app_client_id=r.v4_app_client_id
   AND s.hmac_key_version=r.v4_hmac_key_version
   AND s.idempotency_hmac=r.v4_idempotency_hmac
   AND s.request_hmac=r.v4_request_hmac
 JOIN paper_atproto_authority.identities i
   ON i.owner_webid=a.webid AND i.did=a.atproto_did
 WHERE p_reservation IS NOT NULL AND p_operation IS NOT NULL
   AND p_phase IN ('begin','attest','confirm')
   AND r.reservation_id=p_reservation AND s.operation_id=p_operation
   AND r.v4_bound_at IS NOT NULL AND r.signup_claimed_at IS NOT NULL
   AND r.username=a.username_key AND r.expected_webid=a.webid
   AND r.provider_id=a.provider_id||'/provider'
   -- Re-verify the original v4 binder's app-scope digest. The reservation
   -- app scope is not an arbitrary alias for s.app_client_id.
   AND r.app_client_id=encode(sha256(
     convert_to('activitypods:approved-app:v1','UTF8') ||
     decode('00','hex') || convert_to(s.app_client_id,'UTF8')
   ),'hex')
   AND r.state=CASE WHEN p_phase='confirm' AND a.state='ready'
     THEN 'completed' ELSE 'side_effects_started' END
   AND s.may_have_side_effects AND a.atproto_repo_initialized
   AND a.activitypub_actor_uri=a.webid
   AND i.state='active' AND i.managed
   AND a.webid IS NOT NULL AND a.atproto_did IS NOT NULL
   AND s.enrollment_app_uri IS NOT NULL
   AND s.enrollment_app_uri LIKE 'https://%'
   AND s.enrollment_requirements->>'revision' ~ '^[a-f0-9]{64}$'
   AND jsonb_typeof(s.enrollment_requirements->'required')='array'
   AND jsonb_typeof(s.enrollment_selection->'acceptedSpecialRights')='array'
   AND jsonb_typeof(s.enrollment_selection->'acceptedAccessNeeds')='array'
   -- This is Paper's mandatory Group baseline, not an optional permission
   -- mask. A revoked CreateGroup, ReadGroups or ManageMembers cannot pass.
   AND s.enrollment_requirements->'required' @>
      '["apods:CreateGroup","apods:ReadGroups","apods:ManageMembers"]'::jsonb
   AND s.enrollment_selection->'acceptedSpecialRights' @>
      '["apods:CreateGroup","apods:ReadGroups","apods:ManageMembers"]'::jsonb
   AND NOT EXISTS (
     SELECT 1 FROM jsonb_array_elements_text(
       s.enrollment_requirements->'required') AS necessary(right_uri)
     WHERE NOT (
       (s.enrollment_selection->'acceptedSpecialRights') ? necessary.right_uri
       OR (s.enrollment_selection->'acceptedAccessNeeds') ? necessary.right_uri
     )
   )
   AND (
     (p_phase='begin' AND a.state='provisioning'
       AND s.state IN ('reconciliation_required','evidence_sealed')
       AND s.enrollment_state='consent_claimed'
       AND s.enrollment_expires_at>clock_timestamp()
       AND s.enrollment_registration_uri IS NULL)
     OR
     (p_phase='attest' AND a.state='provisioning'
       AND s.state IN ('reconciliation_required','evidence_sealed')
       AND s.enrollment_state='consent_recorded'
       AND s.enrollment_registration_uri IS NOT NULL)
     OR
     (p_phase='confirm' AND s.enrollment_state='consent_recorded'
       AND s.enrollment_registration_uri IS NOT NULL
       AND ((a.state='provisioning' AND
         s.state IN ('reconciliation_required','evidence_sealed'))
          OR (a.state='ready' AND s.state='ready'
            AND s.completion_app_uri=s.enrollment_app_uri
            AND s.completion_account_generation=a.generation)))
   )
 FOR SHARE OF r,a,s,i
$fn$;
REVOKE ALL ON FUNCTION paper_atproto_authority.bound_signup_owner_scope(
 uuid,uuid,text) FROM PUBLIC;

CREATE FUNCTION paper_atproto_authority.begin_bound_owner_consent(
 p_reservation uuid,p_operation uuid
) RETURNS boolean LANGUAGE plpgsql VOLATILE STRICT SECURITY DEFINER
SET search_path=pg_catalog,pg_temp SET lock_timeout='2s' AS $fn$
DECLARE b RECORD;
BEGIN
 SELECT * INTO b FROM paper_atproto_authority.bound_signup_owner_scope(
   p_reservation,p_operation,'begin');
 IF NOT FOUND THEN RETURN false; END IF;
 RETURN paper_atproto_authority.begin_owner_consent(
   b.owner_webid,b.did,b.app_uri,p_operation,b.request_sha256);
END $fn$;

-- An attestation is authorized ONLY after the real provider has durably
-- recorded its exact native registration URI, which must equal the
-- independently observed URI. The grant and SHA-256 are derived from
-- read-only native RDF evidence by a separate attestor credential.
CREATE FUNCTION paper_atproto_authority.attest_bound_owner_consent(
 p_reservation uuid,p_operation uuid,p_registration text,
 p_grant text,p_native_sha256 bytea
) RETURNS boolean LANGUAGE plpgsql VOLATILE STRICT SECURITY DEFINER
SET search_path=pg_catalog,pg_temp SET lock_timeout='2s' AS $fn$
DECLARE b RECORD;
BEGIN
 IF p_native_sha256 IS NULL OR octet_length(p_native_sha256)<>32 OR
    p_registration IS NULL OR p_grant IS NULL THEN RETURN false; END IF;
 SELECT * INTO b FROM paper_atproto_authority.bound_signup_owner_scope(
   p_reservation,p_operation,'attest');
 IF NOT FOUND OR b.registration_uri<>p_registration OR
    NOT EXISTS (
      SELECT 1 FROM paper_atproto_authority.consents c
      WHERE c.owner_webid=b.owner_webid AND c.app_uri=b.app_uri
        AND c.activation_operation=p_operation
        AND c.activation_request_sha256=b.request_sha256
        AND c.state IN ('pending','active') AND c.revision=1)
 THEN RETURN false; END IF;
 RETURN paper_atproto_authority.attest_owner_consent(
   b.owner_webid,b.did,b.app_uri,p_operation,p_grant,p_native_sha256);
END $fn$;

-- Read-back after Java/Jena I/O, owner revocation or startup: no application
-- Boolean can substitute for the *same current* bound journal/PG evidence.
CREATE FUNCTION paper_atproto_authority.confirm_bound_owner_consent(
 p_reservation uuid,p_operation uuid,p_registration text,
 p_grant text,p_native_sha256 bytea
) RETURNS boolean LANGUAGE plpgsql VOLATILE STRICT SECURITY DEFINER
SET search_path=pg_catalog,pg_temp SET lock_timeout='2s' AS $fn$
DECLARE b RECORD;
BEGIN
 IF p_native_sha256 IS NULL OR octet_length(p_native_sha256)<>32 OR
    p_registration IS NULL OR p_grant IS NULL THEN RETURN false; END IF;
 SELECT * INTO b FROM paper_atproto_authority.bound_signup_owner_scope(
   p_reservation,p_operation,'confirm');
 IF NOT FOUND OR b.registration_uri<>p_registration OR
    NOT EXISTS (
      SELECT 1 FROM paper_atproto_authority.consents c
      WHERE c.owner_webid=b.owner_webid AND c.app_uri=b.app_uri
        AND c.activation_operation=p_operation
        AND c.activation_request_sha256=b.request_sha256
        AND c.state='active' AND c.revision=1)
 THEN RETURN false; END IF;
 RETURN paper_atproto_authority.confirm_owner_consent(
   b.owner_webid,b.did,b.app_uri,p_operation,p_grant,p_native_sha256);
END $fn$;

REVOKE ALL ON FUNCTION paper_atproto_authority.begin_bound_owner_consent(
 uuid,uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION paper_atproto_authority.attest_bound_owner_consent(
 uuid,uuid,text,text,bytea) FROM PUBLIC;
REVOKE ALL ON FUNCTION paper_atproto_authority.confirm_bound_owner_consent(
 uuid,uuid,text,text,bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION paper_atproto_authority.begin_bound_owner_consent(
 uuid,uuid) TO paper_atproto_consent_issuer;
GRANT EXECUTE ON FUNCTION paper_atproto_authority.attest_bound_owner_consent(
 uuid,uuid,text,text,bytea),
 paper_atproto_authority.confirm_bound_owner_consent(
 uuid,uuid,text,text,bytea) TO paper_atproto_consent_attestor;
COMMIT;
