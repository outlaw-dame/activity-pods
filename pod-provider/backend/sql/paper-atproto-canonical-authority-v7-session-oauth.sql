-- NONACTIVATED PostgreSQL 18 OAuth issuance via the EXISTING owner
-- enrollment journal. Run AFTER account v1-v4/v6, reservation/bridge v4,
-- canonical identity and native SAI v1-v3, and OAuth generation v4-v6.
-- No caller-selectable owner WebID, DID, app URI, grant owner or client.
-- Session hash is issued only after the authenticated owner browser's
-- enrollment challenge; a stolen or expired hash cannot issue an OAuth grant.
BEGIN;

-- Raw owner/ID/app-selectable calls remain callable ONLY by migration
-- function owners, never by restricted provider issuer/revoker logins.
REVOKE EXECUTE ON FUNCTION paper_atproto_authority.issue_oauth_generation(
  text,text,text,text,bytea,bigint,bigint) FROM paper_oauth_epoch_issuer;
REVOKE EXECUTE ON FUNCTION paper_atproto_authority.revoke_oauth_generation(
  text,text,text,bigint) FROM paper_oauth_epoch_revoker;

-- The same v3 session scope already authenticates an owner-bound canonical
-- account, reservation, immutable request HMAC, DID and native SAI app.
-- Limit its delegation to a fresh completed native consent and to the
-- existing 10-minute session; never extend that expiry on OAuth retry.
CREATE FUNCTION paper_atproto_authority.issue_session_oauth_generation(
 p_provider text,p_origin text,p_session_hash bytea,p_grant_id text,
 p_scope text,p_expected bigint
) RETURNS bigint
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,pg_temp SET lock_timeout='2s' AS $fn$
DECLARE b record;
BEGIN
 IF p_provider IS NULL OR p_origin IS NULL OR p_session_hash IS NULL OR
    octet_length(p_session_hash)<>32 OR
    p_grant_id IS NULL OR p_grant_id !~ '^[A-Za-z0-9_-]{32}$' OR
    p_expected IS NULL OR p_expected<0 OR
    p_expected>=9223372036854775807 OR
    -- This *initial Paper* grant is scoped only to ATProto and the
    -- supported feed-post write. Broader grants require an explicit
    -- reviewed manifest and separate owner authorization.
    p_scope NOT IN ('atproto',
      'atproto repo:app.bsky.feed.post?action=create')
 THEN RETURN 0; END IF;
 SELECT a.owner_webid,a.app_uri,s.app_client_id AS client_id,
        c.revision AS sai_revision
 INTO b
 FROM paper_account_candidate.signup_operations s
 JOIN paper_account_reservation_proof.reservations r
   ON r.v4_operation_id=s.operation_id
   AND r.v4_account_id=s.account_id
   AND r.v4_provider_id=s.provider_id
   AND r.v4_app_client_id=s.app_client_id
 CROSS JOIN LATERAL paper_atproto_authority.bound_signup_owner_scope(
   r.reservation_id,s.operation_id,'confirm') a
 JOIN paper_atproto_authority.consents c
   ON c.owner_webid=a.owner_webid AND c.app_uri=a.app_uri
 WHERE s.provider_id=p_provider AND s.enrollment_origin=p_origin
   AND s.enrollment_token_hash=p_session_hash
   AND s.enrollment_expires_at>clock_timestamp()
   AND s.enrollment_state='consent_recorded'
   AND s.app_client_id LIKE 'https://%'
   AND s.enrollment_app_uri=a.app_uri
   AND c.state='active' AND c.activation_operation=s.operation_id
   AND c.activation_request_sha256=a.request_sha256
   AND c.activation_native_readback_at IS NOT NULL
   AND c.revision>0
 FOR SHARE OF s,r,c;
 IF NOT FOUND THEN RETURN 0; END IF;
 RETURN paper_atproto_authority.issue_oauth_generation(
   b.owner_webid,b.app_uri,b.client_id,p_grant_id,
   sha256(convert_to(p_scope,'UTF8')),p_expected,b.sai_revision);
END $fn$;

-- Only the currently authenticated enrollment owner may revoke this
-- initial grant. A revoked/expired enrollment session must NEVER be
-- accepted as a new OAuth approval. General post-enrollment revocation
-- needs an independently authenticated long-lived account session gate.
CREATE FUNCTION paper_atproto_authority.revoke_session_oauth_generation(
 p_provider text,p_origin text,p_session_hash bytea,
 p_grant_id text,p_expected bigint
) RETURNS bigint
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,pg_temp SET lock_timeout='2s' AS $fn$
DECLARE b record;
BEGIN
 IF p_session_hash IS NULL OR octet_length(p_session_hash)<>32 OR
   p_provider IS NULL OR p_origin IS NULL OR
   p_grant_id IS NULL OR p_grant_id !~ '^[A-Za-z0-9_-]{32}$' OR
   p_expected IS NULL OR p_expected<=0 OR
   p_expected>=9223372036854775807
 THEN RETURN 0; END IF;
 SELECT a.owner_webid,s.app_client_id AS client_id INTO b
 FROM paper_account_candidate.signup_operations s
 JOIN paper_account_reservation_proof.reservations r
   ON r.v4_operation_id=s.operation_id
   AND r.v4_account_id=s.account_id AND r.v4_provider_id=s.provider_id
   AND r.v4_app_client_id=s.app_client_id
 CROSS JOIN LATERAL paper_atproto_authority.bound_signup_owner_scope(
   r.reservation_id,s.operation_id,'confirm') a
 WHERE s.provider_id=p_provider AND s.enrollment_origin=p_origin
   AND s.enrollment_token_hash=p_session_hash
   AND s.enrollment_expires_at>clock_timestamp()
   AND s.enrollment_state='consent_recorded'
 FOR SHARE OF s,r;
 IF NOT FOUND THEN RETURN 0; END IF;
 RETURN paper_atproto_authority.revoke_oauth_generation(
   b.owner_webid,b.client_id,p_grant_id,p_expected);
END $fn$;

REVOKE ALL ON FUNCTION paper_atproto_authority.issue_session_oauth_generation(
 text,text,bytea,text,text,bigint) FROM PUBLIC;
REVOKE ALL ON FUNCTION paper_atproto_authority.revoke_session_oauth_generation(
 text,text,bytea,text,bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION paper_atproto_authority.issue_session_oauth_generation(
 text,text,bytea,text,text,bigint) TO paper_oauth_epoch_issuer;
GRANT EXECUTE ON FUNCTION paper_atproto_authority.revoke_session_oauth_generation(
 text,text,bytea,text,bigint) TO paper_oauth_epoch_revoker;

-- No LOGIN is provisioned here. Function owner must be distinct from the
-- restricted issuer/revoker LOGIN and the normal provider/Jena runtime.
COMMIT;
