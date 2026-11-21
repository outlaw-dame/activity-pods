-- NONACTIVATED PG18 extension after OAuth generation v4. Reader-only.
-- No server role may infer the current epoch from Redis or an unverified JWT.
BEGIN;
CREATE FUNCTION paper_atproto_authority.current_oauth_generation(
  p_owner text,p_app text,p_client text,p_grant text,p_scope_sha256 bytea
) RETURNS bigint
LANGUAGE sql STABLE STRICT SECURITY DEFINER
SET search_path=pg_catalog AS $fn$
  SELECT coalesce((
    SELECT e.revision
    FROM paper_atproto_authority.oauth_generations e
    JOIN paper_atproto_authority.consents s
      ON s.owner_webid=e.owner_webid AND s.app_uri=e.app_uri
    JOIN paper_atproto_authority.identities i ON i.owner_webid=e.owner_webid
    WHERE e.owner_webid=p_owner AND e.app_uri=p_app
      AND e.client_id=p_client AND e.grant_id=p_grant
      AND e.scope_sha256=p_scope_sha256 AND e.state='active'
      AND s.state='active' AND s.revision=e.sai_revision
      AND s.activation_operation IS NOT NULL
      AND s.activation_native_readback_at IS NOT NULL
      AND s.activation_request_sha256 IS NOT NULL
      AND i.state='active' AND i.managed=true
  ),0::bigint)
$fn$;
REVOKE ALL ON FUNCTION paper_atproto_authority.current_oauth_generation(
  text,text,text,text,bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION paper_atproto_authority.current_oauth_generation(
  text,text,text,text,bytea) TO paper_oauth_epoch_reader;
COMMIT;
