-- NONACTIVATED v2, after paper-credential-epoch-authority-v1.sql.
-- Expose immutable comparison fields via a function-only reader role.
-- Authoritative freshness is established by an independently operated,
-- challenge-bound Ed25519 signer, never by this rewindable PostgreSQL row.
BEGIN;
CREATE FUNCTION paper_credential_epoch.read_certified(p_webid text)
RETURNS TABLE(mode text,state text,epoch text,digest text)
LANGUAGE sql STABLE STRICT SECURITY DEFINER
SET search_path=pg_catalog
AS $read$
 SELECT o.mode,o.state,o.epoch::text,
   coalesce(encode(o.mutation_digest,'hex'),repeat('0',64))
 FROM paper_credential_epoch.owners o WHERE o.webid=p_webid;
$read$;
REVOKE ALL ON FUNCTION paper_credential_epoch.read_certified(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION paper_credential_epoch.read_certified(text)
  TO paper_credential_reader;
COMMIT;
