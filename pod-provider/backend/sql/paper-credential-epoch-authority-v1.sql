-- NONACTIVATED Paper credential epoch authority v1. Dedicated PostgreSQL 18
-- candidate only: neither a production migration nor an independent WORM head.
-- Install only on a disposable isolated cluster under the CI proof.
BEGIN;
DO $roles$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='paper_credential_reader') THEN
    CREATE ROLE paper_credential_reader NOLOGIN NOINHERIT;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='paper_credential_enroller') THEN
    CREATE ROLE paper_credential_enroller NOLOGIN NOINHERIT;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='paper_credential_coordinator') THEN
    CREATE ROLE paper_credential_coordinator NOLOGIN NOINHERIT;
  END IF;
END
$roles$;
CREATE SCHEMA paper_credential_epoch;
REVOKE ALL ON SCHEMA paper_credential_epoch FROM PUBLIC;
CREATE TABLE paper_credential_epoch.owners (
  webid text PRIMARY KEY,
  mode text NOT NULL DEFAULT 'unified' CHECK(mode='unified'),
  epoch bigint NOT NULL CHECK(epoch > 0),
  state text NOT NULL CHECK(state IN ('active','pending','disabled')),
  operation_id uuid,
  next_epoch bigint,
  mutation_digest bytea,
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CONSTRAINT paper_credential_state_consistent CHECK (
    (state='pending' AND operation_id IS NOT NULL AND next_epoch IS NOT NULL
      AND next_epoch > epoch AND mutation_digest IS NULL)
    OR (state IN ('active','disabled') AND operation_id IS NULL
      AND next_epoch IS NULL)
  )
);
REVOKE ALL ON TABLE paper_credential_epoch.owners FROM PUBLIC;
GRANT USAGE ON SCHEMA paper_credential_epoch
  TO paper_credential_reader,paper_credential_enroller,paper_credential_coordinator;
-- The only admission interface. Every request must additionally reconcile
-- an independently fresh, signed, nonrewindable external credential head.
CREATE FUNCTION paper_credential_epoch.read_owner(p_webid text)
RETURNS TABLE(mode text,state text,epoch bigint)
LANGUAGE sql STABLE STRICT SECURITY DEFINER
SET search_path=pg_catalog
AS $read$
 SELECT o.mode,o.state,o.epoch FROM paper_credential_epoch.owners o
 WHERE o.webid=p_webid;
$read$;
-- Enrollment is irreversible. It requires a separately authenticated
-- complete unified signup; this SQL function alone does not prove ownership.
CREATE FUNCTION paper_credential_epoch.enroll_owner(p_webid text)
RETURNS boolean
LANGUAGE plpgsql VOLATILE STRICT SECURITY DEFINER
SET search_path=pg_catalog
AS $enroll$
BEGIN
 IF length(p_webid)<8 OR length(p_webid)>2048 OR
    p_webid !~ '^https://[^[:space:]/?#]+(/[^[:space:]?#]*)?$' THEN
   RETURN false;
 END IF;
 INSERT INTO paper_credential_epoch.owners(webid,epoch,state)
 VALUES(p_webid,1,'active')
 ON CONFLICT (webid) DO NOTHING;
 RETURN FOUND;
END
$enroll$;
-- Serialized durable fence must commit BEFORE the SemApps password write.
-- No caller can clear pending by repeating a begin or switching op ids.
CREATE FUNCTION paper_credential_epoch.begin_change(
 p_webid text,p_op uuid,p_expected_epoch bigint)
RETURNS TABLE(previous_epoch bigint,following_epoch bigint)
LANGUAGE plpgsql VOLATILE STRICT SECURITY DEFINER
SET search_path=pg_catalog
AS $begin$
BEGIN
 IF p_expected_epoch<=0 OR p_expected_epoch>=9223372036854775807 THEN
   RETURN;
 END IF;
 RETURN QUERY
 UPDATE paper_credential_epoch.owners o
 SET state='pending',operation_id=p_op,next_epoch=o.epoch+1,
     mutation_digest=NULL,updated_at=clock_timestamp()
 WHERE o.webid=p_webid AND o.state='active' AND o.epoch=p_expected_epoch
 RETURNING o.epoch,o.next_epoch;
END
$begin$;
-- This seals ONLY a pending operation with a bound 32-byte downstream
-- mutation receipt digest. The caller must authenticate the receipt against
-- the durable SemApps credential write; the digest alone is NOT evidence.
-- Unknown outcome never auto-seals or rolls back the pending fence.
CREATE FUNCTION paper_credential_epoch.seal_change(
 p_webid text,p_op uuid,p_next_epoch bigint,p_receipt_sha256 bytea)
RETURNS boolean
LANGUAGE plpgsql VOLATILE STRICT SECURITY DEFINER
SET search_path=pg_catalog
AS $seal$
BEGIN
 IF length(p_receipt_sha256)<>32 OR p_next_epoch<=1 THEN
   RETURN false;
 END IF;
 UPDATE paper_credential_epoch.owners o
 SET epoch=o.next_epoch,state='active',operation_id=NULL,next_epoch=NULL,
     mutation_digest=p_receipt_sha256,updated_at=clock_timestamp()
 WHERE o.webid=p_webid AND o.state='pending' AND o.operation_id=p_op
   AND o.next_epoch=p_next_epoch;
 RETURN FOUND;
END
$seal$;
-- An administrative disable is monotonic and terminal. Never allow a
-- restored or disabled owner to re-enroll or resume pending mutations.
CREATE FUNCTION paper_credential_epoch.disable_owner(p_webid text)
RETURNS boolean
LANGUAGE plpgsql VOLATILE STRICT SECURITY DEFINER
SET search_path=pg_catalog
AS $disable$
BEGIN
 UPDATE paper_credential_epoch.owners o
 SET epoch=CASE WHEN o.state='pending' THEN o.next_epoch ELSE o.epoch+1 END,
     state='disabled',operation_id=NULL,next_epoch=NULL,
     mutation_digest=NULL,updated_at=clock_timestamp()
 WHERE o.webid=p_webid AND o.state<>'disabled'
   AND o.epoch<9223372036854775807;
 RETURN FOUND;
END
$disable$;
REVOKE ALL ON FUNCTION paper_credential_epoch.read_owner(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION paper_credential_epoch.enroll_owner(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION paper_credential_epoch.begin_change(text,uuid,bigint) FROM PUBLIC;
REVOKE ALL ON FUNCTION paper_credential_epoch.seal_change(text,uuid,bigint,bytea) FROM PUBLIC;
REVOKE ALL ON FUNCTION paper_credential_epoch.disable_owner(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION paper_credential_epoch.read_owner(text) TO paper_credential_reader;
GRANT EXECUTE ON FUNCTION paper_credential_epoch.enroll_owner(text) TO paper_credential_enroller;
GRANT EXECUTE ON FUNCTION paper_credential_epoch.begin_change(text,uuid,bigint)
  TO paper_credential_coordinator;
GRANT EXECUTE ON FUNCTION paper_credential_epoch.seal_change(text,uuid,bigint,bytea)
  TO paper_credential_coordinator;
GRANT EXECUTE ON FUNCTION paper_credential_epoch.disable_owner(text)
  TO paper_credential_coordinator;
COMMIT;
