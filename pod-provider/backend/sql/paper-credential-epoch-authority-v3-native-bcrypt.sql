-- NONACTIVATED disposable PostgreSQL18 integration, after:
-- paper-local-native-auth.sql,
-- paper-credential-epoch-authority-v1.sql and
-- paper-credential-epoch-authority-v2-certified-head.sql.
-- Never auto-migrate by production services or enable signup on this proof.
-- The native account store's generic UPDATE(data), INSERT and DELETE rights
-- must not bypass revocation or replace a tracked unified owner.
BEGIN;
DO $roles$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles
                 WHERE rolname='paper_credential_native_writer') THEN
    CREATE ROLE paper_credential_native_writer NOLOGIN NOINHERIT;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles
                 WHERE rolname='paper_credential_native_attestor') THEN
    CREATE ROLE paper_credential_native_attestor NOLOGIN NOINHERIT;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles
                 WHERE rolname='paper_credential_native_sealer') THEN
    CREATE ROLE paper_credential_native_sealer NOLOGIN NOINHERIT;
  END IF;
END
$roles$;
GRANT USAGE ON SCHEMA paper_credential_epoch TO
  paper_credential_native_writer,
  paper_credential_native_attestor,
  paper_credential_native_sealer;

CREATE TABLE paper_credential_epoch.native_writes (
  operation_id uuid PRIMARY KEY,
  webid text NOT NULL REFERENCES paper_credential_epoch.owners(webid),
  following_epoch bigint NOT NULL CHECK(following_epoch > 1),
  old_hash_sha256 bytea NOT NULL CHECK(octet_length(old_hash_sha256)=32),
  new_hash_sha256 bytea NOT NULL CHECK(octet_length(new_hash_sha256)=32),
  receipt_sha256 bytea NOT NULL CHECK(octet_length(receipt_sha256)=32),
  writing_xid xid8 NOT NULL,
  written_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  UNIQUE(webid,following_epoch)
);
REVOKE ALL ON paper_credential_epoch.native_writes FROM PUBLIC;
REVOKE ALL ON paper_credential_epoch.native_writes FROM
  paper_credential_reader, paper_credential_coordinator,
  paper_credential_enroller, paper_private_auth_runtime;

-- Generic SemApps accounts UPDATE(data) is retained for NONcredential
-- preferences. The PostgreSQL trigger enforces the boundary even if an
-- untrusted adapter or action tries a direct bcrypt update. A writer must
-- first atomically record an op-specific receipt in THIS transaction.
CREATE FUNCTION paper_credential_epoch.guard_native_account()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog AS $guard$
BEGIN
  IF TG_OP='UPDATE' THEN
    IF NEW.data->>'hashedPassword' IS DISTINCT FROM
       OLD.data->>'hashedPassword' THEN
      IF NOT EXISTS (
        SELECT 1 FROM paper_credential_epoch.native_writes w
        JOIN paper_credential_epoch.owners e ON e.webid=w.webid
        WHERE w.webid=OLD.data->>'webId'
          AND OLD.data->>'webId'=NEW.data->>'webId'
          AND w.writing_xid=pg_catalog.pg_current_xact_id()
          AND w.new_hash_sha256=pg_catalog.sha256(
            pg_catalog.convert_to(NEW.data->>'hashedPassword','UTF8'))
          AND e.state='pending'
          AND e.operation_id=w.operation_id
          AND e.next_epoch=w.following_epoch
      ) THEN
        RAISE EXCEPTION 'Credential change requires a pending owner operation'
          USING ERRCODE='42501';
      END IF;
    END IF;
    RETURN NEW;
  ELSIF TG_OP='DELETE' THEN
    -- No ordinary storage adapter may delete a fully claimed owner and
    -- reinsert a new bcrypt record under the same WebID.
    IF OLD.data ? 'signupReservationId'
       OR EXISTS (SELECT 1 FROM paper_credential_epoch.owners e
                  WHERE e.webid=OLD.data->>'webId') THEN
      RAISE EXCEPTION 'Unified account requires supervised tombstone'
        USING ERRCODE='42501';
    END IF;
    RETURN OLD;
  ELSIF TG_OP='INSERT' THEN
    IF NEW.data ? 'webId' AND EXISTS (
       SELECT 1 FROM paper_credential_epoch.owners e
       WHERE e.webid=NEW.data->>'webId'
    ) THEN
      RAISE EXCEPTION 'Existing credential owner cannot be replaced'
        USING ERRCODE='42501';
    END IF;
    RETURN NEW;
  END IF;
  RAISE EXCEPTION 'Invalid account trigger action' USING ERRCODE='42501';
END
$guard$;
REVOKE ALL ON FUNCTION paper_credential_epoch.guard_native_account() FROM PUBLIC;
CREATE TRIGGER paper_native_epoch_guard
BEFORE INSERT OR UPDATE OF data OR DELETE ON paper_private_auth.accounts
FOR EACH ROW EXECUTE FUNCTION paper_credential_epoch.guard_native_account();

-- Only this separate LOGIN/role may write a bcrypt credential. Upstream
-- SemApps must authenticate the actual owner BEFORE requesting a pending
-- operation. A UUID or WebID alone is never sufficient owner authority.
CREATE FUNCTION paper_credential_epoch.write_native_bcrypt(
  p_webid text,p_operation uuid,p_following_epoch bigint,p_bcrypt text
) RETURNS bytea
LANGUAGE plpgsql VOLATILE STRICT SECURITY DEFINER
SET search_path=pg_catalog AS $write$
DECLARE
  o paper_credential_epoch.owners%ROWTYPE;
  a_id uuid;
  old_bcrypt text;
  r bytea;
  changed integer;
BEGIN
  -- Bcrypt encoded hash only, NEVER an unhashed password or client JWT.
  -- Minimum work factor 10. The actual hash is created by SemApps.
  IF p_bcrypt !~ E'^\\$2[aby]\\$(1[0-9]|2[0-9]|3[01])\\$[./A-Za-z0-9]{53}$'
     OR pg_catalog.octet_length(p_bcrypt)<>60 THEN RETURN NULL; END IF;
  SELECT * INTO o FROM paper_credential_epoch.owners e
    WHERE e.webid=p_webid FOR UPDATE;
  IF NOT FOUND OR o.state<>'pending' OR
     o.operation_id IS DISTINCT FROM p_operation OR
     o.next_epoch IS DISTINCT FROM p_following_epoch THEN RETURN NULL; END IF;
  SELECT a.id,a.data->>'hashedPassword' INTO a_id,old_bcrypt
  FROM paper_private_auth.accounts a
  WHERE a.data->>'webId'=p_webid AND a.data ? 'signupReservationId'
  FOR UPDATE;
  IF NOT FOUND OR old_bcrypt IS NULL OR
     old_bcrypt=p_bcrypt THEN RETURN NULL; END IF;

  r:=pg_catalog.sha256(pg_catalog.convert_to(
    pg_catalog.jsonb_build_array('paper.credential.native-write.v1',
      p_webid,p_operation::text,p_following_epoch::text,p_bcrypt)::text,
    'UTF8'));
  INSERT INTO paper_credential_epoch.native_writes
    (operation_id,webid,following_epoch,old_hash_sha256,new_hash_sha256,
      receipt_sha256,writing_xid)
  VALUES (p_operation,p_webid,p_following_epoch,
    pg_catalog.sha256(pg_catalog.convert_to(old_bcrypt,'UTF8')),
    pg_catalog.sha256(pg_catalog.convert_to(p_bcrypt,'UTF8')),
    r,pg_catalog.pg_current_xact_id());
  UPDATE paper_private_auth.accounts a
    SET data=pg_catalog.jsonb_set(a.data,'{hashedPassword}',
      pg_catalog.to_jsonb(p_bcrypt),true)
    WHERE a.id=a_id;
  GET DIAGNOSTICS changed=ROW_COUNT;
  IF changed<>1 THEN
    RAISE EXCEPTION 'Native password write was not persisted'
      USING ERRCODE='55000';
  END IF;
  RETURN r;
END
$write$;

-- Reader gives a remote independent attestor *only* exact operation
-- correlation and NEVER hashes, user profiles or credentials.
CREATE FUNCTION paper_credential_epoch.confirm_native_write(
  p_webid text,p_operation uuid,p_following_epoch bigint,p_receipt bytea
) RETURNS boolean LANGUAGE sql STABLE STRICT SECURITY DEFINER
SET search_path=pg_catalog AS $confirm$
 SELECT EXISTS (
   SELECT 1 FROM paper_credential_epoch.owners o
   JOIN paper_credential_epoch.native_writes w
     ON w.webid=o.webid AND w.operation_id=o.operation_id
       AND w.following_epoch=o.next_epoch
   JOIN paper_private_auth.accounts a ON a.data->>'webId'=o.webid
   WHERE o.webid=p_webid AND o.state='pending'
     AND o.operation_id=p_operation AND o.next_epoch=p_following_epoch
     AND w.receipt_sha256=p_receipt AND pg_catalog.octet_length(p_receipt)=32
     AND w.new_hash_sha256=pg_catalog.sha256(
       pg_catalog.convert_to(a.data->>'hashedPassword','UTF8'))
     AND a.data ? 'signupReservationId'
 );
$confirm$;

-- The old general-purpose digest-only seal allowed a coordinator to
-- provide a fabricated 32-byte digest. Remove its execute privilege.
-- Native sealing now requires an operation-bound persisted bcrypt
-- readback and a distinct sealer role. The external independent signer
-- MUST acknowledge the new checkpoint before any production admission.
REVOKE EXECUTE ON FUNCTION
  paper_credential_epoch.seal_change(text,uuid,bigint,bytea)
  FROM paper_credential_coordinator;
CREATE FUNCTION paper_credential_epoch.seal_verified_native(
  p_webid text,p_operation uuid,p_following_epoch bigint,p_receipt bytea
) RETURNS boolean
LANGUAGE plpgsql VOLATILE STRICT SECURITY DEFINER
SET search_path=pg_catalog AS $seal$
DECLARE
  native_ok boolean;
  changed integer;
BEGIN
  PERFORM 1 FROM paper_credential_epoch.owners o
    WHERE o.webid=p_webid FOR UPDATE;
  IF NOT FOUND THEN RETURN false; END IF;
  SELECT paper_credential_epoch.confirm_native_write(
    p_webid,p_operation,p_following_epoch,p_receipt) INTO native_ok;
  IF native_ok IS DISTINCT FROM true THEN RETURN false; END IF;
  UPDATE paper_credential_epoch.owners o SET
    epoch=o.next_epoch,state='active',operation_id=NULL,next_epoch=NULL,
    mutation_digest=p_receipt,updated_at=pg_catalog.clock_timestamp()
  WHERE o.webid=p_webid AND o.state='pending'
    AND o.operation_id=p_operation AND o.next_epoch=p_following_epoch
    AND o.next_epoch>o.epoch;
  GET DIAGNOSTICS changed=ROW_COUNT;
  RETURN changed=1;
END
$seal$;

REVOKE ALL ON FUNCTION
  paper_credential_epoch.write_native_bcrypt(text,uuid,bigint,text)
  FROM PUBLIC;
REVOKE ALL ON FUNCTION
  paper_credential_epoch.confirm_native_write(text,uuid,bigint,bytea)
  FROM PUBLIC;
REVOKE ALL ON FUNCTION
  paper_credential_epoch.seal_verified_native(text,uuid,bigint,bytea)
  FROM PUBLIC;
GRANT EXECUTE ON FUNCTION
  paper_credential_epoch.write_native_bcrypt(text,uuid,bigint,text)
  TO paper_credential_native_writer;
GRANT EXECUTE ON FUNCTION
  paper_credential_epoch.confirm_native_write(text,uuid,bigint,bytea)
  TO paper_credential_native_attestor,paper_credential_native_sealer;
GRANT EXECUTE ON FUNCTION
  paper_credential_epoch.seal_verified_native(text,uuid,bigint,bytea)
  TO paper_credential_native_sealer;
COMMIT;
