-- NONACTIVATED canonical PG18 signed-repo candidate migration.
-- Run after schema.sql + single-record-mutation.sql; independently deployed
-- PG witness v2 lives in a DIFFERENT cluster. No cross-DB foreign key.
BEGIN;
ALTER TABLE paper_atproto_repo_proof.record_mutations
 ADD COLUMN witness_operation_id uuid;
CREATE UNIQUE INDEX paper_signed_mutation_witness_op_once
 ON paper_atproto_repo_proof.record_mutations(witness_operation_id)
 WHERE witness_operation_id IS NOT NULL;

-- Once the signed commit has correlated its recovery operation, the
-- immutable operation id can never be removed, reassigned or deleted.
-- The independent reconciler verifies this row, signed CID and durable
-- native outbox before settling its external witness intent.
CREATE FUNCTION paper_atproto_repo_proof.guard_witness_mutation_audit()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp AS $fn$
BEGIN
 IF TG_OP='DELETE' THEN
   IF OLD.witness_operation_id IS NOT NULL THEN
     RAISE EXCEPTION USING ERRCODE='P0001',
       MESSAGE='Witnessed signed mutation is immutable';
   END IF;
   RETURN OLD;
 END IF;
 IF NEW.witness_operation_id IS DISTINCT FROM OLD.witness_operation_id
    OR OLD.witness_operation_id IS NOT NULL THEN
   RAISE EXCEPTION USING ERRCODE='P0001',
     MESSAGE='Witness operation binding is immutable';
 END IF;
 RETURN NEW;
END $fn$;
CREATE TRIGGER immutable_witnessed_mutation
 BEFORE UPDATE OR DELETE ON paper_atproto_repo_proof.record_mutations
 FOR EACH ROW EXECUTE FUNCTION
 paper_atproto_repo_proof.guard_witness_mutation_audit();
REVOKE ALL ON FUNCTION
 paper_atproto_repo_proof.guard_witness_mutation_audit() FROM PUBLIC;
COMMIT;
