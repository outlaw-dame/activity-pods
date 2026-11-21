-- NONACTIVATED. Apply after canonical v4/v5 and the restricted
-- pg-restricted-writer-roles.sql migration have created the NOLOGIN writer.
-- Allow the signed writer to LOCK but never SELECT/INSERT/UPDATE/REVOKE
-- OAuth grants. It must call this in the SAME signed-head PG transaction.
BEGIN;
REVOKE ALL ON FUNCTION paper_atproto_authority.lock_oauth_generation_for_write(
  text,text,text,text,bytea,bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION paper_atproto_authority.lock_oauth_generation_for_write(
  text,text,text,text,bytea,bigint) TO paper_atproto_repo_writer;
COMMIT;
