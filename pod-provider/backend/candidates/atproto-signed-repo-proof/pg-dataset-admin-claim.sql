-- TEST-ONLY until a separate privileged dataset administrator and a
-- provider-owned pre-account claim issuer have passed deployment acceptance.
-- One bounded row per canonical username, not per retry, account event,
-- IP address, request, or Pod resource.
BEGIN;
CREATE SCHEMA paper_dataset_admin_proof;
REVOKE ALL ON SCHEMA paper_dataset_admin_proof FROM PUBLIC;
CREATE TABLE paper_dataset_admin_proof.claims (
  dataset text PRIMARY KEY,
  owner_webid text NOT NULL UNIQUE,
  reservation_id uuid NOT NULL UNIQUE,
  signed_ticket_sha256 bytea NOT NULL UNIQUE
    CHECK (octet_length(signed_ticket_sha256)=32),
  state text NOT NULL DEFAULT 'pending'
    CHECK (state IN ('pending','created')),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  completed_at timestamptz,
  CHECK (dataset ~ '^[a-z][a-z0-9_-]{1,31}$'),
  CHECK ((state='created') = (completed_at IS NOT NULL))
);
REVOKE ALL ON ALL TABLES IN SCHEMA paper_dataset_admin_proof FROM PUBLIC;
DO $
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles
                 WHERE rolname='paper_dataset_admin_agent') THEN
    CREATE ROLE paper_dataset_admin_agent NOLOGIN
      NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
  END IF;
END $;
REVOKE ALL ON SCHEMA paper_dataset_admin_proof FROM paper_dataset_admin_agent;
GRANT USAGE ON SCHEMA paper_dataset_admin_proof TO paper_dataset_admin_agent;
GRANT SELECT (dataset,owner_webid,reservation_id,signed_ticket_sha256,
              state,completed_at)
  ON paper_dataset_admin_proof.claims TO paper_dataset_admin_agent;
GRANT INSERT (dataset,owner_webid,reservation_id,signed_ticket_sha256)
  ON paper_dataset_admin_proof.claims TO paper_dataset_admin_agent;
GRANT UPDATE (state,completed_at)
  ON paper_dataset_admin_proof.claims TO paper_dataset_admin_agent;
COMMIT;
