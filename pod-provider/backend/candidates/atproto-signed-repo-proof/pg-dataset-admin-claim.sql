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
COMMIT;
