-- Isolated candidate ONLY; not registered as the live Solid-OIDC/SAI grant writer.
-- Run after paper-groups-postgres-candidate-v1.sql in a disposable database.
-- Revoke intent and the consent deny bit commit in the SAME transaction.
BEGIN;
CREATE TABLE paper_groups_candidate.consent_revocations (
  owner_webid text NOT NULL,
  app_uri text NOT NULL,
  operation_id uuid NOT NULL,
  revision bigint NOT NULL CHECK (revision > 1),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (owner_webid, app_uri, operation_id),
  UNIQUE (owner_webid, app_uri, revision),
  FOREIGN KEY (owner_webid, app_uri)
    REFERENCES paper_groups_candidate.consent(owner_webid, app_uri)
);
-- Deliberately no new global index or per-member audit rows.
REVOKE ALL ON paper_groups_candidate.consent_revocations FROM PUBLIC;
COMMIT;
