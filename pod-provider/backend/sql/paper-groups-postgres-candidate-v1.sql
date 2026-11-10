-- Experimental Group control-plane candidate, PostgreSQL 18.
-- DO NOT install in production or expose to a Data API.
-- A later single-authority migration must bind Solid-OIDC/SAI revocations
-- to these rows BEFORE enabling any Group writes.
BEGIN;
CREATE SCHEMA IF NOT EXISTS paper_groups_candidate;
REVOKE ALL ON SCHEMA paper_groups_candidate FROM PUBLIC;

CREATE TABLE paper_groups_candidate.identities (
  webid text PRIMARY KEY
    CHECK (length(webid) BETWEEN 8 AND 2048),
  enabled boolean NOT NULL DEFAULT true,
  lifecycle_revision bigint NOT NULL DEFAULT 1 CHECK (lifecycle_revision > 0)
);

CREATE TABLE paper_groups_candidate.consent (
  owner_webid text NOT NULL REFERENCES paper_groups_candidate.identities(webid),
  app_uri text NOT NULL CHECK (length(app_uri) BETWEEN 8 AND 2048),
  granted boolean NOT NULL DEFAULT false,
  revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
  PRIMARY KEY (owner_webid, app_uri)
);

CREATE TABLE paper_groups_candidate.groups (
  group_id text PRIMARY KEY CHECK (group_id ~ '^cg_[0-9a-f]{32}$'),
  owner_webid text NOT NULL REFERENCES paper_groups_candidate.identities(webid),
  app_uri text NOT NULL,
  revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
  visibility text NOT NULL DEFAULT 'public'
    CHECK (visibility IN ('public', 'restricted', 'private')),
  state text NOT NULL DEFAULT 'reserved'
    CHECK (state IN ('reserved', 'active', 'suspended')),
  FOREIGN KEY (owner_webid, app_uri)
    REFERENCES paper_groups_candidate.consent(owner_webid, app_uri)
);

CREATE TABLE paper_groups_candidate.members (
  group_id text NOT NULL REFERENCES paper_groups_candidate.groups(group_id),
  actor_uri text NOT NULL CHECK (length(actor_uri) BETWEEN 8 AND 2048),
  role text NOT NULL CHECK (role IN ('owner','admin','moderator','member')),
  status text NOT NULL CHECK
    (status IN ('active','invited','requested','left','banned')),
  change_revision bigint NOT NULL CHECK (change_revision > 0),
  PRIMARY KEY (group_id, actor_uri)
);
-- Efficient keyset pagination; membership/permission predicates and
-- revision are validated through the owning Group before row access.
CREATE INDEX members_active_by_group_actor
  ON paper_groups_candidate.members (group_id, actor_uri COLLATE "C")
  INCLUDE (role, change_revision) WHERE status = 'active';
CREATE INDEX members_pending_by_group
  ON paper_groups_candidate.members (group_id, status, actor_uri COLLATE "C")
  WHERE status IN ('invited','requested');

-- One durable event per canonical Group revision. This is a provider-side
-- transactional audit/handoff source, NOT another Fedify delivery queue.
-- Never send externally from this table without a separately verified
-- sealed recipient snapshot and APDM/Fedify handoff.
CREATE TABLE paper_groups_candidate.transitions (
  group_id text NOT NULL REFERENCES paper_groups_candidate.groups(group_id),
  revision bigint NOT NULL CHECK (revision > 1),
  actor_uri text NOT NULL,
  status text NOT NULL,
  role text NOT NULL,
  operation_id uuid NOT NULL,
  consent_revision bigint NOT NULL CHECK (consent_revision > 0),
  occurred_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (group_id, revision),
  UNIQUE (group_id, operation_id)
);
CREATE INDEX transitions_group_recent
  ON paper_groups_candidate.transitions (group_id, revision DESC);

-- Refuse default SQL table access from unrelated roles. The proof harness
-- uses a dedicated disposable DB owner; production requires narrowly
-- privileged service roles and evaluated RLS/SECURITY DEFINER semantics.
REVOKE ALL ON ALL TABLES IN SCHEMA paper_groups_candidate FROM PUBLIC;
COMMIT;
