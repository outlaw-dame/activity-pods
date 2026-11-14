-- NON-ACTIVATED proof of a managed ATProto empty repository.
-- Dedicated isolated schema; not a Solid/ACL/account authority.
-- Only run against an explicitly disposable PostgreSQL 18 test database.
-- Never run this against live ActivityPods without a reviewed migration.
BEGIN;
CREATE SCHEMA paper_atproto_repo_proof;
REVOKE ALL ON SCHEMA paper_atproto_repo_proof FROM PUBLIC;

CREATE TABLE paper_atproto_repo_proof.repos (
  account_id text COLLATE "C" PRIMARY KEY
    CHECK (length(account_id) BETWEEN 10 AND 2048 AND account_id ~ '^https://[^[:space:]]+$'),
  did text COLLATE "C" NOT NULL UNIQUE CHECK (did ~ '^did:plc:[a-z2-7]{24}$'),
  rev text COLLATE "C" NOT NULL CHECK (rev ~ '^[234567abcdefghij][234567abcdefghijklmnopqrstuvwxyz]{12}$'),
  head_cid text COLLATE "C" NOT NULL CHECK (head_cid ~ '^bafy[a-z2-7]+$'),
  root_cid text COLLATE "C" NOT NULL CHECK (root_cid ~ '^bafy[a-z2-7]+$'),
  generation bigint NOT NULL DEFAULT 1 CHECK (generation = 1),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE paper_atproto_repo_proof.blocks (
  did text COLLATE "C" NOT NULL REFERENCES paper_atproto_repo_proof.repos(did),
  cid text COLLATE "C" NOT NULL CHECK (cid ~ '^bafy[a-z2-7]+$'),
  block bytea NOT NULL CHECK (octet_length(block) BETWEEN 1 AND 131072),
  PRIMARY KEY (did, cid)
);

CREATE TABLE paper_atproto_repo_proof.native_event_outbox (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  did text COLLATE "C" NOT NULL REFERENCES paper_atproto_repo_proof.repos(did),
  commit_cid text COLLATE "C" NOT NULL,
  rev text COLLATE "C" NOT NULL,
  kind text COLLATE "C" NOT NULL CHECK (kind = 'at.commit.v1'),
  status text COLLATE "C" NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','delivered')),
  attempt_count integer NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
  -- Durable lease/fence prevents concurrent acknowledgments by stale workers.
  lease_epoch bigint NOT NULL DEFAULT 0 CHECK (lease_epoch >= 0),
  lease_owner uuid,
  lease_until timestamptz,
  next_attempt_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  last_error_code text CHECK (length(last_error_code) <= 80),
  blocked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  delivered_at timestamptz,
  UNIQUE (did, commit_cid),
  CHECK ((status = 'pending' AND delivered_at IS NULL) OR
         (status = 'delivered' AND delivered_at IS NOT NULL)),
  CHECK ((lease_owner IS NULL) = (lease_until IS NULL)),
  CHECK (blocked_at IS NULL OR status = 'pending'),
  FOREIGN KEY (did, commit_cid) REFERENCES paper_atproto_repo_proof.blocks(did, cid)
);

CREATE INDEX pending_atproto_native_events
ON paper_atproto_repo_proof.native_event_outbox (id)
WHERE status = 'pending';

-- Exact due-queue claims and per-repository head ordering are indexed.
CREATE INDEX due_atproto_native_events
ON paper_atproto_repo_proof.native_event_outbox (next_attempt_at,id)
WHERE status = 'pending' AND blocked_at IS NULL;
CREATE INDEX pending_atproto_repo_order
ON paper_atproto_repo_proof.native_event_outbox (did,id)
WHERE status = 'pending';
-- Repository readiness must find terminally blocked *historical* events
-- via one indexed existence probe, independent of the latest commit.
CREATE INDEX blocked_atproto_repo_history
ON paper_atproto_repo_proof.native_event_outbox (did)
WHERE status = 'pending' AND blocked_at IS NOT NULL;


-- A crash-safe, non-activated PG->RDF projection ledger. Genesis repo + blocks
-- + native-event outbox + RDF recovery intent are one atomic transaction.
-- PostgreSQL lease_epoch is the monotonic fence, NOT a distributed mutex.
-- The eventual RDF writer MUST atomically reject an older fence in Jena.
-- This disposable table is not itself a production migration.
CREATE TABLE paper_atproto_repo_proof.rdf_projection_jobs (
  account_id text COLLATE "C" PRIMARY KEY REFERENCES paper_atproto_repo_proof.repos(account_id),
  did text COLLATE "C" NOT NULL,
  head_cid text COLLATE "C" NOT NULL,
  root_cid text COLLATE "C" NOT NULL,
  rev text COLLATE "C" NOT NULL,
  generation bigint NOT NULL DEFAULT 1 CHECK (generation = 1),
  state text COLLATE "C" NOT NULL DEFAULT 'pending'
    CHECK (state IN ('pending', 'leased', 'applied', 'blocked')),
  lease_epoch bigint NOT NULL DEFAULT 0 CHECK (lease_epoch >= 0),
  lease_owner uuid,
  lease_until timestamptz,
  attempt_count integer NOT NULL DEFAULT 0 CHECK (attempt_count BETWEEN 0 AND 1000),
  next_attempt_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  last_error_code text CHECK (length(last_error_code) <= 80),
  applied_at timestamptz,
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CHECK ((state = 'leased') = (lease_owner IS NOT NULL AND lease_until IS NOT NULL)),
  CHECK ((state = 'applied') = (applied_at IS NOT NULL)),
  FOREIGN KEY (did, head_cid) REFERENCES paper_atproto_repo_proof.blocks(did, cid),
  FOREIGN KEY (did, root_cid) REFERENCES paper_atproto_repo_proof.blocks(did, cid)
);

CREATE INDEX pending_rdf_projection_jobs
  ON paper_atproto_repo_proof.rdf_projection_jobs (next_attempt_at, account_id)
  WHERE state = 'pending';

CREATE INDEX expired_rdf_projection_leases
  ON paper_atproto_repo_proof.rdf_projection_jobs (lease_until, account_id)
  WHERE state = 'leased';

REVOKE ALL ON ALL TABLES IN SCHEMA paper_atproto_repo_proof FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA paper_atproto_repo_proof FROM PUBLIC;
COMMIT;
