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
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  delivered_at timestamptz,
  UNIQUE (did, commit_cid),
  CHECK ((status = 'pending' AND delivered_at IS NULL) OR
         (status = 'delivered' AND delivered_at IS NOT NULL)),
  FOREIGN KEY (did, commit_cid) REFERENCES paper_atproto_repo_proof.blocks(did, cid)
);

CREATE INDEX pending_atproto_native_events
ON paper_atproto_repo_proof.native_event_outbox (id)
WHERE status = 'pending';

REVOKE ALL ON ALL TABLES IN SCHEMA paper_atproto_repo_proof FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA paper_atproto_repo_proof FROM PUBLIC;
COMMIT;
