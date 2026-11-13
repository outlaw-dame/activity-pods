-- Disposable extension of the existing signed-v3 repo proof, NOT a new
-- account authority or production migration. Apply AFTER schema.sql.
-- Allows a bounded signed record commit to advance the authoritative head,
-- with a durable event + RDF projection recovery intent in the SAME tx.
BEGIN;
ALTER TABLE paper_atproto_repo_proof.repos
  DROP CONSTRAINT repos_generation_check;
ALTER TABLE paper_atproto_repo_proof.repos
  ADD CONSTRAINT repos_generation_check CHECK (generation >= 1);
ALTER TABLE paper_atproto_repo_proof.rdf_projection_jobs
  DROP CONSTRAINT rdf_projection_jobs_generation_check;
ALTER TABLE paper_atproto_repo_proof.rdf_projection_jobs
  ADD CONSTRAINT rdf_projection_jobs_generation_check CHECK (generation >= 1);

-- Immutable per-commit mutation metadata for future at.commit event diffs.
-- No token, signer reference, private key, record JSON, or request credential.
CREATE TABLE paper_atproto_repo_proof.record_mutations (
  did text COLLATE "C" NOT NULL REFERENCES paper_atproto_repo_proof.repos(did),
  commit_cid text COLLATE "C" NOT NULL,
  previous_commit_cid text COLLATE "C" NOT NULL,
  previous_rev text COLLATE "C" NOT NULL
    CHECK (previous_rev ~ '^[234567abcdefghij][234567abcdefghijklmnopqrstuvwxyz]{12}$'),
  rev text COLLATE "C" NOT NULL
    CHECK (rev ~ '^[234567abcdefghij][234567abcdefghijklmnopqrstuvwxyz]{12}$'
       AND rev > previous_rev),
  action text COLLATE "C" NOT NULL CHECK (action IN ('create','update','delete')),
  path text COLLATE "C" NOT NULL CHECK (length(path) BETWEEN 3 AND 1024),
  previous_record_cid text COLLATE "C",
  record_cid text COLLATE "C",
  generation bigint NOT NULL CHECK (generation > 1),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (did, commit_cid),
  UNIQUE (did, generation),
  FOREIGN KEY (did, commit_cid)
    REFERENCES paper_atproto_repo_proof.blocks(did, cid),
  FOREIGN KEY (did, previous_commit_cid)
    REFERENCES paper_atproto_repo_proof.blocks(did, cid),
  CHECK ((action = 'create' AND previous_record_cid IS NULL AND record_cid IS NOT NULL)
      OR (action = 'update' AND previous_record_cid IS NOT NULL AND record_cid IS NOT NULL)
      OR (action = 'delete' AND previous_record_cid IS NOT NULL AND record_cid IS NULL))
);
REVOKE ALL ON paper_atproto_repo_proof.record_mutations FROM PUBLIC;
COMMIT;
