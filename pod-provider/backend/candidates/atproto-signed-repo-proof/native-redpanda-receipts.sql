-- NONACTIVATED disposable proof: one durable consumer-effect receipt per signed
-- native event. This is NOT an account authority or a production migration.
-- Requires schema.sql and single-record-mutation.sql in a disposable PG18.
BEGIN;
CREATE TABLE paper_atproto_repo_proof.native_broker_receipts (
  did text COLLATE "C" NOT NULL,
  commit_cid text COLLATE "C" NOT NULL,
  event_seq bigint NOT NULL CHECK (event_seq > 0),
  rev text COLLATE "C" NOT NULL
    CHECK (rev ~ '^[234567abcdefghij][234567abcdefghijklmnopqrstuvwxyz]{12}$'),
  payload_sha256 bytea NOT NULL CHECK (octet_length(payload_sha256)=32),
  topic text COLLATE "C" NOT NULL CHECK (length(topic) BETWEEN 3 AND 201),
  partition_id integer NOT NULL CHECK (partition_id >= 0),
  first_offset bigint NOT NULL CHECK (first_offset >= 0),
  first_seen_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (did,commit_cid),
  UNIQUE (topic,partition_id,first_offset),
  FOREIGN KEY (did,commit_cid)
    REFERENCES paper_atproto_repo_proof.native_event_outbox(did,commit_cid),
  FOREIGN KEY (did) REFERENCES paper_atproto_repo_proof.repos(did)
);
REVOKE ALL ON paper_atproto_repo_proof.native_broker_receipts FROM PUBLIC;
COMMIT;
