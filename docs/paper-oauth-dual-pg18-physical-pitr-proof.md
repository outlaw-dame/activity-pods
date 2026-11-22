# Paper recovery — physical PostgreSQL 18 WAL/PITR rehearsal (NONACTIVATED)

The existing two-cluster witness and Redis rollback tests use real PostgreSQL
SQL transactions but **logical row resets**, not physical point-in-time restore.
The separate, disposable
`pod-provider/backend/scripts/proof-oauth-dual-pg18-physical-pitr.sh`
verifies the necessary *PostgreSQL physical mechanism* without touching any
production account, Redis namespace, Pod, database, object store or credential.

It starts TWO independently initialized PostgreSQL 18 systems with distinct
`system_identifier` values, physically separate `PGDATA` mounts and their
own WAL archives. Both use the same pinned PostgreSQL image digest as the
federation staging baseline, with data checksums and
`archive_mode=on`. There are no published ports or cross-container networks.

Each cluster inserts a synthetic epoch-1 `paper_pitr_probe` row, takes a
real streamed physical `pg_basebackup -X stream`, verifies the resulting
backup manifest via `pg_verifybackup`, places a named restore point,
changes the epoch to a blocked epoch-2 state, places a second named restore
point and forces WAL switch/archival. A new, separately mounted PostgreSQL
data directory is recovered twice from the physical backup with
`recovery.signal`, a read-only archived WAL mount,
`restore_command`, `recovery_target_name`, and
`recovery_target_action=promote`.

The proof requires recovered **before-revocation** clusters to contain the
old active epoch-1 marker, recovered **after-revocation** clusters to contain
the blocked epoch-2 marker, successful promotion out of recovery, identical
source-vs-restored system IDs for each cluster, and distinct system IDs
between the primary and independent witness. This demonstrates why blindly
trusting either physically restored database, or their agreement with each
other, is not enough: the newest independently immutable epoch-2 archive
checkpoint must also be consulted on every OAuth admission.

This is a real physical PostgreSQL recovery exercise, **not** yet
end-to-end Paper authority recovery. It uses a synthetic fixture table
rather than fully populated canonical Account/SAI/OAuth, signed PDS,
and external witness SQL schemas. WAL archive directories are ordinary
ephemeral local files, **not** write-once immutable storage. No hosted
failover or retention/IAM separation has been verified. PostgreSQL
physical backup checksums do not establish a non-rewindable external
authorization authority.

Production P0 still requires a separately administered immutable
retention-compliant archive, verification of both epoch and pending/
resolved signed-write intent receipts from that independent archive,
true complete high-water enumeration and chain/fork detection, primary
**and** witness recovery with real encrypted WAL and owner consent data,
a safe independent abort-proof barrier, constrained TLS runtime
identities, hosted browser OAuth, WebID/SAI, signed PDS/XRPC and
ActivityPub interoperability acceptance. Do not infer `release=OPEN`
from this disposable workflow; federation issue #186 stays OPEN.

## References

- [PostgreSQL 18 continuous archiving and PITR](https://www.postgresql.org/docs/18/continuous-archiving.html)
- [PostgreSQL 18 pg_basebackup](https://www.postgresql.org/docs/18/app-pgbasebackup.html)
- [PostgreSQL 18 pg_verifybackup](https://www.postgresql.org/docs/18/app-pgverifybackup.html)
- [PostgreSQL 18 WAL recovery settings](https://www.postgresql.org/docs/18/runtime-config-wal.html)
- [Official Docker PostgreSQL 18 PGDATA change](https://hub.docker.com/_/postgres)
