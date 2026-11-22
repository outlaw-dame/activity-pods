#!/usr/bin/env bash
set -Eeuo pipefail
# NONACTIVATED DISPOSABLE operational proof of real PG18 physical base backup,
# independently archived WAL, and named-point PITR for TWO failure domains.
# NEVER run this against a real provider, any existing Docker volume or
# account. This does NOT create an immutable external archive or test PDS.
if [[ "${PAPER_PITR_DISPOSABLE:-}" != confirmed || "${CI:-}" != true ]]; then
  echo 'Refusing physical PITR without disposable CI gate' >&2
  exit 2
fi
command -v docker >/dev/null
command -v sudo >/dev/null
image='postgres:18@sha256:2ea8630df176ad090ec92136dee850397c5af8781e4bcf2e4162593691c61bbc'
work="$(mktemp -d)"
# All Docker names and paths are generated locally; never use external input.
suffix="$$-$RANDOM"
containers=()
cleanup() {
  local status=$?
  trap - EXIT
  for name in "${containers[@]}"; do
    docker rm -f "$name" >/dev/null 2>&1 || true
  done
  if [[ -n "$work" && -d "$work" ]]; then
    sudo rm -rf -- "$work" || true
  fi
  exit "$status"
}
trap cleanup EXIT
wait_ready() {
  local name="$1" i
  for ((i=0;i<80;i++)); do
    if docker exec "$name" pg_isready -U postgres -d proof \
      >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.5
  done
  echo "PostgreSQL failed health check: $name" >&2
  docker logs --tail 80 "$name" >&2 || true
  return 1
}
sql() {
  local name="$1"
  shift
  docker exec -u postgres "$name" psql -X -v ON_ERROR_STOP=1 \
    -U postgres -d proof "$@"
}
assert_epoch() {
  local name="$1" expected="$2" expected_state="$3" actual
  actual="$(sql "$name" -Atqc \
    "SELECT epoch::text||':'||state FROM paper_pitr_probe WHERE id='paper';")"
  if [[ "$actual" != "${expected}:${expected_state}" ]]; then
    echo "Unexpected recovered authority state from $name: $actual" >&2
    return 1
  fi
}
start_source() {
  local role="$1" name="paper-pitr-${suffix}-${role}"
  mkdir -p "$work/source-$role" "$work/archive-$role" "$work/backup-$role"
  # Every subdirectory is inside the private mktemp parent; the fixture
  # postgres UNIX user must be able to create archived WAL and backups.
  chmod 0777 "$work/archive-$role" "$work/backup-$role"
  docker run -d --network none --name "$name" \
    -e POSTGRES_USER=postgres -e POSTGRES_PASSWORD=disposable_local_only \
    -e POSTGRES_DB=proof -e POSTGRES_INITDB_ARGS=--data-checksums \
    -v "$work/source-$role:/var/lib/postgresql" \
    -v "$work/archive-$role:/walarchive" \
    -v "$work/backup-$role:/backup" \
    "$image" postgres -c wal_level=replica -c archive_mode=on \
    -c "archive_command=test ! -f /walarchive/%f && cp %p /walarchive/%f || cmp -s %p /walarchive/%f" \
    -c max_wal_senders=10 -c archive_timeout=0 >/dev/null
  containers+=("$name")
  wait_ready "$name"
  sql "$name" -c "CREATE TABLE paper_pitr_probe (
    id text PRIMARY KEY,
    epoch bigint NOT NULL CHECK(epoch>0),
    state text NOT NULL CHECK(state IN ('active','blocked'))
  );"
  sql "$name" -c \
    "INSERT INTO paper_pitr_probe VALUES('paper',1,'active');"
  assert_epoch "$name" 1 active
  # A real streamed physical base backup + manifest, not pg_dump.
  docker exec -u postgres "$name" pg_basebackup -U postgres \
    -D /backup/base -Fp -X stream --checkpoint=fast
  docker exec -u postgres "$name" pg_verifybackup /backup/base
  local base="$work/backup-$role/base"
  [[ -s "$base/backup_manifest" && -s "$base/PG_VERSION" ]] || {
    echo "Missing physical base backup for $role" >&2; return 1;
  }
  local old_segment last_segment
  old_segment="$(sql "$name" -Atqc \
    "SELECT pg_walfile_name(pg_create_restore_point('paper_before_revoke'));")"
  sql "$name" -c \
    "UPDATE paper_pitr_probe SET epoch=2,state='blocked' WHERE id='paper';"
  assert_epoch "$name" 2 blocked
  last_segment="$(sql "$name" -Atqc \
    "SELECT pg_walfile_name(pg_create_restore_point('paper_after_revoke'));")"
  sql "$name" -Atqc 'SELECT pg_switch_wal();' >/dev/null
  local i
  for ((i=0;i<80;i++)); do
    if [[ -s "$work/archive-$role/$old_segment" &&
          -s "$work/archive-$role/$last_segment" ]]; then break; fi
    sleep 0.5
  done
  [[ -s "$work/archive-$role/$old_segment" &&
     -s "$work/archive-$role/$last_segment" ]] || {
    echo "Missing archived WAL for $role" >&2
    return 1
  }
}
restore_at() {
  local role="$1" point="$2" name="paper-pitr-${suffix}-${role}-${point}"
  local dest="$work/restore-$role-$point"
  mkdir -p "$dest/18/docker"
  # Copy the already verified physical backup; NEVER link the source PGDATA.
  sudo cp -a "$work/backup-$role/base/." "$dest/18/docker/"
  sudo tee -a "$dest/18/docker/postgresql.auto.conf" >/dev/null <<EOF
restore_command = 'cp /walarchive/%f %p'
recovery_target_name = 'paper_${point}_revoke'
recovery_target_action = 'promote'
recovery_target_timeline = 'current'
EOF
  sudo touch "$dest/18/docker/recovery.signal"
  sudo chown -R "$postgres_uid:$postgres_gid" "$dest"
  docker run -d --network none --name "$name" \
    -v "$dest:/var/lib/postgresql" \
    -v "$work/archive-$role:/walarchive:ro" \
    "$image" postgres -c archive_mode=off >/dev/null
  containers+=("$name")
  wait_ready "$name"
  local active
  active="$(sql "$name" -Atqc 'SELECT pg_is_in_recovery();')"
  [[ "$active" == f ]] || {
    echo "PITR did not promote at named target: $name" >&2
    return 1
  }
  if [[ "$point" == before ]]; then
    assert_epoch "$name" 1 active
  else
    assert_epoch "$name" 2 blocked
  fi
  local original="paper-pitr-${suffix}-${role}" original_id restored_id
  original_id="$(sql "$original" -Atqc \
    'SELECT system_identifier::text FROM pg_control_system();')"
  restored_id="$(sql "$name" -Atqc \
    'SELECT system_identifier::text FROM pg_control_system();')"
  [[ "$original_id" == "$restored_id" ]] || {
    echo "Restored PGDATA has unexpected system identifier" >&2
    return 1
  }
}
# Every replica must be a different PG18 data directory and WAL archive.
docker pull "$image" >/dev/null
postgres_uid="$(docker run --rm --entrypoint id "$image" -u postgres)"
postgres_gid="$(docker run --rm --entrypoint id "$image" -g postgres)"
start_source primary
start_source witness
primary_id="$(sql "paper-pitr-${suffix}-primary" -Atqc \
 'SELECT system_identifier::text FROM pg_control_system();')"
witness_id="$(sql "paper-pitr-${suffix}-witness" -Atqc \
 'SELECT system_identifier::text FROM pg_control_system();')"
[[ "$primary_id" != "$witness_id" ]] || {
  echo 'Primary and witness shared PostgreSQL system identifier' >&2
  exit 1
}
for role in primary witness; do
  restore_at "$role" before
  restore_at "$role" after
done
# An independent epoch=2 receipt is an EXTERNAL assumption; it is NOT
# supplied by the old physical snapshots. Both pre-revocation physical
# restores have epoch=1 and therefore MUST NOT be accepted as current.
for role in primary witness; do
  actual="$(sql "paper-pitr-${suffix}-${role}-before" -Atqc \
   "SELECT epoch::text FROM paper_pitr_probe WHERE id='paper';")"
  [[ "$actual" != 2 ]] || exit 1
done
echo 'PASS: two independent PG18 physical pg_basebackup/pg_verifybackup, archived-WAL PITR to named before/after revoke points, old dual restore distinguished from external high-water; external WORM and hosted OAuth remain P0, release CLOSED'
