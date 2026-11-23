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
    # pg_isready can succeed against PostgreSQL's temporary initialization
    # server BEFORE the entrypoint creates POSTGRES_DB=proof. The temporary
    # bootstrap server listens only on Unix sockets (listen_addresses='').
    # Require local TCP readiness of the final permanent server AND a real
    # query against the intended named database to avoid both init races.
    if docker exec "$name" pg_isready -h 127.0.0.1 -U postgres -d proof \
      >/dev/null 2>&1 && \
      [[ "$(docker exec -u postgres "$name" psql -X -v ON_ERROR_STOP=1 \
        -U postgres -d proof -Atqc 'SELECT 1' 2>/dev/null || true)" == 1 ]]; then
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
# Check actual Paper credential authority tables, not merely the separate
# generic epoch fixture. Old physically restored rows MUST remain denied
# against an independently held latest credential head (not in this test).
credential_webid='https://paper.example.org/claimtest-physical'
credential_op='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
credential_old='$2b$12$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
credential_new='$2b$12$bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
assert_credential() {
  local name="$1" expected_epoch="$2" expected_state="$3" actual
  actual="$(sql "$name" -Atqc \
    "SELECT mode||':'||state||':'||epoch FROM paper_credential_epoch.read_certified('$credential_webid');")"
  if [[ "$actual" != "unified:${expected_state}:${expected_epoch}" ]]; then
    echo "Unexpected physically restored credential state: $name ($actual)" >&2
    return 1
  fi
}
# Both the canonical credential epoch and the protected SemApps bcrypt row
# must be physically restored together; an old password and old active epoch
# cannot be accepted against a newer independent high-water.
assert_native() {
  local name="$1" expected_writes="$2" expected_hash="$3" expected_token="$4" actual writes token
  actual="$(sql "$name" -Atqc \
    "SELECT data->>'hashedPassword' FROM paper_private_auth.accounts
     WHERE data->>'webId'='$credential_webid';")"
  writes="$(sql "$name" -Atqc \
    "SELECT count(*)::text FROM paper_credential_epoch.native_writes;")"
  token="$(sql "$name" -Atqc \
    "SELECT CASE WHEN data ? 'resetPasswordToken' THEN 'present' ELSE 'absent' END
     FROM paper_private_auth.accounts WHERE data->>'webId'='$credential_webid';")"
  if [[ "$actual" != "$expected_hash" || "$writes" != "$expected_writes" ||
        "$token" != "$expected_token" ]]; then
    echo "Physically restored SemApps account/receipt does not match: $name" >&2
    return 1
  fi
}
start_source() {
  local role="$1"
  local name="paper-pitr-${suffix}-${role}"
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
  # Install the exact function-restricted credential schema only in the
  # unique isolated physical PG18 source (never the live provider).
  local schema
  for schema in paper-local-native-auth.sql \
                paper-credential-epoch-authority-v1.sql \
                paper-credential-epoch-authority-v2-certified-head.sql \
                paper-credential-epoch-authority-v3-native-bcrypt.sql; do
    test -s "pod-provider/backend/sql/$schema"
    docker cp "pod-provider/backend/sql/$schema" "$name:/tmp/$schema"
    sql "$name" -q -f "/tmp/$schema" >/dev/null
  done
  sql "$name" -c "INSERT INTO paper_private_auth.accounts(id,data)
    VALUES('11111111-1111-4111-8111-111111111111',
     jsonb_build_object('username','claimtest-physical',
      'webId','$credential_webid',
      'signupReservationId','22222222-2222-4222-8222-222222222222',
      'hashedPassword','$credential_old',
      'resetPasswordToken','prior-reset-before-revocation'));" >/dev/null
  [[ "$(sql "$name" -Atqc \
    "SELECT paper_credential_epoch.enroll_owner('$credential_webid');")" == t ]] || return 1
  assert_credential "$name" 1 active
  assert_native "$name" 0 "$credential_old" present
  # A real streamed physical base backup + manifest, not pg_dump.
  docker exec -u postgres "$name" pg_basebackup -U postgres \
    -D /backup/base -Fp -X stream --checkpoint=fast
  docker exec -u postgres "$name" pg_verifybackup /backup/base
  # pg_basebackup creates a root folder owned by the container's
  # dedicated postgres UID (0700); the host runner must NOT assume it
  # can stat inside that folder without the corresponding identity.
  docker exec -u postgres "$name" test -s /backup/base/backup_manifest
  docker exec -u postgres "$name" test -s /backup/base/PG_VERSION
  local old_segment last_segment
  old_segment="$(sql "$name" -Atqc \
    "SELECT pg_walfile_name(pg_create_restore_point('paper_before_revoke'));")"
  sql "$name" -c \
    "UPDATE paper_pitr_probe SET epoch=2,state='blocked' WHERE id='paper';"
  assert_epoch "$name" 2 blocked
  # Exact operation-bound native bcrypt mutation and its ledger are
  # committed before terminal disablement, with no direct JSONB bypass.
  [[ "$(sql "$name" -Atqc \
    "SELECT previous_epoch::text||':'||following_epoch::text
     FROM paper_credential_epoch.begin_change('$credential_webid','$credential_op',1);")" == '1:2' ]] || return 1
  receipt="$(sql "$name" -Atqc \
    "SELECT encode(paper_credential_epoch.write_native_bcrypt(
      '$credential_webid','$credential_op',2,'$credential_new'),'hex');")"
  [[ "$receipt" =~ ^[0-9a-f]{64}$ ]] || return 1
  [[ "$(sql "$name" -Atqc \
    "SELECT paper_credential_epoch.seal_verified_native(
       '$credential_webid','$credential_op',2,decode('$receipt','hex'));")" == t ]] || return 1
  assert_credential "$name" 2 active
  assert_native "$name" 1 "$credential_new" absent
  [[ "$(sql "$name" -Atqc \
    "SELECT paper_credential_epoch.disable_owner('$credential_webid');")" == t ]] || return 1
  assert_credential "$name" 3 disabled
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
  local role="$1" point="$2"
  local name="paper-pitr-${suffix}-${role}-${point}"
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
    assert_credential "$name" 1 active
    assert_native "$name" 0 "$credential_old" present
  else
    assert_epoch "$name" 2 blocked
    assert_credential "$name" 3 disabled
    assert_native "$name" 1 "$credential_new" absent
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
  credential_epoch="$(sql "paper-pitr-${suffix}-${role}-before" -Atqc \
    "SELECT epoch FROM paper_credential_epoch.read_certified('$credential_webid');")"
  [[ "$credential_epoch" == 1 ]] || {
    echo 'Expected stale physically restored credential generation' >&2
    exit 1
  }
done
echo 'PASS: separate real PG18 physical backups and WAL PITR of credential v1/v2/v3, original/new native SemApps bcrypt rows and durable operation receipts, pre/post terminal disable; nonactivated, external custody + Redis/Jena/PDS remain P0'
