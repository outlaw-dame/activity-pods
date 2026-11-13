#!/usr/bin/env bash
set -euo pipefail
# Strictly disposable PostgreSQL 18 operational-account candidate restore.
# Do not point this script at a real instance or user database.
if [ "${PAPER_ACCOUNTS_DISPOSABLE:-}" != confirmed ]; then
  echo 'Disposable account restore marker required' >&2
  exit 2
fi
container=paper-accounts-pg18
source_db=paper_accounts_test
restore_db=paper_accounts_restored
tmp="$(mktemp -d)"
trap 'rm -rf -- "$tmp"' EXIT
exec_psql() {
  local db="$1"
  shift
  docker exec -e PGPASSWORD=bench "$container" \
    psql -h 127.0.0.1 -U postgres -X -v ON_ERROR_STOP=1 -d "$db" "$@"
}
# Use an isolated database created by the existing CI fixture, without
# network access, real identities, password verifiers or user Pods.
rows_before="$(exec_psql "$source_db" -Atqc \
  "SELECT count(*) FROM paper_account_candidate.accounts;")"
[ "$rows_before" -gt 0 ] || { echo 'Empty candidate backup fixture' >&2; exit 1; }
exec_psql "$source_db" -Atqc \
  "SELECT provider_id,account_id,username_key,coalesce(webid,''),coalesce(activitypub_actor_uri,''),coalesce(atproto_did,''),coalesce(atproto_handle,''),coalesce(atproto_pds_url,''),atproto_repo_initialized,state,generation FROM paper_account_candidate.accounts ORDER BY account_id;" \
  > "$tmp/source-accounts.txt"
exec_psql "$source_db" -Atqc \
  "SELECT account_id,operation_id,previous_generation,next_generation,kind,payload_digest FROM paper_account_candidate.transitions ORDER BY account_id,next_generation;" \
  > "$tmp/source-transitions.txt"

docker exec -e PGPASSWORD=bench "$container" \
  pg_dump -h 127.0.0.1 -U postgres -d "$source_db" \
  --format=custom --no-owner --no-acl > "$tmp/candidate.dump"
test -s "$tmp/candidate.dump"
# Restore to a completely different disposable database, not back into the
# source. A failed restore must fail CI, not print only a warning.
docker exec -e PGPASSWORD=bench "$container" \
  createdb -h 127.0.0.1 -U postgres "$restore_db"
docker exec -i -e PGPASSWORD=bench "$container" \
  pg_restore -h 127.0.0.1 -U postgres -d "$restore_db" \
  --no-owner --no-acl --exit-on-error < "$tmp/candidate.dump"
exec_psql "$restore_db" -Atqc \
  "SELECT provider_id,account_id,username_key,coalesce(webid,''),coalesce(activitypub_actor_uri,''),coalesce(atproto_did,''),coalesce(atproto_handle,''),coalesce(atproto_pds_url,''),atproto_repo_initialized,state,generation FROM paper_account_candidate.accounts ORDER BY account_id;" \
  > "$tmp/restored-accounts.txt"
exec_psql "$restore_db" -Atqc \
  "SELECT account_id,operation_id,previous_generation,next_generation,kind,payload_digest FROM paper_account_candidate.transitions ORDER BY account_id,next_generation;" \
  > "$tmp/restored-transitions.txt"
cmp "$tmp/source-accounts.txt" "$tmp/restored-accounts.txt"
cmp "$tmp/source-transitions.txt" "$tmp/restored-transitions.txt"
rows_after="$(exec_psql "$restore_db" -Atqc \
  'SELECT count(*) FROM paper_account_candidate.accounts;')"
[ "$rows_before" = "$rows_after" ]
# Critical invariants must survive a restore; no malformed, split or duplicate
# public identity can be silently accepted by the restored schema.
invalid="$(exec_psql "$restore_db" -Atqc \
  "SELECT count(*) FROM paper_account_candidate.accounts WHERE (webid IS NULL AND state <> 'reserved') OR (webid IS NOT NULL AND (activitypub_actor_uri IS DISTINCT FROM webid OR atproto_did IS NULL));")"
[ "$invalid" = 0 ]
constraints="$(exec_psql "$restore_db" -Atqc \
  "SELECT count(*) FROM pg_constraint WHERE conrelid='paper_account_candidate.accounts'::regclass AND contype IN ('u','c','p');")"
[ "$constraints" -ge 5 ]
echo 'account_postgres_disposable_backup_restore_equality_passed'
