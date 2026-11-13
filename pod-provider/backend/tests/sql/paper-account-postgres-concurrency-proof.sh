#!/usr/bin/env bash
set -euo pipefail
# Disposable CI-only database. Proves concurrent username reservation is
# serialized by PostgreSQL, not by a process-local in-memory lock.
container="${1:-paper-account-pg-test}"
db=paper_account_disposable
psql_ci() {
  docker exec -i -e PGPASSWORD=disposable-ci-only "$container" \
    psql -X -v ON_ERROR_STOP=1 -U postgres -d "$db" "$@"
}
first_sql="BEGIN;
INSERT INTO paper_account_candidate.operations (
  operation_id, provider_id, app_client_id, idempotency_digest,
  request_digest, username_key, lease_token, lease_expires_at
) VALUES (
  '00000000-0000-4000-8000-000000000011', 'provider-a',
  'https://client.example', decode(repeat('12',32),'hex'),
  decode(repeat('21',32),'hex'), 'same_concurrent_name',
  '00000000-0000-4000-8000-000000000012',
  clock_timestamp()+interval '10 minutes'
);
SELECT pg_sleep(4);
COMMIT;"
second_sql="INSERT INTO paper_account_candidate.operations (
  operation_id, provider_id, app_client_id, idempotency_digest,
  request_digest, username_key, lease_token, lease_expires_at
) VALUES (
  '00000000-0000-4000-8000-000000000013', 'provider-a',
  'https://other.example', decode(repeat('13',32),'hex'),
  decode(repeat('23',32),'hex'), 'same_concurrent_name',
  '00000000-0000-4000-8000-000000000014',
  clock_timestamp()+interval '10 minutes'
);"
first_output="$(mktemp)"
second_output="$(mktemp)"
trap 'rm -f "$first_output" "$second_output"' EXIT
psql_ci -c "$first_sql" >"$first_output" 2>&1 &
first_pid=$!
sleep 1
# The second reservation must not succeed even on a separate database client.
if psql_ci -c "$second_sql" >"$second_output" 2>&1; then
  wait "$first_pid" || true
  echo "::error::Concurrent unique username reservation unexpectedly succeeded" >&2
  exit 1
fi
wait "$first_pid"
# Confirm that the expected constraint, not a transient network/SQL error,
# caused the rejection. No production payloads are used in this fixture.
if ! grep -q 'duplicate key value violates unique constraint' "$second_output"; then
  sed -n '1,18p' "$second_output" >&2
  echo "::error::Concurrent reservation failed for an unexpected reason" >&2
  exit 1
fi
count="$(psql_ci -Atqc "SELECT count(*) FROM paper_account_candidate.operations
  WHERE provider_id='provider-a' AND username_key='same_concurrent_name';")"
if [ "$count" != 1 ]; then
  echo "::error::Expected exactly one durable reservation, found $count" >&2
  exit 1
fi
echo 'account_pg_concurrent_unique_reservation_passed'
