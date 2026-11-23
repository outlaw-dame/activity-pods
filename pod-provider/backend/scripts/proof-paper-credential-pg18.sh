#!/usr/bin/env bash
set -Eeuo pipefail
# NONACTIVATED CI-only proof. Nothing here deploys an authority or opens signup.
if [[ "$CI" != true || "$PAPER_CREDENTIAL_PG_DISPOSABLE" != confirmed ]]; then
  echo 'Refusing credential authority proof outside disposable CI' >&2
  exit 2
fi
: "$PGHOST" "$PGPORT" "$PGDATABASE" "$PGUSER" "$PGPASSWORD"
db() { psql -X -qAt -v ON_ERROR_STOP=1 "$@"; }
value() { db -c "$1"; }
eq() {
  local actual="$1" expected="$2" label="$3"
  if [[ "$actual" != "$expected" ]]; then
    echo "Credential epoch regression: $label (actual=$actual expected=$expected)" >&2
    exit 1
  fi
}
denied() {
  local label="$1" statement="$2"
  if db -c "$statement" >/dev/null 2>&1; then
    echo "Credential epoch unauthorized operation succeeded: $label" >&2
    exit 1
  fi
}
db -f /work/pod-provider/backend/sql/paper-credential-epoch-authority-v1.sql >/dev/null
owner='https://paper.example.org/users/proof'
op='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
wrong='bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'
eq "$(value "SET ROLE paper_credential_enroller;
 SELECT paper_credential_epoch.enroll_owner('$owner');")" t 'initial unified enrollment'
eq "$(value "SET ROLE paper_credential_enroller;
 SELECT paper_credential_epoch.enroll_owner('$owner');")" f 're-enrollment denied'
eq "$(value "SET ROLE paper_credential_enroller;
 SELECT paper_credential_epoch.enroll_owner('http://bad.example.org');")" f 'insecure identity refused'
eq "$(value "SET ROLE paper_credential_reader;
 SELECT mode||'|'||state||'|'||epoch FROM paper_credential_epoch.read_owner('$owner');")" 'unified|active|1' 'read authenticated state'
denied 'direct protected SELECT' "SET ROLE paper_credential_reader; SELECT * FROM paper_credential_epoch.owners;"
denied 'direct protected UPDATE' "SET ROLE paper_credential_reader; UPDATE paper_credential_epoch.owners SET epoch=1;"
denied 'reader mutation function' "SET ROLE paper_credential_reader; SELECT paper_credential_epoch.disable_owner('$owner');"
denied 'unprivileged enrollment' "SET ROLE paper_credential_reader; SELECT paper_credential_epoch.enroll_owner('$owner');"
denied 'schema CREATE' "SET ROLE paper_credential_reader; CREATE TABLE paper_credential_epoch.evil(id integer);"
denied 'PUBLIC reader' "SET ROLE pg_read_all_data; SELECT * FROM paper_credential_epoch.read_owner('$owner');"
eq "$(value "SET ROLE paper_credential_coordinator;
 SELECT previous_epoch||'|'||following_epoch FROM paper_credential_epoch.begin_change('$owner','$op',1);")" '1|2' 'pending fence admitted'
eq "$(value "SET ROLE paper_credential_reader;
 SELECT mode||'|'||state||'|'||epoch FROM paper_credential_epoch.read_owner('$owner');")" 'unified|pending|1' 'reader denies pending'
eq "$(value "SET ROLE paper_credential_coordinator;
 SELECT count(*) FROM paper_credential_epoch.begin_change('$owner','$wrong',1);")" 0 'race cannot start second change'
eq "$(value "SET ROLE paper_credential_coordinator;
 SELECT paper_credential_epoch.seal_change('$owner','$wrong',2,decode(repeat('aa',32),'hex'));")" f 'different operation denied'
eq "$(value "SET ROLE paper_credential_coordinator;
 SELECT paper_credential_epoch.seal_change('$owner','$op',2,decode('aa','hex'));")" f 'weak downstream receipt denied'
eq "$(value "SET ROLE paper_credential_reader;
 SELECT mode||'|'||state||'|'||epoch FROM paper_credential_epoch.read_owner('$owner');")" 'unified|pending|1' 'ambiguous write remains fenced'
eq "$(value "SET ROLE paper_credential_coordinator;
 SELECT paper_credential_epoch.seal_change('$owner','$op',2,decode(repeat('ab',32),'hex'));")" t 'exact operation sealed'
eq "$(value "SET ROLE paper_credential_reader;
 SELECT mode||'|'||state||'|'||epoch FROM paper_credential_epoch.read_owner('$owner');")" 'unified|active|2' 'epoch monotonically advanced'
eq "$(value "SET ROLE paper_credential_coordinator;
 SELECT paper_credential_epoch.seal_change('$owner','$op',2,decode(repeat('ab',32),'hex'));")" f 'replayed ACK denied'
eq "$(value "SET ROLE paper_credential_coordinator;
 SELECT count(*) FROM paper_credential_epoch.begin_change('$owner','$wrong',1);")" 0 'old snapshot expected epoch denied'
eq "$(value "SET ROLE paper_credential_coordinator;
 SELECT paper_credential_epoch.disable_owner('$owner');")" t 'terminal disable'
eq "$(value "SET ROLE paper_credential_reader;
 SELECT mode||'|'||state||'|'||epoch FROM paper_credential_epoch.read_owner('$owner');")" 'unified|disabled|3' 'disabled epoch'
eq "$(value "SET ROLE paper_credential_enroller;
 SELECT paper_credential_epoch.enroll_owner('$owner');")" f 'disabled cannot re-enroll'
eq "$(value "SET ROLE paper_credential_coordinator;
 SELECT count(*) FROM paper_credential_epoch.begin_change('$owner','$wrong',3);")" 0 'disabled cannot mutate'
eq "$(value "SET ROLE paper_credential_coordinator;
 SELECT paper_credential_epoch.disable_owner('$owner');")" f 'disable replay denied'
echo 'PASS: real PG18 restricted credential roles, pending/ACK, replay, terminal disable; NONACTIVATED'
