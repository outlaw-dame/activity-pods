'use strict';

/** Disposable real PostgreSQL integration of the *Moleculer* candidate.
 * Test-only fixtureOnly:true is deliberately absent from runtime service
 * registration. No live account, Pod or federation fixture is contacted.
 */
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { Pool } = require('pg');
const { createCandidateService } = require('../candidates/collective-postgres-moleculer');
if (process.env.G2_BENCH_DISPOSABLE !== 'confirmed' ||
    !/^postgres(?:ql)?:\/\/[^@]+@(?:localhost|127\.0\.0\.1):[0-9]+\//.test(process.env.G2_POSTGRES_DSN || '')) {
  throw new Error('Refusing non-disposable PostgreSQL target');
}
const owner = 'https://paper-bench.example/users/owner#me';
const app = 'https://paper-bench.example/app';
const groupId = 'cg_' + 'a'.repeat(32);
const member = i => 'https://remote.example/users/' + String(i).padStart(6, '0');
const pool = new Pool({
  connectionString: process.env.G2_POSTGRES_DSN,
  max: 4, min: 0, idleTimeoutMillis: 5000, connectionTimeoutMillis: 3000,
  statement_timeout: 8000, idle_in_transaction_session_timeout: 5000,
  allowExitOnIdle: true
});
const factory = createCandidateService({ pool, fixtureOnly: true });
const service = { settings: { enabled: true } };
const execute = (op, params) =>
  factory.actions[op].handler.call(service, { params });
const uuid = () => crypto.randomUUID();
async function main() {
  try {
    const empty = await pool.query(
      "SELECT count(*)::integer AS n FROM pg_catalog.pg_tables WHERE schemaname='public'"
    );
    assert.equal(empty.rows[0].n, 0);
    await pool.query(fs.readFileSync(path.resolve(__dirname,
      '../sql/paper-groups-postgres-candidate-v1.sql'), 'utf8'));
    await pool.query(fs.readFileSync(path.resolve(__dirname, '../sql/paper-groups-postgres-candidate-v2-revocation.sql'), 'utf8'));
    await pool.query('INSERT INTO paper_groups_candidate.identities (webid) VALUES ($1)', [owner]);
    await pool.query(
      'INSERT INTO paper_groups_candidate.consent (owner_webid,app_uri,granted) VALUES ($1,$2,true)',
      [owner,app]
    );
    await pool.query(
      'INSERT INTO paper_groups_candidate.groups (group_id,owner_webid,app_uri) VALUES ($1,$2,$3)',
      [groupId,owner,app]
    );
    await pool.query(
      "INSERT INTO paper_groups_candidate.members VALUES ($1,$2,'owner','active',1)",
      [groupId,owner]
    );
    const common = { groupId, owner, app };
    const op = uuid();
    const change = { ...common, member: member(1), role: 'member',
      status: 'active', expectedRevision: 1, operationId: op };
    // An injected Pool alone cannot bypass the fixture/release fence.
    const disabled = createCandidateService({pool});
    await assert.rejects(
      () => disabled.actions.change.handler.call(service, {params:change}),
      e => e.type === 'GROUP_POSTGRES_NOT_RELEASED'
    );
    const first = await execute('change',change);
    assert.deepEqual(first,{ membershipRevision: 2, replay: false });
    assert.deepEqual(await execute('change',change),
      { membershipRevision: 2, replay: true });
    await assert.rejects(
      () => execute('change',{...change,member:member(2)}),
      e => e.type === 'GROUP_POSTGRES_OPERATION_CONFLICT'
    );
    await assert.rejects(
      () => execute('change',{...change,member:member(2),operationId:uuid()}),
      e => e.type === 'GROUP_POSTGRES_STALE_REVISION'
    );
    const firstPage = await execute('list',{...common,limit:1});
    assert.equal(firstPage.membershipRevision,2);
    assert.equal(firstPage.hasMore,true);
    assert.equal(firstPage.members.length,1);
    const next = await execute('list',{
      ...common,limit:1,cursor:firstPage.nextCursor,expectedRevision:2
    });
    assert.equal(next.members.length,1);
    await assert.rejects(
      () => execute('list',{...common,limit:1,cursor:firstPage.nextCursor}),
      e => e.type === 'GROUP_POSTGRES_STALE_PAGE'
    );
    // The same single consent row is locked by each membership write.
    // A revoke cannot race past an active writer; after commit, both
    // writes and private reads fail without a cache fallback.
    const revocationOp = uuid();
    const held = await pool.connect();
    let revokedCommitted = false;
    try {
      await held.query('BEGIN');
      await held.query(
        'SELECT granted FROM paper_groups_candidate.consent ' +
        'WHERE owner_webid=$1 AND app_uri=$2 FOR SHARE',
        [owner,app]
      );
      const revokePromise = execute('revokeConsent',{
        owner,app,expectedConsentRevision:1,operationId:revocationOp
      }).then(value=>{revokedCommitted=true;return value;});
      await new Promise(resolve=>setTimeout(resolve,120));
      assert.equal(revokedCommitted,false,'revocation bypassed the held consent lock');
      await held.query('COMMIT');
      assert.deepEqual(await revokePromise,{consentRevision:2,replay:false,granted:false});
    } finally {
      try { await held.query('ROLLBACK'); } catch (_) {}
      held.release();
    }
    assert.deepEqual(await execute('revokeConsent',{
      owner,app,expectedConsentRevision:1,operationId:revocationOp
    }),{consentRevision:2,replay:true,granted:false});
    await assert.rejects(
      ()=>execute('revokeConsent',{
        owner,app,expectedConsentRevision:1,operationId:uuid()
      }),e=>e.type==='GROUP_POSTGRES_STALE_CONSENT_REVISION'
    );
    assert.equal((await pool.query(
      'SELECT count(*)::integer AS n FROM paper_groups_candidate.consent_revocations'
    )).rows[0].n,1);
    await assert.rejects(
      () => execute('change',{...change,expectedRevision:2,operationId:uuid()}),
      e => e.type === 'GROUP_POSTGRES_AUTHORITY_DENIED'
    );
    await assert.rejects(
      () => execute('list',{...common,limit:100}),
      e => e.type === 'GROUP_POSTGRES_AUTHORITY_DENIED'
    );
    const proof = (await pool.query(
      'SELECT revision FROM paper_groups_candidate.groups WHERE group_id=$1',
      [groupId]
    )).rows[0].revision;
    assert.equal(Number(proof),2);
    console.log(JSON.stringify({
      proof:'paper-groups-moleculer-pg-transaction-bridge',ok:true,
      fixtureOnly:true,revision:2,poolMax:pool.options.max,revocationEvents:1,
      liveSAI:false,activated:false,remoteDelivery:false
    }));
  } finally { await pool.end(); }
}
main().catch(e => { console.error('GROUP_POSTGRES_MOLECULER_PROOF_FAILED',e);process.exitCode=1; });
