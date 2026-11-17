'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs/promises');
const path = require('node:path');
const { Pool } = require('pg');
const { ServiceBroker } = require('moleculer');
const ApiGateway = require('moleculer-web');
const { makeBrowserEnrollmentService } = require('../candidates/provider-browser-enrollment-service');
const { createProviderBrowserEnrollment } = require('../candidates/provider-browser-enrollment');

test('real PostgreSQL enrollment: bounded credential, exact owner, consent CAS and uncertain native mutation', async () => {
  assert.equal(process.env.NODE_ENV, 'test');
  assert.equal(process.env.PAPER_BROWSER_ENROLLMENT_DISPOSABLE, 'confirmed');
  assert.equal(process.env.PAPER_ACCOUNTS_DISPOSABLE, 'confirmed');
  const config = JSON.parse(await fs.readFile(process.env.PAPER_ENROLLMENT_TEST_CONFIG, 'utf8'));
  const rootUrl = new URL(config.databaseUrl);
  assert.equal(rootUrl.hostname, '127.0.0.1');
  assert.equal(rootUrl.port, '5549');
  assert.equal(rootUrl.pathname, '/paper_local_plc');
  const options = { max: 3, connectionTimeoutMillis: 3000, statement_timeout: 5000,
    query_timeout: 6000, idleTimeoutMillis: 1000, allowExitOnIdle: true };
  const admin = new Pool({ ...options, connectionString: rootUrl.href });
  const suffix = crypto.randomBytes(8).toString('hex');
  const database = 'paper_enrollment_' + suffix;
  const login = 'paper_enrollment_' + suffix;
  const password = crypto.randomBytes(32).toString('hex');
  let databaseCreated = false, loginCreated = false, roleCreated = false, owner, runtime, secondRuntime, broker;
  try {
    const roleBefore = await admin.query("SELECT 1 FROM pg_roles WHERE rolname='paper_enrollment_runtime'");
    roleCreated = roleBefore.rowCount === 0;
    await admin.query(`CREATE DATABASE ${database}`);
    databaseCreated = true;
    const dbUrl = new URL(rootUrl);
    dbUrl.pathname = '/' + database;
    owner = new Pool({ ...options, connectionString: dbUrl.href });
    for (const file of ['v1', 'v2-signup-ledger', 'v3-evidence-seal', 'v4-atomic-completion', 'v6-enrollment']) {
      await owner.query(await fs.readFile(path.join(__dirname, '../sql/paper-account-postgres-candidate-' + file + '.sql'), 'utf8'));
    }
    await admin.query(`CREATE ROLE ${login} LOGIN PASSWORD '${password}' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS`);
    loginCreated = true;
    await admin.query(`GRANT paper_enrollment_runtime TO ${login} WITH INHERIT TRUE, SET FALSE, ADMIN FALSE`);
    dbUrl.username = login; dbUrl.password = password;
    runtime = new Pool({ ...options, connectionString: dbUrl.href });
    secondRuntime = new Pool({ ...options, connectionString: dbUrl.href });
    await assert.rejects(runtime.query('SELECT * FROM paper_account_candidate.signup_operations'), { code: '42501' });
    await assert.rejects(runtime.query("UPDATE paper_account_candidate.accounts SET state='ready'"), { code: '42501' });

    const providerId = 'https://provider.paper.example.org';
    const appClientId = 'https://app.paper.example.org/client';
    const appUri = 'https://app.paper.example.org/application';
    const browserOrigin = 'https://login.paper.example.org';
    const returnUri = 'https://app.paper.example.org/signup-return';
    const csrfKey = crypto.randomBytes(32);
    const required = appUri + '#profile';
    const optional = appUri + '#photos';
    const revision = crypto.createHash('sha256').update('resolved grant semantics v1').digest('hex');
    let manifest = { required: [required], optional: [optional], revision };
    let nativeCalls = 0, nativeFailure = false;
    const seen = [];
    const settings = { providerId, appClientId, appUri, browserOrigin, returnUri, csrfKey,
      fixtureOnly: true, loadRequirements: async () => manifest,
      registerApp: async input => {
        nativeCalls++; seen.push(input);
        if (nativeFailure) throw Error('lost native acknowledgment');
        return input.webId + '/registrations/app';
      } };
    const service = createProviderBrowserEnrollment({ ...settings, pool: runtime });
    const otherWorker = createProviderBrowserEnrollment({ ...settings, pool: secondRuntime });
    const fixture = async (issuer = service) => {
      const accountId = crypto.randomUUID(), operationId = crypto.randomUUID();
      const username = 'enroll-' + crypto.randomBytes(6).toString('hex');
      const webId = providerId + '/users/' + username;
      const did = 'did:plc:' + [...crypto.randomBytes(24)].map(n => String.fromCharCode(97 + n % 26)).join('');
      const idempotencyHmac = crypto.randomBytes(32), requestHmac = crypto.randomBytes(32);
      // Account/identity rows are explicitly fixtures. This test proves the
      // enrollment store, not signed-PDS or native SAI end-to-end acceptance.
      await owner.query(`INSERT INTO paper_account_candidate.accounts
        (account_id,provider_id,username_key,webid,activitypub_actor_uri,atproto_did,
         atproto_handle,atproto_pds_url,atproto_repo_initialized,state)
        VALUES ($1,$2,$3,$4,$4,$5,$6,$2,true,'provisioning')`,
      [accountId, providerId, username, webId, did, username + '.paper.example.org']);
      await owner.query(`INSERT INTO paper_account_candidate.signup_operations
        (operation_id,provider_id,account_id,app_client_id,hmac_key_version,idempotency_hmac,request_hmac,state,may_have_side_effects)
        VALUES ($1,$2,$3,$4,1,$5,$6,'reconciliation_required',true)`,
      [operationId, providerId, accountId, appClientId, idempotencyHmac, requestHmac]);
      const scope = { operationId, idempotencyHmac, requestHmac };
      let cookie;
      const issued = await issuer.issue({ ...scope, setCookie: value => { cookie = value; } });
      assert.match(cookie, /; Path=\/; Secure; HttpOnly; SameSite=Strict; Max-Age=600$/u);
      assert(!JSON.stringify(issued).includes(cookie.split('=')[1].split(';')[0]));
      return { scope, cookie, issued, webId, username,
        request: { cookie, origin: browserOrigin, csrfToken: issued.csrfToken, approve: true, selected: [required] } };
    };
    const first = await fixture();
    const differentClient = createProviderBrowserEnrollment({ ...settings, pool: runtime,
      appClientId: 'https://app.paper.example.org/another-client' });
    await assert.rejects(differentClient.view({ cookie: first.cookie, origin: browserOrigin }));
    await assert.rejects(differentClient.consent(first.request));
    assert.equal((await otherWorker.view({ cookie: first.cookie, origin: browserOrigin })).state, 'awaiting_consent');
    await assert.rejects(service.issue({ ...first.scope, setCookie: () => assert.fail('no replacement credential') }));
    await assert.rejects(service.view({ cookie: first.cookie, origin: 'https://attacker.example' }));
    await assert.rejects(service.view({ cookie: first.cookie + '; ' + first.cookie.split(';')[0], origin: browserOrigin }));
    await assert.rejects(service.consent({ ...first.request, csrfToken: crypto.randomBytes(32).toString('base64url') }));
    await assert.rejects(service.consent({ ...first.request, selected: [optional] }));
    await assert.rejects(service.consent({ ...first.request, selected: [required, 'https://attacker.example/right'] }));
    manifest = { required: [required], optional: [optional], revision: 'b'.repeat(64) };
    await assert.rejects(service.consent(first.request), { code: 'ENROLLMENT_REQUIREMENTS_CHANGED' });
    manifest = { required: [required], optional: [optional], revision };
    assert.equal(nativeCalls, 0);
    const race = await Promise.allSettled([service.consent(first.request), otherWorker.consent(first.request)]);
    assert.equal(race.filter(r => r.status === 'fulfilled').length, 1);
    assert.equal(nativeCalls, 1);
    assert.deepEqual(seen[0], { webId: first.webId, username: first.username, appUri,
      acceptedAccessNeeds: [required], acceptedSpecialRights: [] });
    assert.equal((await otherWorker.view({ cookie: first.cookie, origin: browserOrigin })).state, 'consent_recorded');
    await assert.rejects(service.consent(first.request));
    const state = await owner.query('SELECT state,enrollment_selection FROM paper_account_candidate.signup_operations WHERE operation_id=$1', [first.scope.operationId]);
    assert.equal(state.rows[0].state, 'reconciliation_required', 'consent is not canonical completion');

    const lost = await fixture();
    nativeFailure = true;
    await assert.rejects(service.consent(lost.request), { code: 'ENROLLMENT_CONSENT_RECONCILIATION_REQUIRED' });
    nativeFailure = false;
    await assert.rejects(otherWorker.consent(lost.request), { code: 'ENROLLMENT_ALREADY_CLAIMED' });
    assert.equal(nativeCalls, 2, 'uncertain mutation is never replayed by another worker');
    assert.equal((await service.view({ cookie: lost.cookie, origin: browserOrigin })).state, 'consent_claimed');

    const refused = await fixture();
    assert.deepEqual(await service.consent({ ...refused.request, approve: false, selected: [] }), { state: 'denied' });
    await assert.rejects(service.consent(refused.request));
    assert.equal(nativeCalls, 2);
    const optionalConsent = await fixture();
    await service.consent({ ...optionalConsent.request, selected: [required, optional] });
    assert.deepEqual(seen.at(-1).acceptedAccessNeeds, [required, optional].sort());
    const expired = await fixture();
    await owner.query("UPDATE paper_account_candidate.signup_operations SET enrollment_expires_at=clock_timestamp()-interval '1 second' WHERE operation_id=$1", [expired.scope.operationId]);
    await assert.rejects(service.view({ cookie: expired.cookie, origin: browserOrigin }));
    await assert.rejects(service.consent(expired.request));
    await assert.rejects(owner.query('UPDATE paper_account_candidate.signup_operations SET enrollment_state=NULL WHERE operation_id=$1', [first.scope.operationId]), { code: '23514' });
    await owner.query(`GRANT SELECT ON paper_account_candidate.accounts TO ${login}`);
    await assert.rejects(service.view({ cookie: first.cookie, origin: browserOrigin }));
    await owner.query(`REVOKE SELECT ON paper_account_candidate.accounts FROM ${login}`);
    await admin.query(`GRANT paper_enrollment_runtime TO ${login} WITH INHERIT TRUE, SET TRUE, ADMIN FALSE`);
    await assert.rejects(service.view({ cookie: first.cookie, origin: browserOrigin }));
    await admin.query(`GRANT paper_enrollment_runtime TO ${login} WITH INHERIT TRUE, SET FALSE, ADMIN FALSE`);
    await owner.query(`GRANT SELECT(enrollment_token_hash) ON paper_account_candidate.signup_operations TO ${login}`);
    await assert.rejects(service.view({ cookie: first.cookie, origin: browserOrigin }));
    await owner.query(`REVOKE SELECT(enrollment_token_hash) ON paper_account_candidate.signup_operations FROM ${login}`);
    // Real HTTP adapter and Moleculer dispatch. Native SAI storage is a fixture
    // here; the adapter must derive the owner and call exactly registerApp.
    broker = new ServiceBroker({ logger: false });
    const gateway = broker.createService({ mixins: [ApiGateway], settings: {
      port: 0, ip: '127.0.0.1', routes: [], log4XXResponses: false, logRequest: null, logResponse: null
    } });
    const nativeOwners = new Map();
    let adapterCalls = 0;
    broker.createService({ name: 'auth.account', actions: {
      findByWebId: { handler: ctx => nativeOwners.get(ctx.params.webId) }
    } });
    broker.createService({ name: 'auth-agent', actions: {
      registerApp: { handler(ctx) {
        const account = nativeOwners.get(ctx.meta.webId);
        assert(account);
        assert.equal(ctx.meta.dataset, account.username);
        assert.equal(ctx.params.appUri, appUri);
        assert.deepEqual(ctx.params.acceptedAccessNeeds, [required]);
        assert(!Object.hasOwn(ctx.params, 'acceptAllRequirements'));
        adapterCalls++;
        return account.webId + '/registrations/application';
      } }
    } });
    const adapter = makeBrowserEnrollmentService({ ...settings, broker, pool: runtime });
    broker.createService(adapter.schema);
    await broker.start();
    const httpFixture = await fixture(adapter);
    nativeOwners.set(httpFixture.webId, { webId: httpFixture.webId,
      username: httpFixture.username, signupReservationId: crypto.randomUUID() });
    const endpoint = 'http://127.0.0.1:' + gateway.server.address().port + '/api/signup-enrollment';
    const headers = { origin: browserOrigin, cookie: httpFixture.cookie.split(';')[0], 'content-type': 'application/json' };
    const statusReply = await fetch(endpoint, { headers });
    assert.equal(statusReply.status, 200);
    assert.equal(statusReply.headers.get('cache-control'), 'no-store');
    assert.equal(statusReply.headers.get('access-control-allow-origin'), browserOrigin);
    assert.equal((await statusReply.json()).state, 'awaiting_consent');
    const post = (body, extra = {}) => fetch(endpoint + '/consent', {
      method: 'POST', headers: { ...headers, ...extra }, body: JSON.stringify(body)
    });
    const body = { csrfToken: httpFixture.issued.csrfToken, approve: true, selected: [required] };
    const wrongOwner = await post({ ...body, webId: first.webId });
    assert(wrongOwner.status >= 400); await wrongOwner.arrayBuffer();
    const wrongOrigin = await post(body, { origin: 'https://attacker.example' });
    assert(wrongOrigin.status >= 400); await wrongOrigin.arrayBuffer();
    const arbitraryAction = await fetch(endpoint + '/auth.account/findByWebId', { headers });
    assert.equal(arbitraryAction.status, 404); await arbitraryAction.arrayBuffer();
    assert.equal(adapterCalls, 0);
    const accepted = await post(body);
    assert.equal(accepted.status, 200);
    assert.deepEqual(await accepted.json(), { state: 'consent_recorded', completionPending: true });
    assert.equal(adapterCalls, 1);
    const repeated = await post(body);
    assert.equal(repeated.status, 409); await repeated.arrayBuffer();
    assert.equal(adapterCalls, 1);
    const saved = process.env.NODE_ENV;
    try {
      process.env.NODE_ENV = 'production';
      await assert.rejects(adapter.schema.started.call({ broker }), { code: 'ENROLLMENT_NOT_RELEASED' });
      await assert.rejects(service.view({ cookie: first.cookie, origin: browserOrigin }), { code: 'ENROLLMENT_NOT_RELEASED' });
    } finally { process.env.NODE_ENV = saved; }
  } finally {
    if (broker) await broker.stop();
    for (const pool of [runtime, secondRuntime, owner]) if (pool) await pool.end();
    if (databaseCreated) await admin.query(`DROP DATABASE ${database}`);
    if (loginCreated) await admin.query(`DROP ROLE ${login}`);
    if (roleCreated) await admin.query('DROP ROLE IF EXISTS paper_enrollment_runtime');
    await admin.end();
  }
});
