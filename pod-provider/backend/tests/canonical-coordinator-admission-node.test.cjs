'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs/promises');
const path = require('node:path');
const { Pool } = require('pg');

async function drainDatabaseConnections(admin, database) {
  const deadline = Date.now() + 5000;
  while ((await admin.query('SELECT 1 FROM pg_stat_activity WHERE datname=$1', [database])).rowCount) {
    if (Date.now() >= deadline) throw Error('Disposable database still has live connections');
    await new Promise(resolve => setTimeout(resolve, 50));
  }
}

test('canonical coordinator: actual restricted SQL, durable fence and no duplicate execution', async () => {
  assert.equal(process.env.NODE_ENV, 'test');
  for (const name of ['PAPER_ACCOUNTS_DISPOSABLE','APODS_ACCOUNT_RESERVATION_DISPOSABLE','ATPROTO_REPO_PROOF_DISPOSABLE']) assert.equal(process.env[name], 'confirmed');
  const { createCanonicalCoordinatorAdmission } = await import('../candidates/atproto-signed-repo-proof/canonical-coordinator-admission.mjs');
  const { makeAccountReservationAuthority } = await import('../candidates/atproto-signed-repo-proof/account-reservation-authority.mjs');
  const config = JSON.parse(await fs.readFile(process.env.PAPER_ENROLLMENT_TEST_CONFIG, 'utf8'));
  const root = new URL(config.databaseUrl);
  assert.equal(root.hostname, '127.0.0.1'); assert.equal(root.port, '5549'); assert.equal(root.pathname, '/paper_local_plc');
  const options = { max: 3, connectionTimeoutMillis: 3000, query_timeout: 6000, statement_timeout: 5000,
    idleTimeoutMillis: 1000, allowExitOnIdle: true };
  const admin = new Pool({ ...options, connectionString: root.href });
  const suffix = crypto.randomBytes(8).toString('hex');
  const database = 'paper_coordinator_' + suffix;
  const pools = [], logins = [], createdRoles = [];
  let owner, databaseCreated = false;
  try {
    await admin.query(`CREATE DATABASE ${database}`); databaseCreated = true;
    const db = new URL(root); db.pathname = '/' + database;
    owner = new Pool({ ...options, connectionString: db.href });
    const files = [
      ...['v1','v2-signup-ledger','v3-evidence-seal','v4-atomic-completion','v6-enrollment'].map(v => '../sql/paper-account-postgres-candidate-' + v + '.sql'),
      '../sql/paper-browser-signup-transaction.sql', '../candidates/atproto-signed-repo-proof/schema.sql', '../sql/paper-atproto-canonical-authority-v1.sql',
      ...['pg-preaccount-reservations','pg-v4-reservation-completion-bridge','pg-canonical-signup-reserver','pg-enrollment-handoff'].map(v => '../candidates/atproto-signed-repo-proof/' + v + '.sql')
    ];
    for (const file of files) {
      const sql = await fs.readFile(path.join(__dirname, file), 'utf8');
      for (const match of sql.matchAll(/CREATE ROLE ([a-z_]+)/g)) {
        if (!(await admin.query('SELECT 1 FROM pg_roles WHERE rolname=$1', [match[1]])).rowCount) createdRoles.push(match[1]);
      }
      await owner.query(sql);
    }
    const runtime = async role => {
      const login = 'paper_test_' + logins.length + '_' + suffix;
      const password = crypto.randomBytes(32).toString('hex');
      await admin.query(`CREATE ROLE ${login} LOGIN PASSWORD '${password}' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS`);
      logins.push(login);
      await admin.query(`GRANT ${role} TO ${login} WITH INHERIT TRUE, SET FALSE, ADMIN FALSE`);
      const url = new URL(db); url.username = login; url.password = password;
      const pool = new Pool({ ...options, connectionString: url.href }); pools.push(pool); return pool;
    };
    const worker = await runtime('paper_account_proof_worker');
    const issuer = await runtime('paper_account_proof_issuer');
    const reserver = await runtime('paper_account_signup_reserver');
    const binder = await runtime('paper_account_bridge_binder');
    const { makeBrowserSignupTransaction } = require('../candidates/browser-signup-transaction');
    const txConfig = { providerId: 'https://provider.example', appClientId: 'https://app.example/id',
      browserOrigin: 'https://login.example', returnUri: 'https://app.example/return', encryptionKey: crypto.randomBytes(32) };
    const verifierPool = await runtime('paper_browser_signup_verifier');
    const verifier = makeBrowserSignupTransaction({ ...txConfig, pool: verifierPool });
    const redeemerPool = await runtime('paper_browser_signup_redeemer');
    const redeemer = makeBrowserSignupTransaction({ ...txConfig, pool: redeemerPool });
    const fingerprint = crypto.randomBytes(32).toString('hex'), idempotencyKey = crypto.randomUUID();
    const proof = 'fixture.' + crypto.randomBytes(32).toString('base64url');
    let cookie;
    const tx = { idempotencyKey, fingerprint, proof, expiresAt: new Date(Date.now()+60000), setCookie: value => { cookie = value; } };
    await assert.rejects(redeemer.bindVerified(tx), { code: '42501' });
    await verifier.bindVerified(tx);
    const redemption = { cookie, origin: txConfig.browserOrigin, fingerprint };
    await assert.rejects(verifier.bindVerified(tx));
    await assert.rejects(redeemer.consume({ ...redemption, fingerprint: 'a'.repeat(64) }));
    await assert.rejects(redeemer.consume({ ...redemption, origin: 'https://other.example' }));
    await assert.rejects(redeemer.consume({ ...redemption, cookie: cookie + '; ' + cookie.split(';')[0] }));
    const otherReturn = makeBrowserSignupTransaction({ ...txConfig, returnUri: 'https://app.example/other',
      pool: await runtime('paper_browser_signup_redeemer') });
    await assert.rejects(otherReturn.consume(redemption));
    await assert.rejects(verifier.bindVerified({ ...tx, expiresAt: new Date(Date.now()-1000) }));
    const redemptions = await Promise.allSettled([redeemer.consume(redemption), redeemer.consume(redemption)]);
    assert.deepEqual(redemptions.filter(item => item.status === 'fulfilled').map(item => item.value),
      [{ idempotencyKey, challengeToken: proof }]);
    assert.equal((await owner.query('SELECT sealed_proof IS NULL AS cleared FROM paper_browser_signup.transactions')).rows[0].cleared,true);
    const { makeLocalSignupVerifier, issueLocalInvitation } = require('../candidates/local-browser-signup-verifier');
    const api = require('../services/unified-account-api.service').methods;
    const policy = require('../services/provider-capabilities.service').methods;
    const { fingerprint: signupFingerprint } = require('../services/utils/atproto-account-coordinated-signup');
    const invitationKeys = crypto.generateKeyPairSync('ed25519');
    const scope = { ...txConfig };
    const verificationKey = crypto.randomBytes(32).toString('base64url');
    const env = { ...process.env, APODS_ACCOUNT_REQUEST_FINGERPRINT_KEY: crypto.randomBytes(32).toString('base64url'),
      APODS_ACCOUNT_VERIFICATION_HMAC_KEY: verificationKey };
    const verify = makeLocalSignupVerifier({ publicKey: invitationKeys.publicKey, scope, transaction: verifier, env });
    const account = { username:'invited', email:'invited@example.test', password:'disposable-password',
      profile:{displayName:'invited'} };
    const invitation = issueLocalInvitation({ scope, privateKey:invitationKeys.privateKey, username:account.username,email:account.email });
    // A signed invitation must always fit the downstream verifier's UTF-8 byte budget.
    assert.throws(() => issueLocalInvitation({ scope: { ...scope, appClientId: 'https://app.example/' + 'x'.repeat(260) },
      privateKey: invitationKeys.privateKey, username: account.username, email: 'é'.repeat(150) + '@example.test' }));
    let issuedCookie;
    const verification = { account, origin:scope.browserOrigin, invitation, setCookie: value => { issuedCookie = value; } };
    await assert.rejects(verify({ ...verification, account:{...account,email:'another@example.test'} }));
    await assert.rejects(verify({ ...verification, origin:'https://other.example' }));
    await verify(verification);
    await assert.rejects(verify(verification));
    const fp = signupFingerprint({ api, appClientId:scope.appClientId, redirectUri:scope.returnUri, accountParams:account,
      protocols:api.requestedProtocolsFromAccountParams.call(api, account),env });
    const verifiedProof = await redeemer.consume({ cookie:issuedCookie,origin:scope.browserOrigin,fingerprint:fp });
    const previousKey = process.env.APODS_ACCOUNT_VERIFICATION_HMAC_KEY;
    try {
      process.env.APODS_ACCOUNT_VERIFICATION_HMAC_KEY = verificationKey;
      assert(policy.verifyDurableSignupChallenge({ ...account,verification:verifiedProof, idempotencyKey:verifiedProof.idempotencyKey,
        appClientId:scope.appClientId,redirectUri:scope.returnUri,origin:scope.browserOrigin,requestFingerprint:fp }));
    } finally {
      if (previousKey === undefined) delete process.env.APODS_ACCOUNT_VERIFICATION_HMAC_KEY;
      else process.env.APODS_ACCOUNT_VERIFICATION_HMAC_KEY = previousKey;
    }
    const authority = makeAccountReservationAuthority({ workerPool: worker, issuerPool: issuer });
    const appClientId = 'https://paper.example.org/application';
    const appScope = crypto.createHash('sha256').update('activitypods:approved-app:v1\0').update(appClientId).digest('hex');
    const settings = { reserverPool: reserver, binderPool: binder, appClientId, hmacKey: crypto.randomBytes(32) };
    const admission = createCanonicalCoordinatorAdmission(settings);
    const reserve = async () => {
      const input = { appClientId: appScope, username: 'local-' + crypto.randomBytes(5).toString('hex'),
        idempotencyKey: crypto.randomUUID(), requestFingerprint: crypto.randomBytes(32).toString('hex'), dailyLimit: 100 };
      const result = await authority.reserve(input);
      assert.equal(result.outcome, 'reserved');
      const fence = { ...input, ...result };
      assert.equal(await authority.startSideEffects(fence), true);
      return { input, fence, request: { ...input, appScope, reservationId: result.reservationId } };
    };
    const lease = async f => {
      return (await issuer.query('SELECT paper_account_reservation_proof.dataset_claim_lease($1,$2,$3,$4,$5,$6) AS lease',
        ['https://paper.example.org/provider', appScope, f.fence.reservationId, f.fence.fenceToken,
          f.input.username, 'https://paper.example.org/' + f.input.username])).rows[0].lease;
    };
    for (const ownerUri of ['https://paper.example.org/users/scopecheck', 'https://other.example/scopecheck']) {
      await assert.rejects(worker.query(
        'SELECT * FROM paper_account_reservation_proof.reserve($1,$2,$3,$4,$5,$6,$7,$8)',
        ['https://paper.example.org/provider', appScope, crypto.randomBytes(32), crypto.randomBytes(32),
          'scopecheck', ownerUri, 100, 120]), { code: '22023' });
    }
    const first = await reserve();
    assert.equal(await authority.claimSignup(first.fence), false, 'unbound execution denied');
    assert.equal(await lease(first), null, 'unbound ticket denied');
    await assert.rejects(admission.admit({ ...first.request, appScope: '0'.repeat(64) }));
    const race = await Promise.allSettled([admission.admit(first.request), admission.admit(first.request)]);
    assert.equal(race.filter(r => r.status === 'fulfilled').length, 1);
    const admitted = race.find(r => r.status === 'fulfilled').value;
    const row = (await owner.query(`SELECT o.state,o.may_have_side_effects,r.v4_account_id,r.v4_operation_id
      FROM paper_account_candidate.signup_operations o JOIN paper_account_reservation_proof.reservations r
      ON r.v4_operation_id=o.operation_id WHERE o.operation_id=$1`, [admitted.operationId])).rows[0];
    assert.deepEqual(row, { state: 'reconciliation_required', may_have_side_effects: true,
      v4_account_id: admitted.accountId, v4_operation_id: admitted.operationId });
    assert(await lease(first) instanceof Date);
    const claims = await Promise.all([authority.claimSignup(first.fence), authority.claimSignup(first.fence)]);
    assert.equal(claims.filter(Boolean).length, 1);
    assert.equal((await authority.reserve(first.input)).fenceToken, null);
    await assert.rejects(admission.admit(first.request));
    assert.equal((await owner.query('SELECT count(*)::int AS n FROM paper_account_candidate.accounts')).rows[0].n, 1);
    await assert.rejects(reserver.query("UPDATE paper_account_candidate.accounts SET state='ready'"), { code: '42501' });
    await assert.rejects(reserver.query("UPDATE paper_account_candidate.signup_operations SET evidence_sealed_at=now()"), { code: '42501' });
    await assert.rejects(reserver.query('SELECT webid FROM paper_account_candidate.accounts'), { code: '42501' });

    const failed = await reserve();
    const broken = createCanonicalCoordinatorAdmission({ ...settings, binderPool: { connect: async () => { throw Error('lost binder'); } } });
    await assert.rejects(broken.admit(failed.request), { code: 'CANONICAL_SIGNUP_ADMISSION_UNAVAILABLE', retryable: false });
    await assert.rejects(admission.admit(failed.request), 'uncertain admission cannot start again');
    assert.equal(await lease(failed), null);
    assert.equal(await authority.claimSignup(failed.fence), false);
    assert.equal((await owner.query('SELECT count(*)::int AS n FROM paper_account_candidate.accounts')).rows[0].n, 2);

    const lost = await reserve();
    const lostAck = createCanonicalCoordinatorAdmission({ ...settings, binderPool: { async connect() {
      const client = await binder.connect();
      return { release: discard => client.release(discard), async query(sql, values) {
        const result = await client.query(sql, values);
        if (sql.startsWith('SELECT paper_account_reservation_proof.bind_v4_signup(')) throw Error('lost committed bind reply');
        return result;
      } };
    } } });
    await assert.rejects(lostAck.admit(lost.request));
    assert.equal((await owner.query('SELECT v4_bound_at IS NOT NULL AS bound FROM paper_account_reservation_proof.reservations WHERE reservation_id=$1', [lost.fence.reservationId])).rows[0].bound, true);
    assert.equal(await lease(lost), null, 'binding without the durable canonical side-effect fence is insufficient');
    assert.equal(await authority.claimSignup(lost.fence), false);
    await assert.rejects(admission.admit(lost.request));
    assert.equal((await owner.query('SELECT count(*)::int AS n FROM paper_account_candidate.accounts')).rows[0].n, 3);

    const handoffPool = await runtime('paper_enrollment_handoff');
    const enrollmentPool = await runtime('paper_enrollment_runtime');
    const providerId = 'https://paper.example.org';
    const webId = providerId + '/' + first.input.username;
    const returnUri = providerId + '/signup-return';
    const { createCandidate } = require('../candidates/postgres-account-lifecycle');
    const { makeBrowserEnrollmentService } = require('../candidates/provider-browser-enrollment-service');
    const identityBinder = await runtime('paper_enrollment_identity_binder');
    const lifecycle = createCandidate({ pool: identityBinder, fixtureOnly: true });
    let pendingReservation = first.fence.reservationId;
    const broker = { async call(action) {
      if (action === 'auth.account.findByWebId') {
        return { webId, username: first.input.username, signupReservationId: pendingReservation };
      }
      assert.equal(action, 'identitybindings.getByCanonicalAccountId');
      return { webId, activityPubActorId: webId, atprotoManaged: true, repoInitialized: true,
        atSigningKeyRef: 'signing-ref', atRotationKeyRef: 'rotation-ref', repoRootCid: 'test-root', repoRev: 'test-rev',
        atprotoDid: 'did:plc:' + 'a'.repeat(24), atprotoHandle: first.input.username + '.paper.example.org',
        atprotoPdsUrl: providerId };
    } };
    const enrollment = makeBrowserEnrollmentService({ broker, handoffPool, lifecycle,
      pool: enrollmentPool, providerId, appClientId, returnUri, browserOrigin: providerId,
      appUri: appClientId, csrfKey: crypto.randomBytes(32), fixtureOnly: true,
      loadRequirements: async () => ({ required: [appClientId + '#profile'], optional: [], revision: 'b'.repeat(64) })
    });
    const { ServiceBroker } = require('moleculer');
    const ApiGateway = require('moleculer-web');
    const { makeLocalBrowserSignupServices } = require('../candidates/provider-browser-enrollment-service');
    const httpBroker = new ServiceBroker({ logger:false });
    const gateway = httpBroker.createService({ mixins:[ApiGateway], settings:{ port:0, ip:'127.0.0.1',
      routes:[], logRequest:null, logResponse:null, log4XXResponses:false } });
    const previousEnv = Object.fromEntries(['APODS_ACCOUNT_VERIFICATION_HMAC_KEY','APODS_ACCOUNT_REQUEST_FINGERPRINT_KEY']
      .map(name => [name,process.env[name]]));
    try {
      for (const name of Object.keys(previousEnv)) process.env[name] = env[name];
      const signedScope = { providerId, appClientId, returnUri, browserOrigin:providerId };
      const services = makeLocalBrowserSignupServices({ ...signedScope, handoffPool,lifecycle,broker:httpBroker,
        verifierPool,redeemerPool, transactionKey:txConfig.encryptionKey, invitationPublicKey:invitationKeys.publicKey,
        appBearer:crypto.randomBytes(32).toString('base64url'), pool:enrollmentPool, csrfKey:crypto.randomBytes(32),
        fixtureOnly:true, appUri:appClientId, loadRequirements:async()=>({required:[],optional:[],revision:'b'.repeat(64)}) });
      httpBroker.createService({name:'auth.account'});
      httpBroker.createService({name:'auth-agent'});
      httpBroker.createService(services.schema);
      await httpBroker.start();
      const endpoint = 'http://127.0.0.1:'+gateway.server.address().port+'/api/signup-enrollment/verify';
      const invite = issueLocalInvitation({ scope:signedScope, privateKey:invitationKeys.privateKey,
        username:account.username,email:account.email });
      const post = origin => fetch(endpoint,{method:'POST',headers:{origin,'content-type':'application/json'},
        body:JSON.stringify({account,invitation:invite})});
      assert.equal((await post('https://another.example')).status,403);
      const response = await post(providerId);
      assert.equal(response.status,200);
      assert.deepEqual(await response.json(),{state:'verified'});
      const sessionCookie = response.headers.get('set-cookie');
      assert.match(sessionCookie,/^__Host-paper-signup=/u);
      assert.equal((await post(providerId)).status,403);
      const received = await makeBrowserSignupTransaction({ ...signedScope,pool:redeemerPool,encryptionKey:txConfig.encryptionKey })
        .consume({cookie:sessionCookie.split(';')[0],origin:providerId,fingerprint:signupFingerprint({
          api,appClientId,redirectUri:returnUri,accountParams:account,protocols:api.requestedProtocolsFromAccountParams.call(api, account),env
        })});
      assert.equal(received.idempotencyKey,invite.split('.')[0]);
    } finally {
      await httpBroker.stop();
      for(const [name,value] of Object.entries(previousEnv)) {
        if(value === undefined) delete process.env[name]; else process.env[name]=value;
      }
    }
    const handoff = enrollment.signupApi.methods.beginDisposableEnrollment;
    const cookies = [];
    const input = { reservationId: first.fence.reservationId, appClientId, redirectUri: returnUri,
      username: first.input.username, webId, setCookie: value => cookies.push(value) };
    await assert.rejects(handoff({ ...input, redirectUri: providerId + '/other' }));
    pendingReservation = failed.fence.reservationId;
    await assert.rejects(handoff(input));
    await assert.rejects(handoff({ ...input, reservationId: pendingReservation }));
    assert.deepEqual(cookies, []);
    pendingReservation = first.fence.reservationId;
    const handoffs = await Promise.allSettled([handoff(input), handoff(input)]);
    if (handoffs.every(result => result.status === "rejected")) throw handoffs[0].reason;
    assert.equal(handoffs.filter(result => result.status === 'fulfilled').length, 1);
    assert.equal(cookies.length, 1);
    assert.match(cookies[0], /^__Host-paper-enrollment=/u);
    const view = enrollment.schema.actions.view.handler;
    const session = await view({ meta: { enrollmentCookie: cookies[0].split(';')[0], enrollmentOrigin: providerId } });
    assert.equal(session.state, 'awaiting_consent');
    assert.deepEqual(session.requirements.required, [appClientId + '#profile']);
    await assert.rejects(view({ meta: { enrollmentCookie: cookies[0].split(';')[0],
      enrollmentOrigin: 'https://other.example.org' } }));
    assert.equal((await createCandidate({ pool: owner, fixtureOnly: true })
      .read({ providerId, accountId: admitted.accountId })).state, 'provisioning');
    await assert.rejects(identityBinder.query("UPDATE paper_account_candidate.accounts SET state='ready' WHERE account_id=$1",
      [admitted.accountId]), { code: '42501' });
    await assert.rejects(identityBinder.query("UPDATE paper_account_candidate.signup_operations SET state='ready'"),
      { code: '42501' });
    await assert.rejects(handoff(input));
    await assert.rejects(handoffPool.query('SELECT * FROM paper_account_candidate.accounts'), { code: '42501' });

    const drift = await reserve();
    await owner.query(`GRANT SELECT(webid) ON paper_account_candidate.accounts TO ${logins[2]}`);
    await assert.rejects(admission.admit(drift.request));
    await owner.query(`REVOKE SELECT(webid) ON paper_account_candidate.accounts FROM ${logins[2]}`);
    assert.equal((await owner.query('SELECT count(*)::int AS n FROM paper_account_candidate.accounts')).rows[0].n, 3);
    await owner.query(`GRANT EXECUTE ON FUNCTION paper_account_reservation_proof.canonical_signup_is_fenced(uuid) TO ${logins[2]}`);
    await assert.rejects(admission.admit(drift.request));
    await owner.query(`REVOKE EXECUTE ON FUNCTION paper_account_reservation_proof.canonical_signup_is_fenced(uuid) FROM ${logins[2]}`);
    assert.equal((await owner.query('SELECT count(*)::int AS n FROM paper_account_candidate.accounts')).rows[0].n, 3);
    const saved = process.env.NODE_ENV; process.env.NODE_ENV = 'production';
    try { assert.throws(() => createCanonicalCoordinatorAdmission(settings)); await assert.rejects(admission.admit(drift.request)); }
    finally { process.env.NODE_ENV = saved; }
  } finally {
    await Promise.allSettled(pools.map(p => p.end()));
    await owner?.end();
    if (databaseCreated) {
      // release(true) removes clients from pg's pool before their sockets have
      // finished closing. Never force-terminate those sockets during teardown.
      await drainDatabaseConnections(admin, database);
      await admin.query(`DROP DATABASE ${database}`);
    }
    for (const login of logins.reverse()) await admin.query(`DROP ROLE ${login}`);
    for (const role of [...new Set(createdRoles)].reverse()) await admin.query(`DROP ROLE IF EXISTS ${role}`);
    await admin.end();
  }
});


test('local coordinator configuration rejects unsafe files, endpoints and production', async () => {
  const os = require('node:os');
  const { loadCanonicalCoordinator } = await import('../candidates/atproto-signed-repo-proof/canonical-coordinator-config.mjs');
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'paper-coordinator-config-'));
  const filename = path.join(directory, 'private.json');
  const config = { appClientId: 'https://paper.example.org/application',
    reserverDsn: 'postgres://paper_account_reserver_login:disposable@127.0.0.1:5548/atproto_signed_repo_proof_test',
    binderDsn: 'postgres://paper_bridge_binder_login:disposable@127.0.0.1:5548/atproto_signed_repo_proof_test',
    hmacKeyBase64: crypto.randomBytes(32).toString('base64'), hmacKeyVersion: 1 };
  try {
    await fs.writeFile(filename, JSON.stringify(config), { mode: 0o600 });
    const loaded = await loadCanonicalCoordinator(filename); await loaded.close();
    await fs.chmod(filename, 0o644); await assert.rejects(loadCanonicalCoordinator(filename));
    await fs.chmod(filename, 0o600);
    await fs.symlink(filename, path.join(directory, 'link'));
    await assert.rejects(loadCanonicalCoordinator(path.join(directory, 'link')));
    for (const changed of [{ ...config, binderDsn: config.binderDsn + '?options=-crole=admin' },
      { ...config, extra: true }, { ...config, hmacKeyBase64: 'invalid' },
      { ...config, reserverDsn: config.reserverDsn.replace('127.0.0.1', 'other.example') }]) {
      await fs.writeFile(filename, JSON.stringify(changed)); await assert.rejects(loadCanonicalCoordinator(filename));
    }
    await fs.writeFile(filename, 'x'.repeat(16385)); await assert.rejects(loadCanonicalCoordinator(filename));
    await fs.writeFile(filename, JSON.stringify(config));
    const saved = process.env.NODE_ENV; process.env.NODE_ENV = 'production';
    try { await assert.rejects(loadCanonicalCoordinator(filename)); } finally { process.env.NODE_ENV = saved; }
  } finally { await fs.rm(directory, { recursive: true, force: true }); }
});
