'use strict';
// NONACTIVATED real PostgreSQL18 + freshly signed independent checkpoint proof.
// All accounts/keys/roles are disposable and created only inside CI.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { Pool } = require('pg');
const { createDisposableCredentialHeadAuthority, subjectHash } =
  require('../candidates/credential-signed-latest-head');
const { createDisposableCertifiedCredentialReader } =
  require('../candidates/credential-pg-certified-reader');
const { createDisposableCredentialEpochMiddleware } =
  require('../middlewares/credential-epoch');

if (process.env.CI !== 'true' || process.env.NODE_ENV !== 'test' ||
    process.env.PAPER_CREDENTIAL_HEAD_DISPOSABLE !== 'confirmed' ||
    process.env.PAPER_CREDENTIAL_PG_DISPOSABLE !== 'confirmed')
  throw Error('Refusing nondisposable credential head test');

const owner = 'https://paper.example.org/users/challenge-probe';
const admin = new Pool({
  host: process.env.PGHOST, port: Number(process.env.PGPORT),
  database: process.env.PGDATABASE, user: process.env.PGUSER,
  password: process.env.PGPASSWORD, max: 2, connectionTimeoutMillis: 2500
});
const readerLogin = 'paper_credential_reader_login_ci';
const password = crypto.randomBytes(24).toString('hex');
const opts = {
  host: process.env.PGHOST, port: Number(process.env.PGPORT),
  database: process.env.PGDATABASE, user: readerLogin,
  password, max: 2, connectionTimeoutMillis: 2500
};
let readerPool;
const clock = 1800000000;
const authorityId = 'witness.independent.test';
const {publicKey, privateKey} = crypto.generateKeyPairSync('ed25519');
const external = {
  epoch: '1', state: 'active', digest: '0'.repeat(64)
};
const domain = Buffer.from('paper:credential:attest:v1\0');
const sign = (challenge, data = external, key = privateKey) => {
  const body = Buffer.from(JSON.stringify({
    kind: 'paper.credential.head.v1', authority: authorityId,
    subject: challenge.subject, epoch: data.epoch, state: data.state,
    digest: data.digest, nonce: challenge.nonce, issuedAt: clock
  }));
  return { body, signature: crypto.sign(null, Buffer.concat([domain,body]), key) };
};
const mkAuthority = readHead => createDisposableCredentialHeadAuthority({
  readHead, trustedPublicKey: publicKey, authority: authorityId,
  fixtureOnly: true, now: () => clock
});
const good = mkAuthority(async challenge => sign(challenge));
const reader = () => createDisposableCertifiedCredentialReader({
  pool: readerPool, headAuthority: good, fixtureOnly: true
});
const rejected = async (call, code) => {
  await assert.rejects(call, error => error?.code === code,
    'must deny with explicit security code ' + code);
};
const as = async (sql, params = []) => (await admin.query(sql,params)).rows;

async function main() {
  try {
    const sqlroot = path.join(__dirname, '..', 'sql');
    for (const name of [
      'paper-credential-epoch-authority-v1.sql',
      'paper-credential-epoch-authority-v2-certified-head.sql'
    ]) {
      await admin.query(fs.readFileSync(path.join(sqlroot,name),'utf8'));
    }
    // A separate LOGIN, no elevated memberships, no admin credentials.
    await admin.query(`CREATE ROLE ${readerLogin} LOGIN PASSWORD '${password}'`);
    await admin.query(`GRANT paper_credential_reader TO ${readerLogin}
      WITH INHERIT TRUE, SET FALSE, ADMIN FALSE`);
    readerPool = new Pool(opts);
    assert.equal((await as(
      'SELECT paper_credential_epoch.enroll_owner($1::text) AS ok',[owner]))[0].ok,true);

    const first = await reader().readOwnerState(owner);
    assert.deepEqual(first,{webId:owner,mode:'unified',epoch:'1',state:'active'});
    // Compose the actual Paper RS256 admission middleware with the real
    // restricted PG18 reader. SemApps service routing is still a fixture.
    const rsa = crypto.generateKeyPairSync('rsa',{modulusLength:2048});
    const b64 = value => Buffer.from(JSON.stringify(value)).toString('base64url');
    const jwtSign = payload => {
      const input = b64({alg:'RS256',typ:'JWT'})+'.'+b64(payload);
      return input+'.'+crypto.sign('sha256',Buffer.from(input),
        rsa.privateKey).toString('base64url');
    };
    const jwtVerify = token => {
      const bits = typeof token === 'string' ? token.split('.') : [];
      if (bits.length !== 3 ||
          !crypto.verify('sha256',Buffer.from(bits[0]+'.'+bits[1]),
            rsa.publicKey,Buffer.from(bits[2]||'','base64url')))
        return false;
      try { return JSON.parse(Buffer.from(bits[1],'base64url').toString('utf8')); }
      catch { return false; }
    };
    const broker = { async call(name,params,options) {
      assert.equal(name,'auth.account.findByWebId');
      assert.equal(params.webId,owner);
      assert.deepEqual(options.meta,{});
      return {webId:owner,signupReservationId:'real-pg-reservation-0001'};
    }};
    const guard = createDisposableCredentialEpochMiddleware({
      fixtureOnly:true,authority:reader(),now:()=>clock
    });
    const mint = guard.localAction(ctx => jwtSign(ctx.params.payload),
      {name:'auth.jwt.generateServerSignedToken'});
    const inspect = guard.localAction(ctx => jwtVerify(ctx.params.token),
      {name:'auth.jwt.verifyServerSignedToken'});
    const issue = () => mint({broker,params:{payload:{webId:owner}}});
    const check = token => inspect({broker,params:{token}});
    const bearerEpoch1 = await issue();
    assert.equal((await check(bearerEpoch1)).paper_credential_epoch,'1');


    await assert.rejects(() => readerPool.query(
      'SELECT * FROM paper_credential_epoch.owners'));
    await assert.rejects(() => readerPool.query(
      'SELECT paper_credential_epoch.disable_owner($1)',[owner]));
    await assert.rejects(() => readerPool.query(
      'SET ROLE paper_credential_coordinator'));
    await rejected(async () => createDisposableCertifiedCredentialReader({
      pool: admin, headAuthority: good, fixtureOnly:true
    }).readOwnerState(owner),'CREDENTIAL_PG_ROLE_UNSAFE');

    const operation = crypto.randomUUID();
    const started = await as(
      'SELECT * FROM paper_credential_epoch.begin_change($1::text,$2::uuid,$3::bigint)',
      [owner,operation,'1']);
    assert.equal(started.length,1);
    assert.equal(started[0].following_epoch,'2');
    // Pending fence committed in PG while older external head still exists.
    await rejected(() => reader().readOwnerState(owner),'CREDENTIAL_PG_ROLLBACK_OR_RACE');
    assert.equal(await check(bearerEpoch1),false);
    external.state='pending';
    const pending = await reader().readOwnerState(owner);
    assert.equal(pending.state,'pending');
    assert.equal(await check(bearerEpoch1),false);
    // These data are NEVER an authorization for a bearer.
    assert.notEqual(pending.state,'active');

    const receipt = crypto.createHash('sha256').update('proof-committed-password-operation').digest('hex');
    const sealed = await as(
      'SELECT paper_credential_epoch.seal_change($1::text,$2::uuid,$3::bigint,$4::bytea) AS ok',
      [owner,operation,'2',Buffer.from(receipt,'hex')]);
    assert.equal(sealed[0].ok,true);
    // Database commit without independent latest-head ACK must deny.
    await rejected(() => reader().readOwnerState(owner),'CREDENTIAL_PG_ROLLBACK_OR_RACE');
    external.epoch='2'; external.state='active'; external.digest=receipt;
    assert.equal(await check(bearerEpoch1),false);
    const bearerEpoch2 = await issue();
    assert.equal((await check(bearerEpoch2)).paper_credential_epoch,'2');
    assert.equal((await reader().readOwnerState(owner)).epoch,'2');

    // A primary PostgreSQL rewind cannot resurrect an old JWT generation.
    await as(`UPDATE paper_credential_epoch.owners SET epoch=1,state='active',
      operation_id=NULL,next_epoch=NULL,mutation_digest=NULL WHERE webid=$1`,[owner]);
    await rejected(() => reader().readOwnerState(owner),'CREDENTIAL_PG_ROLLBACK_OR_RACE');
    assert.equal(await check(bearerEpoch2),false);
    await as(`UPDATE paper_credential_epoch.owners SET epoch=2,state='active',
      operation_id=NULL,next_epoch=NULL,mutation_digest=$2 WHERE webid=$1`,
      [owner,Buffer.from(receipt,'hex')]);
    assert.equal((await check(bearerEpoch2)).paper_credential_epoch,'2');

    // Former signed head cannot be replayed: a second request has a fresh
    // independently unpredictable nonce (not an HTTP caller-provided nonce).
    let oldReply;
    const replay = mkAuthority(async challenge => {
      if (!oldReply) oldReply = sign(challenge);
      return oldReply;
    });
    await replay.readFresh(owner);
    await rejected(() => replay.readFresh(owner),'CREDENTIAL_HEAD_SCOPE_INVALID');
    const foreign = crypto.generateKeyPairSync('ed25519');
    const fake = mkAuthority(async challenge => sign(challenge,external,foreign.privateKey));
    await rejected(() => fake.readFresh(owner),'CREDENTIAL_HEAD_SIGNATURE_INVALID');
    const badScope = mkAuthority(async challenge => sign({...challenge,subject:subjectHash(
      'https://paper.example.org/other')}));
    await rejected(() => badScope.readFresh(owner),'CREDENTIAL_HEAD_SCOPE_INVALID');

    let count=0;
    const racing = mkAuthority(async challenge => {
      count++;
      const state = count===1 ? {...external} :
        {...external,epoch:'3',state:'disabled',digest:'0'.repeat(64)};
      return sign(challenge,state);
    });
    const racedReader = createDisposableCertifiedCredentialReader({
      pool:readerPool,headAuthority:racing,fixtureOnly:true
    });
    await rejected(() => racedReader.readOwnerState(owner),'CREDENTIAL_PG_ROLLBACK_OR_RACE');
    const unavailable = mkAuthority(async () => { throw Error('remote failure'); });
    await rejected(() => unavailable.readFresh(owner),'CREDENTIAL_HEAD_UNAVAILABLE');
    // Override the default network timeout only through a new verified constructor.
    const timed = createDisposableCredentialHeadAuthority({
      readHead: () => new Promise(() => {}), trustedPublicKey:publicKey,
      authority:authorityId,fixtureOnly:true,now:()=>clock,timeoutMs:100
    });
    await rejected(() => timed.readFresh(owner),'CREDENTIAL_HEAD_UNAVAILABLE');

    assert.equal((await as(
      'SELECT paper_credential_epoch.disable_owner($1::text) AS ok',[owner]))[0].ok,true);
    external.epoch='3'; external.state='disabled'; external.digest='0'.repeat(64);
    assert.equal((await reader().readOwnerState(owner)).state,'disabled');
    assert.equal(await check(bearerEpoch2),false);
    assert.equal((await as(
      'SELECT paper_credential_epoch.enroll_owner($1::text) AS ok',[owner]))[0].ok,false);

    // A private "head" published outside the database is a test fixture;
    // it does not prove nonrewindable custody or independent administration.
    console.log('PASS: real PG18 credential reader + fresh Ed25519 nonce proof, rollback, races, role separation; NONACTIVATED');
  } finally {
    await readerPool?.end();
    await admin.end();
  }
}
main().catch(error => {
  // No database secrets or bearer tokens in error output.
  console.error('Credential head regression failed:',error.code || error.name);
  process.exitCode=1;
});
