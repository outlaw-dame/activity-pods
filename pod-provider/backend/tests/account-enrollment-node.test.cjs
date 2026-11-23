'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { ServiceBroker } = require('moleculer');
const jwt = require('jsonwebtoken');
const JwtService = require('@semapps/auth/services/jwt');
const AccountEnrollment = require('../middlewares/account-enrollment');

test('real broker and RS256 service fence incomplete accounts across password, token mint and token use', async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'paper-enrollment-'));
  const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
  });
  await fs.writeFile(path.join(directory, 'jwtRS256.key'), privateKey, { mode: 0o600 });
  await fs.writeFile(path.join(directory, 'jwtRS256.key.pub'), publicKey);
  const webId = 'https://provider.example/users/alice';
  let account = { webId, username: 'alice' };
  let lookupFailure = false;
  let lookups = 0;
  const broker = new ServiceBroker({ logger: false, middlewares: [AccountEnrollment()] });
  broker.createService({
    name: 'auth.account',
    actions: {
      verify: { handler: () => account },
      findByWebId: { handler(ctx) {
        lookups++;
        assert.deepEqual(ctx.meta, {});
        assert.equal(ctx.params.webId, webId);
        if (lookupFailure) throw Error('private database diagnostic');
        return account;
      } }
    }
  });
  broker.createService({ mixins: [JwtService], settings: { jwtPath: directory } });
  try {
    await broker.start();
    const mint = () => broker.call('auth.jwt.generateServerSignedToken',
      { payload: { webId } }, { meta: { dataset: 'attacker', webId: 'attacker' } });
    const verify = token => broker.call('auth.jwt.verifyServerSignedToken', { token });
    const token = await mint();
    assert.equal(jwt.verify(token, publicKey, { algorithms: ['RS256'] }).webId, webId);
    assert.equal((await verify(token)).webId, webId);
    assert.equal((await broker.call('auth.account.verify', {})).webId, webId);

    // A previously signed token cannot bypass a newly observed enrollment
    // fence, nor can an alternate login method mint a new token for it.
    for (const marker of [crypto.randomUUID(), '', null, false, []]) {
      account = { webId, username: 'alice', signupReservationId: marker };
      await assert.rejects(mint(), { type: 'ACCOUNT_ENROLLMENT_INCOMPLETE' });
      await assert.rejects(broker.call('auth.account.verify', {}),
        { type: 'ACCOUNT_ENROLLMENT_INCOMPLETE' });
      assert.equal(await verify(token), false);
    }
    account = { webId, username: 'alice' };
    lookupFailure = true;
    const before = lookups;
    await assert.rejects(mint());
    assert.equal(lookups, before + 1, 'failed lookup is not retried');
    assert.equal(await verify(token), false);
    lookupFailure = false;
    account = null;
    await assert.rejects(mint(), { type: 'ACCOUNT_ENROLLMENT_INCOMPLETE' });
    assert.equal(await verify(token), false);
    account = { webId: 'https://provider.example/users/bob' };
    await assert.rejects(mint(), { type: 'ACCOUNT_ENROLLMENT_INCOMPLETE' });
    assert.equal(await verify(token), false);
    assert.equal(await verify('forged-token'), false);
  } finally {
    await broker.stop();
    await fs.rm(directory, { recursive: true, force: true });
  }
});


test('upstream SemApps enrolled-owner password/reset/tombstone actions fail closed before mutation', async () => {
  const webId = 'https://provider.example/users/unified';
  const legacy = 'https://provider.example/users/legacy';
  const mutations = [
    'setPassword', 'setNewPassword', 'generateResetPasswordToken',
    'updateAccountSettings', 'deleteByWebId', 'setTombstone'
  ];
  let account = {webId,username:'unified',signupReservationId:crypto.randomUUID()};
  let failLookup = false;
  const invoked = [];
  const lookups = [];
  const broker = new ServiceBroker({logger:false, cacher:false,
    middlewares:[AccountEnrollment()]});
  const actions = Object.fromEntries(mutations.map(name => [name,{
    handler() {invoked.push(name); return { changed:true }; }
  }]));
  actions.findByWebId = {handler(ctx) {
    lookups.push({params:{...ctx.params},meta:{...ctx.meta}});
    assert.deepEqual(ctx.meta,{});
    if (failLookup) throw Error('Sensitive storage error');
    return ctx.params.webId === account?.webId ? account : null;
  }};
  broker.createService({name:'auth.account',actions});
  try {
    await broker.start();
    for(const marker of [crypto.randomUUID(),'',null,false,[]]) {
      account={webId,username:'unified',signupReservationId:marker};
      for(const name of mutations){
        const params={webId,password:'fake-should-not-run',
          token:'untrusted',newPassword:'fake-should-not-run'};
        const meta=name==='updateAccountSettings'?
          {webId,dataset:'hostile-caller-dataset'} :
          {webId:'https://attacker.invalid/other',dataset:'hostile'};
        await assert.rejects(broker.call('auth.account.'+name,params,{meta}),
          {type:'ACCOUNT_ENROLLMENT_MUTATION_NOT_RELEASED'});
      }
    }
    assert.equal(invoked.length,0,'no enrolled action can execute a native mutation');
    assert.equal(lookups.length,mutations.length*5);
    account={webId,username:'unified'};
    // When the owner has no enrollment marker, do not rewrite the legacy
    // SemApps password/reset behavior (backward compatibility).
    for(const name of mutations) {
      const params={webId,password:'password',token:'token',newPassword:'next'};
      const meta={webId};
      assert.deepEqual(await broker.call('auth.account.'+name,params,{meta}),{changed:true});
    }
    assert.deepEqual(invoked,mutations);
    // Neither caller-controlled routing metadata nor alternate account lookup
    // errors can relax the fence. No retries on ambiguous storage failure.
    account={webId,username:'unified',signupReservationId:crypto.randomUUID()};
    const before=lookups.length;
    failLookup=true;
    await assert.rejects(broker.call('auth.account.setPassword',
      {webId,password:'password'}),{type:'ACCOUNT_ENROLLMENT_MUTATION_NOT_RELEASED'});
    assert.equal(lookups.length,before+1);
    failLookup=false;
    await assert.rejects(broker.call('auth.account.updateAccountSettings',
      {newPassword:'password'},{meta:{webId:legacy}}),
      {type:'ACCOUNT_ENROLLMENT_MUTATION_NOT_RELEASED'});
    await assert.rejects(broker.call('auth.account.setNewPassword',
      {webId:legacy,token:'not-valid',password:'password'}),
      {type:'ACCOUNT_ENROLLMENT_MUTATION_NOT_RELEASED'});
    await assert.rejects(broker.call('auth.account.updateAccountSettings',
      {newPassword:'password'},{meta:{}}),
      {type:'ACCOUNT_ENROLLMENT_MUTATION_NOT_RELEASED'});
    assert.deepEqual(invoked,mutations);
  }finally{await broker.stop();}
});
