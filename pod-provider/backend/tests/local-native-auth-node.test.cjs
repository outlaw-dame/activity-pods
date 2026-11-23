'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const { ServiceBroker } = require('moleculer');
const { Pool } = require('pg');
const NativeAccount = require('@semapps/auth/services/account');
const { TripleStoreAdapter } = require('@semapps/triplestore');
const { localNativeAccountStore } = require('../candidates/local-native-account-store');
const accountEnrollment = require('../middlewares/account-enrollment');

test('native signup stores a bcrypt account, attaches the reserved owner and enforces the login fence after restart', async () => {
  const username = 'claimtest-' + randomUUID().slice(0,8);
  const reservation = randomUUID();
  const email = username + '@example.test';
  const password = randomUUID();
  const webId = 'https://paper.example.org/' + username;
  // The native auth + canonical revocation SQL is never accessed against a
  // hosted account: this is the fixed isolated GitHub Actions PG18 fixture.
  const adminDsn = 'postgres://paper_probe:probe_local_only@127.0.0.1:5548/atproto_signed_repo_proof_test';
  if (process.env.NODE_ENV !== 'test' ||
      process.env.PAPER_CREDENTIAL_NATIVE_DISPOSABLE !== 'confirmed' ||
      process.env.PAPER_CREDENTIAL_PG_DISPOSABLE !== 'confirmed' ||
      process.env.PAPER_NATIVE_CREDENTIAL_TEST_DSN !== adminDsn)
    throw Error('Real SemApps credential regression requires disposable PG18');
  const controlPool = new Pool({
    connectionString: adminDsn, max: 1, connectionTimeoutMillis: 2500
  });
  const makeBroker = () => {
    const broker = new ServiceBroker({logger:false, cacher:false,
      middlewares:[localNativeAccountStore(), accountEnrollment()]});
    broker.createService({name:'triplestore'});
    const account = broker.createService({mixins:[NativeAccount],
      adapter:new TripleStoreAdapter({type:'AuthAccount', dataset:'paper-private-auth'})});
    return {broker,account};
  };
  let {broker,account} = makeBroker();
  let id;
  try {
    await broker.start();
    const submitted = { username, email, password, signupReservationId:reservation };
    const concurrent = await Promise.allSettled([1,2].map(() => broker.call('auth.account.create',submitted)));
    assert.equal(concurrent.filter(result => result.status === 'fulfilled').length,1);
    const record = await broker.call('auth.account.findByUsername',{username});
    id = record['@id'];
    assert.equal(record.password, undefined);
    assert.equal(await account.comparePassword(password,record.hashedPassword),true);
    assert.equal(await account.comparePassword(password+'wrong',record.hashedPassword),false);
    await assert.rejects(broker.call('auth.account.attachWebId',{accountUri:id,webId:webId+'wrong'}));
    await broker.call('auth.account.attachWebId',{accountUri:id,webId});
    // Verify the actual upstream @semapps/auth 1.1.4 action handlers are
    // blocked by the always-registered broker middleware, not only a fake
    // action fixture. The underlying PostgreSQL v3 trigger is an additional
    // independent defense against direct adapter or service bypass.
    assert.equal((await controlPool.query(
      'SELECT paper_credential_epoch.enroll_owner($1) AS accepted',[webId]
    )).rows[0].accepted,true);
    const prior = await broker.call('auth.account.findByWebId',{webId});
    assert.equal(prior.hashedPassword,record.hashedPassword);
    const nextHash = await account.hashPassword('different-credential');
    const blocked = [
      ['setPassword',{webId,password:'different-credential'}],
      ['setNewPassword',{webId,token:'untrusted-token',password:'different-credential'}],
      ['generateResetPasswordToken',{webId}],
      ['updateAccountSettings',{currentPassword:password,newPassword:'different-credential'}],
      ['deleteByWebId',{webId}],
      ['setTombstone',{webId}]
    ];
    for (const [name,params] of blocked) {
      await assert.rejects(broker.call('auth.account.'+name,params,{
        meta:{webId,dataset:'untrusted-routing'} }),
        {type:'ACCOUNT_ENROLLMENT_MUTATION_NOT_RELEASED'},
        name+' must not bypass canonical credential pending-state');
    }
    await assert.rejects(account.adapter.updateById(id,
      {$set:{hashedPassword:nextHash}}),
      /Private account operation unavailable/);
    await assert.rejects(account.adapter.removeById(id),
      /Private account operation unavailable/);
    const untouched = await broker.call('auth.account.findByWebId',{webId});
    assert.equal(untouched.hashedPassword,prior.hashedPassword);
    assert.equal(untouched.signupReservationId,reservation);
    assert.equal((await controlPool.query(
      'SELECT state,epoch FROM paper_credential_epoch.read_certified($1)',[webId]
    )).rows[0].state,'active');
    assert.equal((await controlPool.query(
      'SELECT count(*)::integer AS operations FROM paper_credential_epoch.native_writes'
    )).rows[0].operations,0);
    const locale = 'Locale "Example" / 日本語';
    await Promise.all([account.adapter.updateById(id,{$set:{preferredLocale:locale}}),
      account.adapter.updateById(id,{$set:{displayName:'Pending owner'}})]);
    await assert.rejects(account.adapter.updateById(id,{$set:{signupReservationId:null}}));
    await broker.stop();
    ({broker,account} = makeBroker());
    await broker.start();
    const retained = await broker.call('auth.account.findByWebId',{webId});
    assert.equal(retained.signupReservationId,reservation);
    assert.equal(retained.preferredLocale,locale);
    assert.equal(retained.displayName,'Pending owner');
    assert.equal(retained['@id'],id);
    await assert.rejects(broker.call('auth.account.verify',{username,password}),{type:'ACCOUNT_ENROLLMENT_INCOMPLETE'});
    await assert.rejects(broker.call('auth.account.verify',{username,password:'incorrect'}),/account.not-found/);
  } finally { await Promise.allSettled([broker.stop(), controlPool.end()]); }
});
