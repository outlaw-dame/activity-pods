'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const { ServiceBroker } = require('moleculer');
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
  } finally { await broker.stop(); }
});
