'use strict';
// Production-mode NEGATIVE acceptance; no real account, database or signing
// secrets. The middleware must close unscoped inherited data actions even
// when an internal broker caller spoofs privileged metadata.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { ServiceBroker } = require('moleculer');
const AccountEnrollment = require('../middlewares/account-enrollment');

if (process.env.CI !== 'true' || process.env.NODE_ENV !== 'production')
  throw Error('Raw account closure proof requires isolated production CI mode');

test('closed production refuses all generic write and direct identity creation routes', async () => {
  const generic = ['insert','update','remove','create','attachWebId'];
  const attempts = [];
  const owner = 'https://provider.example/users/legacy';
  const actions = Object.fromEntries(generic.map(name => [name,{
    handler() {attempts.push(name);return {accepted:true};}
  }]));
  actions.findByWebId = {handler(ctx) {
    assert.deepEqual(ctx.meta,{});
    assert.equal(ctx.params.webId,owner);
    return {webId:owner,username:'legacy'};
  }};
  actions.updateAccountSettings = {handler() {
    attempts.push('settings');
    return {changed:true};
  }};
  actions.setPassword = {handler() {
    attempts.push('setPassword');
    return {changed:true};
  }};
  const broker=new ServiceBroker({
    logger:false,cacher:false,middlewares:[AccountEnrollment()]
  });
  broker.createService({name:'auth.account',actions});
  try{
    await broker.start();
    for (const name of generic) {
      await assert.rejects(
        broker.call('auth.account.'+name,{
          id:'urn:AuthAccount:unscoped',webId:owner,
          password:'untrusted',signupReservationId:'spoofed'
        },{meta:{
          isSystemCall:true,webId:owner,dataset:'attacker-dataset'
        }}),
        {type:'ACCOUNT_UNSCOPED_IDENTITY_WRITE_DENIED'}
      );
    }
    assert.deepEqual(attempts,[],'no direct identity write can run');
    const prior=process.env.NODE_ENV;
    process.env.NODE_ENV='test';
    try{
      // The production boundary is captured when middleware is created:
      // changing environment at runtime cannot unlock existing brokers.
      await assert.rejects(broker.call('auth.account.update',{
        id:'urn:AuthAccount:unscoped',webId:owner
      }),{type:'ACCOUNT_UNSCOPED_IDENTITY_WRITE_DENIED'});
    }finally{process.env.NODE_ENV=prior;}
    assert.deepEqual(attempts,[]);
    // Legacy approved account operations remain supported. Only the
    // unscoped generic actions and closed-signup create/attach are denied.
    assert.deepEqual(await broker.call('auth.account.updateAccountSettings',{
      currentPassword:'legacy',email:'example@invalid.test'
    },{meta:{webId:owner}}),{changed:true});
    assert.deepEqual(await broker.call('auth.account.setPassword',{
      webId:owner,password:'legacy'
    }),{changed:true});
    assert.deepEqual(attempts,['settings','setPassword']);
  }finally{await broker.stop();}
});
