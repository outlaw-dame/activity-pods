'use strict';
const { ServiceBroker } = require('moleculer');
const { randomUUID } = require('node:crypto');
jest.mock('../config/config', () => ({ BASE_URL:'https://paper.example.org/' }));
jest.mock('@semapps/solid', () => ({ StorageService: { name: 'solid-storage' } }));
jest.mock('@semapps/webid', () => ({ WebIdService: { name: 'webid' } }));
jest.mock('@semapps/activitypub', () => ({ FULL_ACTOR_TYPES: {} }));
const storage = require('../services/solid/storage');
const webid = require('../services/core/webid');

test('signup uses the prepared dataset exactly once and refuses stale and unrelated callers', async () => {
  const flags = ['APODS_ATPROTO_DATASET_ADMIN_DELEGATION_DISPOSABLE','APODS_ACCOUNT_RESERVATION_DISPOSABLE',
    'APODS_ACCOUNT_COORDINATOR_DISPOSABLE'];
  const before = flags.map(k => process.env[k]);
  const username = 'claimtest-12345678';
  const root = 'https://paper.example.org/' + username + '/data';
  const account = { username, signupReservationId: randomUUID() };
  const provision = jest.fn(() => ({ dataset: username }));
  const roots = [];
  const broker = new ServiceBroker({ logger: false });
  try {
    flags.forEach(k => { process.env[k] = 'confirmed'; });
    broker.createService({ name: 'dataset-provisioning', actions: { ensureSecureDataset: provision } });
    broker.createService({ name: 'ldp.container', actions: { create(ctx) {
      roots.push([ctx.params.containerUri,ctx.meta.dataset]); return true;
    } } });
    broker.createService({ name:'auth.account', actions:{ findByUsername(ctx) {
      expect(ctx.meta).toEqual({});
      return account;
    } } });
    broker.createService({ ...storage, settings: { ...storage.settings, baseUrl:'https://paper.example.org/',pathName:'data' } });
    broker.createService({ name:'webid', hooks:webid.hooks, actions:{ createWebId() { return true; } } });
    broker.createService({ name:'auth', actions:{ signup(ctx) {
      return ctx.call('webid.createWebId', { nick: username }, { meta:{ isSignup:true } });
    } } });
    await broker.start();
    await expect(broker.call('webid.createWebId', { nick:username }, { meta:{ isSignup:true } })).rejects.toThrow();
    await expect(broker.call('solid-storage.createPendingSignupRoot', { username })).rejects.toThrow();
    await broker.call('auth.signup');
    expect(roots).toEqual([[root, username]]);
    account.webId = 'https://paper.example.org/' + username;
    await expect(broker.call('auth.signup')).rejects.toThrow();
    expect(roots).toHaveLength(1);
    expect(provision).not.toHaveBeenCalled();
  } finally {
    await broker.stop();
    flags.forEach((key,i) => { if (before[i] === undefined) delete process.env[key]; else process.env[key] = before[i]; });
  }
});
