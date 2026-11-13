'use strict';
const { ServiceBroker } = require('moleculer');
const unified = require('../services/unified-account.service');
const atproto = require('../services/core/atproto-provisioning');

describe('unified account: one authoritative signup and no fake production PDS', () => {
  const webId = 'https://pods.example/alice';
  const did = 'did:plc:abcdefghijklmnopqrstuvwx';
  let broker;
  let signups;
  let atprotoRepeat;
  const input = {
    username: 'alice', email: 'alice@example.test', password: 'correct-horse-example',
    profile: { displayName: 'Alice' }
  };
  beforeEach(async () => {
    signups = jest.fn(async () => ({
      canonicalAccountId: webId, username: 'alice', status: 'active',
      signupProvisioning: {
        webId, actorId: webId, activityPubHandle: '@alice@pods.example',
        did, atprotoHandle: 'alice.pods.example', repoInitialized: true
      }
    }));
    atprotoRepeat = jest.fn(async () => {
      throw new Error('Repeated PLC provisioning is prohibited');
    });
    broker = new ServiceBroker({ logger: false });
    broker.createService({ name: 'provider-capabilities', actions: {
      assertAccountProvisioningGrant: () => ({ allowed: true })
    }});
    broker.createService({ name: 'account-provisioning-state', actions: {
      begin: () => ({ provisioningId: 'prov-test' }),
      markPhase: () => ({ ok: true }),
      finalize: () => ({ ok: true })
    }});
    broker.createService({ name: 'accounts', actions: { create: signups } });
    broker.createService({ name: 'webid-provisioning', actions: {
      create: () => ({ webId, podBaseUrl: 'https://pods.example/alice/data' })
    }});
    broker.createService({ name: 'activitypub-provisioning', actions: {
      provisionForAccount: () => ({
        actorId: webId, handle: '@alice@pods.example',
        inbox: webId + '/inbox', outbox: webId + '/outbox'
      })
    }});
    broker.createService({ name: 'identitybindings', actions: {
      getByCanonicalAccountId: () => ({
        webId, activityPubActorId: webId, atprotoDid: did, atprotoHandle: 'alice.pods.example',
        atprotoSource: 'local', atprotoManaged: true, repoInitialized: true,
        repoRootCid: 'bafyreigenesisplaceholder', repoRev: '0',
        atSigningKeyRef: 'commit:secret-ref', atRotationKeyRef: 'rotate:secret-ref',
        atprotoPdsUrl: 'https://pods.example'
      })
    }});
    broker.createService({ name: 'atproto-provisioning', actions: {
      provisionForAccount: atprotoRepeat
    }});
    broker.createService(unified);
    await broker.start();
  });
  afterEach(async () => {
    await broker.stop();
  });
  it('does not call ATProto provisioning a second time when auth.signup supplied DID evidence', async () => {
    const result = await broker.call('unified-account.create', input, {
      meta: { accountProvisioning: { capabilityId: 'provider.account.provisioning' } }
    });
    expect(signups).toHaveBeenCalledTimes(1);
    expect(atprotoRepeat).not.toHaveBeenCalled();
    expect(result.webId).toBe(webId);
    expect(result.activitypub.actorId).toBe(webId);
    expect(result.atproto).toEqual({
      did, handle: 'alice.pods.example', repoInitialized: true,
      atprotoPdsUrl: 'https://pods.example'
    });
  });
  it('refuses inconsistent persisted DID evidence instead of reprovisioning', async () => {
    signups.mockResolvedValueOnce({
      canonicalAccountId: webId, signupProvisioning: {
        webId, actorId: webId, did: 'did:plc:bbbbbbbbbbbbbbbbbbbbbbbb',
        atprotoHandle: 'alice.pods.example', repoInitialized: true
      }
    });
    await expect(broker.call('unified-account.create', input, {
      meta: { accountProvisioning: { capabilityId: 'provider.account.provisioning' } }
    })).rejects.toMatchObject({ code: 503 });
    expect(atprotoRepeat).not.toHaveBeenCalled();
  });
  it('does not treat metadata placeholders as real PDS bootstrap in production', async () => {
    const former = process.env.NODE_ENV;
    process.env.NODE_ENV = 'production';
    const mockCtx = { call: jest.fn() };
    try {
      await expect(atproto.methods.initializeRepoState.call({}, mockCtx, {
        canonicalAccountId: webId, did, handle: 'alice.pods.example'
      })).rejects.toMatchObject({ type: 'ATPROTO_PDS_REPOSITORY_NOT_READY' });
      expect(mockCtx.call).not.toHaveBeenCalled();
      await expect(atproto.methods.verifyProvisionedState.call({}, mockCtx, {
        canonicalAccountId: webId, binding: { repoInitialized: true }, didMethod: 'plc'
      })).rejects.toMatchObject({ type: 'ATPROTO_PDS_REPOSITORY_NOT_READY' });
    } finally {
      if (former === undefined) delete process.env.NODE_ENV;
      else process.env.NODE_ENV = former;
    }
  });
});
