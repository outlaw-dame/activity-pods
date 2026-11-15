const { ServiceBroker } = require('moleculer');

describe('entryway-app-bootstrap-api service', () => {
  let broker;
  let createOrUpdateCalls;
  let providerService;
  let findByWebId;

  const approvedApp = {
    appClientId: 'https://memory.example/app',
    appUri: 'https://memory.example/app',
    acceptedAccessNeeds: ['https://memory.example/ns/access-needs#timeline'],
    acceptedSpecialRights: ['apods:ReadInbox', 'apods:ReadOutbox']
  };

  beforeEach(async () => {
    createOrUpdateCalls = [];
    broker = new ServiceBroker({ logger: false });

    broker.createService({
      name: 'api',
      actions: {
        addRoute: async () => true
      }
    });

    const provider = require('../services/provider-capabilities.service');
    broker.createService({
      ...provider,
      settings: {
        ...provider.settings,
        approvedApps: [{
          clientId: approvedApp.appClientId,
          bearerTokens: ['account-signup-token'],
          allowedOrigins: ['https://memory.example'],
          allowedRedirectUris: ['https://memory.example/auth/callback']
        }]
      }
    });
    findByWebId = jest.fn(async () => ({ username: 'alice', disabled: false }));
    broker.createService({
      name: 'auth.account',
      actions: { findByWebId }
    });

    broker.createService({
      name: 'app-registrations',
      actions: {
        createOrUpdate: async ctx => {
          createOrUpdateCalls.push(ctx.params);
          return 'http://localhost:3000/alice/data/app-registration-memory';
        }
      }
    });

    broker.createService({
      name: 'access-grants',
      actions: {
        getForApp: async () => [{ id: 'http://localhost:3000/alice/data/grant-memory' }]
      }
    });

    const service = require('../services/entryway-app-bootstrap-api.service');
    broker.createService({
      ...service,
      settings: {
        ...service.settings,
        enabled: true,
        internalBearerToken: 'provider-internal-token',
        approvedApps: [approvedApp]
      }
    });

    await broker.start();
    providerService = broker.getLocalService('provider-capabilities');
    seedCompletedSignup(providerService, approvedApp.appClientId);
  });

  afterEach(async () => {
    await broker.stop();
  });

  test('registers an approved app and returns only registration/grant metadata', async () => {
    const result = await broker.call('entryway-app-bootstrap-api.bootstrap', bootstrapPayload(), {
      meta: {
        $headers: {
          authorization: 'Bearer provider-internal-token'
        }
      }
    });

    expect(result).toMatchObject({
      appRegistrationUri: 'http://localhost:3000/alice/data/app-registration-memory',
      accessGrantUris: ['http://localhost:3000/alice/data/grant-memory']
    });
    expect(result).toHaveProperty('bootstrappedAt');
    expect(JSON.stringify(result)).not.toContain('provider-internal-token');

    expect(createOrUpdateCalls).toEqual([
      {
        appUri: 'https://memory.example/app',
        podOwner: 'http://localhost:3000/alice/profile/card#me',
        acceptedAccessNeeds: approvedApp.acceptedAccessNeeds,
        acceptedSpecialRights: approvedApp.acceptedSpecialRights
      }
    ]);
  });

  test('requires a completed signup record before creating any grants', async () => {
    const recordKey = providerService.buildIdempotencyRecordKey(
      approvedApp.appClientId, PROVIDER_IDEMPOTENCY_KEY);
    const record = providerService.idempotencyRecords.get(recordKey);

    for (const mutated of [
      { ...record, status: 'in_progress' },
      { ...record, status: 'failed' },
      { ...record, expiresAt: Date.now() - 1 },
      { ...record, response: { ...record.response, webId: 'http://localhost:3000/bob/profile/card#me' } },
      { ...record, response: { ...record.response, activitypub: { actorId: 'http://localhost:3000/bob' } } },
      { ...record, response: { ...record.response, solid: { ...record.response.solid, podBaseUrl: 'http://localhost:3000/bob/data/' } } },
      { ...record, username: 'bob' }
    ]) {
      providerService.idempotencyRecords.set(recordKey, mutated);
      await expect(broker.call('entryway-app-bootstrap-api.bootstrap', bootstrapPayload(), {
        meta: { $headers: { authorization: 'Bearer provider-internal-token' } }
      })).rejects.toMatchObject({ code: 403, type: 'BOOTSTRAP_PROVISIONING_UNVERIFIED' });
      expect(createOrUpdateCalls).toHaveLength(0);
    }
    providerService.idempotencyRecords.set(recordKey, record);
  });

  test('rejects cross-account, cross-app and forged provenance references before SAI mutation', async () => {
    for (const changes of [
      { webId: 'http://localhost:3000/bob/profile/card#me', canonicalAccountId: 'http://localhost:3000/bob/profile/card#me' },
      { username: 'bob' },
      { actorId: 'http://localhost:3000/bob' },
      { podStorageUrl: 'http://localhost:3000/bob/data/' },
      { appClientId: 'https://unknown.example/app' },
      { idempotencyKey: 'entryway:acct_22222222-2222-4222-8222-222222222222:aaaaaaaaaaaaaaaaaaaaaaaa' },
      { idempotencyKey: 'not-a-provider-reference' },
      { atprotoDid: 'did:plc:someone-else' }
    ]) {
      await expect(broker.call('entryway-app-bootstrap-api.bootstrap', {
        ...bootstrapPayload(), ...changes
      }, {
        meta: { $headers: { authorization: 'Bearer provider-internal-token' } }
      })).rejects.toMatchObject({ code: expect.any(Number) });
      expect(createOrUpdateCalls).toHaveLength(0);
    }
  });

  test('rejects missing, disabled or mismatched local owner before writing grants', async () => {
    for (const owner of [null, { username: 'alice', disabled: true }, { username: 'bob', disabled: false }]) {
      findByWebId.mockResolvedValueOnce(owner);
      await expect(broker.call('entryway-app-bootstrap-api.bootstrap', bootstrapPayload(), {
        meta: { $headers: { authorization: 'Bearer provider-internal-token' } }
      })).rejects.toMatchObject({ code: 403, type: 'BOOTSTRAP_OWNER_UNVERIFIED' });
      expect(createOrUpdateCalls).toHaveLength(0);
    }
  });

  test('production never uses process-local signup state as authority for SAI writes', async () => {
    const original = process.env.NODE_ENV;
    process.env.NODE_ENV = 'production';
    try {
      await expect(broker.call('entryway-app-bootstrap-api.bootstrap', bootstrapPayload(), {
        meta: { $headers: { authorization: 'Bearer provider-internal-token' } }
      })).rejects.toMatchObject({ code: 503, type: 'BOOTSTRAP_DURABLE_AUTHORITY_REQUIRED' });
      expect(createOrUpdateCalls).toHaveLength(0);
    } finally {
      if (original === undefined) delete process.env.NODE_ENV;
      else process.env.NODE_ENV = original;
    }
  });

  test('rejects missing or invalid internal bearer token', async () => {
    await expect(
      broker.call('entryway-app-bootstrap-api.bootstrap', bootstrapPayload(), {
        meta: { $headers: { authorization: 'Bearer wrong-token' } }
      })
    ).rejects.toMatchObject({
      code: 401,
      type: 'UNAUTHORIZED'
    });
  });

  test('rejects apps that are not approved for bootstrap', async () => {
    await expect(
      broker.call(
        'entryway-app-bootstrap-api.bootstrap',
        {
          ...bootstrapPayload(),
          appClientId: 'https://unknown.example/app'
        },
        {
          meta: { $headers: { authorization: 'Bearer provider-internal-token' } }
        }
      )
    ).rejects.toMatchObject({
      code: 403,
      type: 'UNAUTHORIZED_APP'
    });
  });

  test('rejects mismatched canonicalAccountId and webId for current bootstrap path', async () => {
    await expect(
      broker.call(
        'entryway-app-bootstrap-api.bootstrap',
        {
          ...bootstrapPayload(),
          canonicalAccountId: 'http://localhost:3000/alice/internal-subject'
        },
        {
          meta: { $headers: { authorization: 'Bearer provider-internal-token' } }
        }
      )
    ).rejects.toMatchObject({
      code: 400,
      type: 'IDENTITY_MISMATCH'
    });
  });
});

function bootstrapPayload() {
  return {
    accountId: 'acct_11111111-1111-4111-8111-111111111111',
    canonicalAccountId: 'http://localhost:3000/alice/profile/card#me',
    username: 'alice',
    webId: 'http://localhost:3000/alice/profile/card#me',
    actorId: 'http://localhost:3000/alice',
    podStorageUrl: 'http://localhost:3000/alice/data/',
    providerId: 'default',
    appClientId: 'https://memory.example/app',
    idempotencyKey: PROVIDER_IDEMPOTENCY_KEY
  };
}

const PROVIDER_IDEMPOTENCY_KEY =
  'entryway:acct_11111111-1111-4111-8111-111111111111:aaaaaaaaaaaaaaaaaaaaaaaa';

function seedCompletedSignup(providerService, appClientId, overrides = {}) {
  const account = {
    canonicalAccountId: 'http://localhost:3000/alice/profile/card#me',
    webId: 'http://localhost:3000/alice/profile/card#me',
    activitypub: { actorId: 'http://localhost:3000/alice' },
    solid: {
      webId: 'http://localhost:3000/alice/profile/card#me',
      podBaseUrl: 'http://localhost:3000/alice/data/'
    },
    atproto: { did: 'did:plc:example', handle: 'alice.test' },
    provisioning: { state: 'completed' },
    ...overrides
  };
  providerService.idempotencyRecords.set(
    providerService.buildIdempotencyRecordKey(
      appClientId, PROVIDER_IDEMPOTENCY_KEY),
    {
      key: PROVIDER_IDEMPOTENCY_KEY,
      appClientId,
      username: 'alice',
      requestFingerprint: 'provider-record-fingerprint',
      status: 'completed',
      expiresAt: Date.now() + 60_000,
      response: account
    }
  );
}
