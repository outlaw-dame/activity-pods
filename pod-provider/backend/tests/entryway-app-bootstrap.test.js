const { ServiceBroker } = require('moleculer');

describe('entryway-app-bootstrap-api service', () => {
  let broker;
  let createOrUpdateCalls;
  let providerService;
  let findByWebId;
  let storedRegistration;
  let storedGrants;
  let storedAccessAuthorizations;
  let storedDataAuthorizations;
  let storageGetUrl;

  const approvedApp = {
    appClientId: 'https://memory.example/app',
    appUri: 'https://memory.example/app',
    acceptedAccessNeeds: ['https://memory.example/ns/access-needs#timeline'],
    acceptedSpecialRights: ['apods:ReadInbox', 'apods:ReadOutbox']
  };

  beforeEach(async () => {
    createOrUpdateCalls = [];
    storedRegistration = {
      id: 'http://localhost:3000/alice/data/app-registration-memory',
      'interop:registeredBy': 'http://localhost:3000/alice/profile/card#me',
      'interop:registeredAgent': approvedApp.appUri,
      'interop:hasAccessGrant': ['http://localhost:3000/alice/data/grant-memory']
    };
    storedGrants = [{
      id: 'http://localhost:3000/alice/data/grant-memory',
      'interop:grantedBy': 'http://localhost:3000/alice/profile/card#me',
      'interop:grantee': approvedApp.appUri
    }];
    storedAccessAuthorizations = [{
      'interop:grantedBy': 'http://localhost:3000/alice/profile/card#me',
      'interop:grantee': approvedApp.appUri,
      'apods:hasSpecialRights': approvedApp.acceptedSpecialRights
    }];
    storedDataAuthorizations = [{
      'interop:dataOwner': 'http://localhost:3000/alice/profile/card#me',
      'interop:grantee': approvedApp.appUri,
      'interop:satisfiesAccessNeed': approvedApp.acceptedAccessNeeds[0]
    }];
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
    storageGetUrl = jest.fn(async () => 'http://localhost:3000/alice/data/');
    broker.createService({
      name: 'solid-storage',
      actions: { getUrl: storageGetUrl }
    });
    broker.createService({
      name: 'auth.account',
      actions: { findByWebId }
    });

    broker.createService({
      name: 'app-registrations',
      actions: {
        getForApp: async () => storedRegistration,
        // Detect accidental reintroduction of privileged backend grants.
        createOrUpdate: async ctx => {
          createOrUpdateCalls.push(ctx.params);
          throw new Error('Backend must not mutate SAI grants');
        }
      }
    });

    broker.createService({
      name: 'access-grants',
      actions: { getForApp: async () => storedGrants }
    });
    broker.createService({
      name: 'access-authorizations',
      actions: { getForApp: async () => storedAccessAuthorizations }
    });
    broker.createService({
      name: 'data-authorizations',
      actions: { getForApp: async () => storedDataAuthorizations }
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

    expect(createOrUpdateCalls).toEqual([]);
  });

  function installPgProof(results = [{}]) {
    providerService.idempotencyRecords.clear();
    const base = {
      verified: true,
      accountId: '11111111-1111-4111-8111-111111111111',
      grantUri: 'http://localhost:3000/alice/data/grant-memory',
      consentRevision: '1', accountGeneration: '3',
      releaseAuthorized: false, canAuthenticate: false
    };
    const proof = jest.fn();
    for (const result of results) proof.mockResolvedValueOnce({ ...base, ...result });
    providerService.pgBootstrapReadiness = { assertCurrent: proof };
    providerService.pgBootstrapAppClientId = approvedApp.appClientId;
    return proof;
  }

  function pgPayload() {
    return {
      ...bootstrapPayload(),
      atprotoDid: 'did:plc:aaaaaaaaaaaaaaaaaaaaaaaa',
      atprotoHandle: 'alice.paper.example.org'
    };
  }

  test('uses current PG readiness instead of the volatile Map and rechecks SAI revision', async () => {
    const proof = installPgProof([{}, {}]);
    const result = await broker.call('entryway-app-bootstrap-api.bootstrap', pgPayload(), {
      meta: { $headers: { authorization: 'Bearer provider-internal-token' } }
    });
    expect(result.accessGrantUris).toEqual(['http://localhost:3000/alice/data/grant-memory']);
    expect(proof).toHaveBeenCalledTimes(2);
    for (const [input] of proof.mock.calls) {
      expect(input).toMatchObject({
        idempotencyKey: PROVIDER_IDEMPOTENCY_KEY,
        username: 'alice',
        webId: 'http://localhost:3000/alice/profile/card#me',
        actorId: 'http://localhost:3000/alice',
        atprotoDid: 'did:plc:aaaaaaaaaaaaaaaaaaaaaaaa',
        atprotoHandle: 'alice.paper.example.org'
      });
    }
    expect(storageGetUrl).toHaveBeenCalledTimes(1);
    expect(createOrUpdateCalls).toHaveLength(0);
  });

  test('a second approved signup client cannot borrow the pinned PG proof even with the same SAI app URI', async () => {
    const proof = installPgProof([{}, {}]);
    const appService = broker.getLocalService('entryway-app-bootstrap-api');
    const alternateClient = 'https://alternate.example/account-client';
    appService.settings.approvedApps.push({
      ...approvedApp,
      appClientId: alternateClient,
      // This is deliberately the same SAI application: sharing a grant
      // cannot confer another signup client's ledger privileges.
      appUri: approvedApp.appUri
    });

    await expect(broker.call('entryway-app-bootstrap-api.bootstrap', {
      ...pgPayload(),
      appClientId: alternateClient
    }, {
      meta: { $headers: { authorization: 'Bearer provider-internal-token' } }
    })).rejects.toMatchObject({
      code: 403,
      type: 'BOOTSTRAP_PG_SCOPE_INVALID'
    });
    expect(proof).not.toHaveBeenCalled();
    expect(storageGetUrl).not.toHaveBeenCalled();
    expect(createOrUpdateCalls).toEqual([]);

    // The provider-pinned client can still pass the same authority check.
    const response = await broker.call('entryway-app-bootstrap-api.bootstrap', pgPayload(), {
      meta: { $headers: { authorization: 'Bearer provider-internal-token' } }
    });
    expect(response.accessGrantUris).toEqual([
      'http://localhost:3000/alice/data/grant-memory'
    ]);
    expect(proof).toHaveBeenCalledTimes(2);
  });

  test('a configured PG reader without a pinned app client fails closed', async () => {
    const proof = installPgProof([{}, {}]);
    providerService.pgBootstrapAppClientId = null;
    await expect(broker.call('entryway-app-bootstrap-api.bootstrap', pgPayload(), {
      meta: { $headers: { authorization: 'Bearer provider-internal-token' } }
    })).rejects.toMatchObject({
      code: 403, type: 'BOOTSTRAP_PG_SCOPE_INVALID'
    });
    expect(proof).not.toHaveBeenCalled();
    expect(createOrUpdateCalls).toEqual([]);
  });

  test('rejects PG consent grant mismatch, revision drift and owner storage drift', async () => {
    const call = () => broker.call('entryway-app-bootstrap-api.bootstrap', pgPayload(), {
      meta: { $headers: { authorization: 'Bearer provider-internal-token' } }
    });

    installPgProof([{ grantUri: 'http://localhost:3000/alice/data/other-grant' }]);
    await expect(call()).rejects.toMatchObject({
      code: 409, type: 'BOOTSTRAP_CANONICAL_SAI_MISMATCH'
    });

    const proof = installPgProof([{}, { consentRevision: '2' }]);
    await expect(call()).rejects.toMatchObject({
      code: 409, type: 'BOOTSTRAP_CANONICAL_SAI_MISMATCH'
    });
    expect(proof).toHaveBeenCalledTimes(2);

    installPgProof([{}]);
    storageGetUrl.mockResolvedValueOnce('http://localhost:3000/bob/data/');
    await expect(call()).rejects.toMatchObject({
      code: 409, type: 'BOOTSTRAP_STORAGE_MISMATCH'
    });
    expect(createOrUpdateCalls).toHaveLength(0);
  });

  test('PG error never falls back to volatile Map or leaks database details', async () => {
    const proof = installPgProof();
    proof.mockReset().mockRejectedValue(new Error('postgres://admin:password@db/private'));
    await expect(broker.call('entryway-app-bootstrap-api.bootstrap', pgPayload(), {
      meta: { $headers: { authorization: 'Bearer provider-internal-token' } }
    })).rejects.toMatchObject({
      code: 503, type: 'BOOTSTRAP_PG_PROOF_UNAVAILABLE'
    });
    expect(createOrUpdateCalls).toHaveLength(0);
  });

  test('an injected PG reader never overrides the production bootstrap release fuse', async () => {
    installPgProof([{}, {}]);
    const original = process.env.NODE_ENV;
    process.env.NODE_ENV = 'production';
    try {
      await expect(broker.call('entryway-app-bootstrap-api.bootstrap', pgPayload(), {
        meta: { $headers: { authorization: 'Bearer provider-internal-token' } }
      })).rejects.toMatchObject({
        code: 503, type: 'BOOTSTRAP_DURABLE_AUTHORITY_REQUIRED'
      });
    } finally {
      if (original === undefined) delete process.env.NODE_ENV;
      else process.env.NODE_ENV = original;
    }
  });

  test('does not turn app approval into owner consent or create missing grants', async () => {
    storedRegistration = null;
    await expect(broker.call('entryway-app-bootstrap-api.bootstrap', bootstrapPayload(), {
      meta: { $headers: { authorization: 'Bearer provider-internal-token' } }
    })).rejects.toMatchObject({
      code: 428, type: 'BOOTSTRAP_OWNER_CONSENT_REQUIRED'
    });
    expect(createOrUpdateCalls).toEqual([]);
  });

  test('refuses mismatched, revoked and stale owner-authorized SAI records', async () => {
    const originalRegistration = storedRegistration;
    const originalGrants = storedGrants;
    const makeCall = () => broker.call('entryway-app-bootstrap-api.bootstrap', bootstrapPayload(), {
      meta: { $headers: { authorization: 'Bearer provider-internal-token' } }
    });
    for (const bad of [
      { ...originalRegistration, 'interop:registeredBy': 'http://localhost:3000/bob/profile/card#me' },
      { ...originalRegistration, 'interop:registeredAgent': 'https://another.example/app' },
      { ...originalRegistration, 'interop:hasAccessGrant': ['http://localhost:3000/alice/data/old-revoked-grant'] },
      { ...originalRegistration, 'interop:hasAccessGrant': [
        'http://localhost:3000/alice/data/grant-memory', 'http://localhost:3000/alice/data/grant-memory'
      ] }
    ]) {
      storedRegistration = bad;
      await expect(makeCall()).rejects.toMatchObject({ code: expect.any(Number) });
      expect(createOrUpdateCalls).toEqual([]);
    }
    storedRegistration = originalRegistration;
    for (const bad of [
      [],
      [{ ...originalGrants[0], 'interop:grantedBy': 'http://localhost:3000/bob/profile/card#me' }],
      [{ ...originalGrants[0], 'interop:grantee': 'https://another.example/app' }]
    ]) {
      storedGrants = bad;
      await expect(makeCall()).rejects.toMatchObject({ code: expect.any(Number) });
      expect(createOrUpdateCalls).toEqual([]);
    }
  });

  test('rejects owner-approved rights outside provider policy without creating or changing grants', async () => {
    storedAccessAuthorizations = [{
      ...storedAccessAuthorizations[0],
      'apods:hasSpecialRights': ['apods:UpdateWebId']
    }];
    await expect(broker.call('entryway-app-bootstrap-api.bootstrap', bootstrapPayload(), {
      meta: { $headers: { authorization: 'Bearer provider-internal-token' } }
    })).rejects.toMatchObject({ code: 409, type: 'BOOTSTRAP_CONSENT_SCOPE_MISMATCH' });
    expect(createOrUpdateCalls).toEqual([]);

    storedAccessAuthorizations = [];
    storedDataAuthorizations = [{
      ...storedDataAuthorizations[0],
      'interop:satisfiesAccessNeed': 'https://memory.example/ns/access-needs#unapproved'
    }];
    await expect(broker.call('entryway-app-bootstrap-api.bootstrap', bootstrapPayload(), {
      meta: { $headers: { authorization: 'Bearer provider-internal-token' } }
    })).rejects.toMatchObject({ code: 409, type: 'BOOTSTRAP_CONSENT_SCOPE_MISMATCH' });
    expect(createOrUpdateCalls).toEqual([]);
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
