'use strict';
const crypto = require('node:crypto');
const { ServiceBroker } = require('moleculer');

describe('new unified account: authorized API to one authoritative WebID/AP/PLC identity', () => {
  let broker;
  let signupCalls;
  let atprotoRepeat;
  let accountRecords;
  const app = Object.freeze({
    clientId: 'https://memory.example/app',
    bearerTokens: ['app-test-credential-not-production'],
    verificationTokens: ['verified-test-user'],
    allowedOrigins: ['https://memory.example'],
    allowAtproto: true,
    maxAccountsPerDay: 20
  });
  const limited = Object.freeze({
    clientId: 'https://limited.example/app',
    bearerTokens: ['limited-test-credential-not-production'],
    verificationTokens: ['verified-limited-test-user'],
    allowedOrigins: ['https://limited.example'],
    allowAtproto: true,
    maxAccountsPerDay: 1
  });

  function identity(username) {
    const webId = `https://pods.example/users/${username}`;
    const alphabet = 'abcdefghijklmnopqrstuvwxyz234567';
    const entropy = crypto.createHash('sha256').update(username).digest();
    const did = 'did:plc:' + Array.from(entropy.subarray(0, 24), b => alphabet[b & 31]).join('');
    return { webId, did };
  }
  function payload(username = 'alice', appClientId = app.clientId) {
    return {
      username,
      email: `${username}@example.test`,
      password: 'fixture-test-password-123',
      profile: { displayName: username },
      appClientId,
      verification: {
        method: 'email',
        challengeToken: appClientId === limited.clientId
          ? 'verified-limited-test-user' : 'verified-test-user'
      },
      protocols: {
        solid: true,
        activitypub: true,
        atproto: { enabled: true, didMethod: 'did:plc' }
      }
    };
  }
  function meta(clientId = app.clientId, idempotencyKey = 'once-only') {
    return {
      meta: {
        $headers: {
          authorization: clientId === limited.clientId
            ? 'Bearer limited-test-credential-not-production'
            : 'Bearer app-test-credential-not-production',
          origin: clientId === limited.clientId
            ? 'https://limited.example' : 'https://memory.example',
          ...(idempotencyKey ? { 'idempotency-key': idempotencyKey } : {})
        }
      }
    };
  }

  beforeAll(async () => {
    signupCalls = jest.fn(async ctx => {
      const { username } = ctx.params;
      const { webId, did } = identity(username);
      accountRecords.set(webId, {
        webId, activityPubActorId: webId,
        atprotoDid: did, atprotoHandle: `${username}.pods.example`,
        atprotoSource: 'local', atprotoManaged: true,
        repoInitialized: true, repoRootCid: 'bafy' + 'a'.repeat(48),
        repoRev: '3kskdumj2wvab',
        atSigningKeyRef: `sign:${username}`,
        atRotationKeyRef: `rotate:${username}`,
        atprotoPdsUrl: 'https://pds.example'
      });
      return {
        canonicalAccountId: webId, username, status: 'active',
        signupProvisioning: {
          webId, actorId: webId,
          activityPubHandle: `@${username}@pods.example`,
          did, atprotoHandle: `${username}.pods.example`,
          repoInitialized: true
        }
      };
    });
    atprotoRepeat = jest.fn(async () => {
      throw new Error('A second PLC submission must never occur');
    });
    accountRecords = new Map();
    broker = new ServiceBroker({ logger: false });
    broker.createService({ name: 'api', actions: { addRoute: () => true } });
    const provider = require('../services/provider-capabilities.service');
    broker.createService({
      ...provider,
      settings: {
        ...provider.settings,
        accountProvisioningEnabled: true,
        atprotoEnabled: true,
        approvedApps: [app, limited],
        requiresApprovedApps: true,
        requiresUserVerification: true,
        requireBearerToken: true,
        requireIdempotencyKey: true
      }
    });
    broker.createService({
      name: 'account-provisioning-state',
      actions: {
        begin: () => ({ provisioningId: crypto.randomUUID() }),
        markPhase: () => ({ ok: true }),
        finalize: () => ({ ok: true })
      }
    });
    broker.createService({ name: 'accounts', actions: { create: signupCalls } });
    broker.createService({
      name: 'webid-provisioning',
      actions: {
        create: ctx => {
          const { webId } = identity(ctx.params.username);
          return { webId, podBaseUrl: `https://pods.example/data/${ctx.params.username}/` };
        }
      }
    });
    broker.createService({
      name: 'activitypub-provisioning',
      actions: {
        provisionForAccount: ctx => {
          const { webId } = identity(ctx.params.username);
          return {
            actorId: webId, handle: `@${ctx.params.username}@pods.example`,
            inbox: webId + '/inbox', outbox: webId + '/outbox'
          };
        }
      }
    });
    broker.createService({
      name: 'identitybindings',
      actions: {
        getByCanonicalAccountId: ctx => accountRecords.get(ctx.params.canonicalAccountId) || null
      }
    });
    broker.createService({
      name: 'atproto-provisioning',
      actions: { provisionForAccount: atprotoRepeat }
    });
    broker.createService(require('../services/unified-account.service'));
    broker.createService(require('../services/unified-account-api.service'));
    await broker.start();
  });

  afterAll(async () => {
    await broker.stop();
  });

  test('approved new signup has one WebID=AP actor, managed did:plc, and no second PLC call', async () => {
    const result = await broker.call('unified-account-api.create',
      payload('alice'), meta(app.clientId, 'new-alice-1'));
    const { webId, did } = identity('alice');
    expect(result.canonicalAccountId).toBe(webId);
    expect(result.webId).toBe(webId);
    expect(result.activitypub.actorId).toBe(webId);
    expect(result.activitypub.inbox).toBe(webId + '/inbox');
    expect(result.atproto.did).toBe(did);
    expect(result.atproto.handle).toBe('alice.pods.example');
    expect(result.atproto.repoInitialized).toBe(true);
    expect(result.provisioning.state).toBe('completed');
    expect(signupCalls).toHaveBeenCalledTimes(1);
    expect(atprotoRepeat).not.toHaveBeenCalled();
    expect(JSON.stringify(result)).not.toContain('fixture-test-password-123');
  });

  test('an identical completed idempotency key replays without provisioning', async () => {
    const p = payload('bob');
    const opts = meta(app.clientId, 'new-bob-once');
    const first = await broker.call('unified-account-api.create', p, opts);
    const before = signupCalls.mock.calls.length;
    const replay = await broker.call('unified-account-api.create', p, opts);
    expect(replay).toEqual(first);
    expect(signupCalls.mock.calls.length).toBe(before);
    expect(atprotoRepeat).not.toHaveBeenCalled();
  });

  test('same key with a different request is rejected before a second signup', async () => {
    const opts = meta(app.clientId, 'new-claire-conflict');
    await broker.call('unified-account-api.create', payload('claire'), opts);
    const before = signupCalls.mock.calls.length;
    await expect(broker.call('unified-account-api.create', payload('claire2'), opts))
      .rejects.toMatchObject({ code: 409, type: 'idempotency_key_conflict' });
    expect(signupCalls.mock.calls.length).toBe(before);
  });

  test('unapproved app, missing verification or missing idempotency key cannot create', async () => {
    const before = signupCalls.mock.calls.length;
    await expect(broker.call('unified-account-api.create', payload('stranger', 'https://unknown.example'),
      meta(app.clientId, 'new-stranger')))
      .rejects.toMatchObject({ code: 403, type: 'unauthorized_app' });
    const noVerification = payload('unverified');
    delete noVerification.verification;
    await expect(broker.call('unified-account-api.create', noVerification,
      meta(app.clientId, 'new-unverified')))
      .rejects.toMatchObject({ code: 403, type: 'user_verification_required' });
    await expect(broker.call('unified-account-api.create', payload('no-key'),
      meta(app.clientId, null)))
      .rejects.toMatchObject({ code: 400, type: 'idempotency_key_required' });
    expect(signupCalls.mock.calls.length).toBe(before);
  });

  test('existing identity import and mandatory protocol opt-out are rejected before a reservation', async () => {
    const before = signupCalls.mock.calls.length;
    await expect(broker.call('unified-account-api.create', {
      ...payload('legacy'), atproto: { existingDid: identity('legacy').did }
    }, meta(app.clientId, 'legacy-denied')))
      .rejects.toMatchObject({ code: 400, type: 'UNIFIED_ACCOUNT_NEW_ONLY' });
    await expect(broker.call('unified-account-api.create', {
      ...payload('optout'), protocols: { solid: true, activitypub: false, atproto: true }
    }, meta(app.clientId, 'optout-denied')))
      .rejects.toMatchObject({ code: 400, type: 'UNIFIED_IDENTITY_REQUIRED' });
    expect(signupCalls.mock.calls.length).toBe(before);
  });

  test('per-approved-app daily quota rejects second new account', async () => {
    await broker.call('unified-account-api.create',
      payload('limit1', limited.clientId),
      meta(limited.clientId, 'limited-1'));
    const before = signupCalls.mock.calls.length;
    await expect(broker.call('unified-account-api.create',
      payload('limit2', limited.clientId),
      meta(limited.clientId, 'limited-2')))
      .rejects.toMatchObject({ code: 429, type: 'limit_exceeded' });
    expect(signupCalls.mock.calls.length).toBe(before);
  });
});
