'use strict';

const signingSchema = require('../services/signing.service');

const ACTOR = 'http://localhost:3000/alice';
const KEY_ID = 'http://localhost:3000/public-key/alice-rsa';
function makeService(overrides = {}) {
  return {
    settings: signingSchema.settings,
    ...signingSchema.methods,
    ...overrides
  };
}

function localAccount(overrides = {}) {
  return { username: 'alice', webId: ACTOR, ...overrides };
}

function localActor(overrides = {}) {
  return {
    id: ACTOR,
    type: 'Person',
    publicKey: {
      id: KEY_ID,
      owner: ACTOR,
      publicKeyPem: 'PUBLIC'
    },
    ...overrides
  };
}

function rsaPrivateKey(overrides = {}) {
  return {
    id: 'http://localhost:3000/alice/data/key/private-rsa',
    owner: ACTOR,
    controller: ACTOR,
    privateKeyPem: 'PRIVATE',
    'rdfs:seeAlso': KEY_ID,
    ...overrides
  };
}

describe('ActivityPub signing authority boundary', () => {
  test.each([
    ['person account', localAccount()],
    ['group account', localAccount({ group: true })]
  ])('accepts an exact local %s only after account and actor proof', async (_label, account) => {
    const ctx = {
      meta: { traceId: 'trace-actor' },
      call: jest.fn(async (action, params, options) => {
        if (action === 'auth.account.findByWebId') {
          expect(params).toEqual({ webId: ACTOR });
          return account;
        }
        if (action === 'activitypub.actor.get') {
          expect(params).toEqual({ actorUri: ACTOR, webId: 'system' });
          expect(options).toEqual({
            meta: { traceId: 'trace-actor', dataset: 'alice', webId: ACTOR }
          });
          return localActor();
        }
        throw new Error(`Unexpected action: ${action}`);
      })
    };
    const result = await makeService()._validateLocalActor(ctx, ACTOR);
    expect(result.ok).toBe(true);
    expect(result.account).toEqual(account);
    expect(result.actor.id).toBe(ACTOR);
    expect(ctx.call.mock.calls.map(([name]) => name)).toEqual([
      'auth.account.findByWebId',
      'activitypub.actor.get'
    ]);
  });

  test.each([
    ['remote actor', 'https://remote.example/users/alice'],
    ['same-host non-account', 'http://localhost:3000/not-a-user']
  ])('rejects %s before accepting actor authority', async (_label, actorUri) => {
    const ctx = {
      call: jest.fn(async action => {
        if (action === 'auth.account.findByWebId') return null;
        throw new Error(`Unexpected action: ${action}`);
      })
    };
    const result = await makeService()._validateLocalActor(ctx, actorUri);
    expect(result).toMatchObject({ ok: false, error: 'ACTOR_NOT_LOCAL', retryable: false });
    expect(ctx.call).toHaveBeenCalledTimes(1);
  });

  test('fails closed and retryable when account authority is unavailable', async () => {
    const ctx = { call: jest.fn(async () => { throw new Error('database unavailable'); }) };
    await expect(makeService()._validateLocalActor(ctx, ACTOR)).resolves.toEqual({
      ok: false,
      error: 'ACTOR_NOT_LOCAL',
      message: 'local account verification unavailable',
      retryable: true
    });
  });

  test('requires the resolved actor ID to exactly match the requested actor URI', async () => {
    const ctx = {
      call: jest.fn(async action => {
        if (action === 'auth.account.findByWebId') return localAccount();
        if (action === 'activitypub.actor.get') return localActor({ id: 'http://localhost:3000/bob' });
        throw new Error(`Unexpected action: ${action}`);
      })
    };
    const result = await makeService()._validateLocalActor(ctx, ACTOR);
    expect(result).toMatchObject({ ok: false, error: 'ACTOR_NOT_LOCAL', retryable: false });
  });

  test('rejects non-HTTP actors and URL credentials before any authority lookup', async () => {
    for (const actorUri of [
      'did:example:alice',
      'ftp://localhost/alice',
      'http://user:password@localhost:3000/alice',
      'not a URL'
    ]) {
      const ctx = { call: jest.fn() };
      const result = await makeService()._validateLocalActor(ctx, actorUri);
      expect(result).toMatchObject({ ok: false, error: 'INVALID_INPUT', retryable: false });
      expect(ctx.call).not.toHaveBeenCalled();
    }
  });

  test('resolves exactly one actor-attached RSA key in the authoritative account dataset', async () => {
    const ctx = {
      meta: { traceId: 'trace-1' },
      call: jest.fn(async (action, params, options) => {
        const expectedMeta = { traceId: 'trace-1', dataset: 'alice', webId: ACTOR };
        expect(options).toEqual({ meta: expectedMeta });
        if (action === 'keys.findPrivateKeyUri') {
          expect(params).toEqual({ publicKeyUri: KEY_ID });
          return rsaPrivateKey().id;
        }
        if (action === 'keys.container.get') {
          expect(params).toEqual({
            resourceUri: rsaPrivateKey().id,
            accept: 'application/ld+json',
            webId: ACTOR
          });
          return rsaPrivateKey();
        }
        throw new Error(`Unexpected action: ${action}`);
      })
    };
    await expect(
      makeService()._resolveActivityPubSigningMaterial(ctx, ACTOR, localAccount(), localActor())
    ).resolves.toEqual({ ok: true, keyId: KEY_ID, privateKeyPem: 'PRIVATE' });
  });

  test.each([
    ['wrong owner', rsaPrivateKey({ owner: 'http://localhost:3000/bob' })],
    ['wrong controller', rsaPrivateKey({ controller: 'http://localhost:3000/bob' })],
    ['missing private key', rsaPrivateKey({ privateKeyPem: undefined })],
    ['unattached key', rsaPrivateKey({ 'rdfs:seeAlso': 'http://localhost:3000/public-key/other' })],
    ['unsafe key identifier', rsaPrivateKey({ 'rdfs:seeAlso': 'https://pods.example/key\"algorithm=none' })]
  ])('rejects signing material with %s', async (_label, key) => {
    const ctx = {
      meta: {},
      call: jest.fn(async action => {
        if (action === 'keys.findPrivateKeyUri') return key.id;
        if (action === 'keys.container.get') return key;
        throw new Error(`Unexpected action: ${action}`);
      })
    };
    const result = await makeService()._resolveActivityPubSigningMaterial(
      ctx,
      ACTOR,
      localAccount(),
      localActor()
    );
    expect(result).toMatchObject({ ok: false, error: 'KEY_UNAVAILABLE', retryable: false });
  });

  test('rejects ambiguous actor-controlled keys and marks key outages retryable', async () => {
    const secondKeyId = 'http://localhost:3000/public-key/alice-rsa-2';
    const ambiguousCtx = {
      meta: {},
      call: jest.fn(async (action, params) => {
        if (action === 'keys.findPrivateKeyUri') return `${params.publicKeyUri}/private`;
        if (action === 'keys.container.get') {
          const keyId = params.resourceUri === `${KEY_ID}/private` ? KEY_ID : secondKeyId;
          return rsaPrivateKey({ id: params.resourceUri, 'rdfs:seeAlso': keyId });
        }
        throw new Error(`Unexpected action: ${action}`);
      })
    };
    await expect(
      makeService()._resolveActivityPubSigningMaterial(
        ambiguousCtx,
        ACTOR,
        localAccount(),
        localActor({ publicKey: [{ id: KEY_ID }, { id: secondKeyId }] })
      )
    ).resolves.toMatchObject({ ok: false, error: 'KEY_UNAVAILABLE', retryable: false });

    const outageCtx = {
      meta: {},
      call: jest.fn(async () => { throw new Error('key service unavailable'); })
    };
    await expect(
      makeService()._resolveActivityPubSigningMaterial(outageCtx, ACTOR, localAccount(), localActor())
    ).resolves.toEqual({
      ok: false,
      error: 'KEY_UNAVAILABLE',
      message: 'RSA key lookup unavailable',
      retryable: true
    });
  });

  test('does not create signing material and rejects an actor with no attached key', async () => {
    const ctx = { meta: {}, call: jest.fn() };
    await expect(
      makeService()._resolveActivityPubSigningMaterial(
        ctx,
        ACTOR,
        localAccount(),
        localActor({ publicKey: undefined })
      )
    ).resolves.toEqual({
      ok: false,
      error: 'KEY_UNAVAILABLE',
      message: 'no RSA signing key is attached to the actor',
      retryable: false
    });
    expect(ctx.call).not.toHaveBeenCalled();
  });

  test('batch signing traverses only the deployed account, actor and key authority chain', async () => {
    const request = {
      requestId: 'req-1',
      actorUri: ACTOR,
      method: 'POST',
      profile: 'ap_post_v1',
      target: { host: 'remote.example', path: '/inbox' },
      body: { bytes: '{}', encoding: 'utf8' },
      digest: { mode: 'server_compute' }
    };
    const ctx = {
      params: { requests: [request] },
      meta: { $headers: { authorization: 'Bearer ignored-by-test' } },
      call: jest.fn(async action => {
        if (action === 'auth.account.findByWebId') return localAccount();
        if (action === 'activitypub.actor.get') return localActor();
        if (action === 'keys.findPrivateKeyUri') return rsaPrivateKey().id;
        if (action === 'keys.container.get') return rsaPrivateKey();
        throw new Error(`Unexpected action: ${action}`);
      })
    };
    const signOne = jest.fn(async (actorUri, keyId, privateKeyPem, item) => ({
      requestId: item.requestId,
      ok: true,
      actorUri,
      keyId,
      privateKeyPem
    }));
    const result = await signingSchema.actions.signHttpRequestsBatch.handler.call(
      makeService({ _auth: jest.fn(), _signOne: signOne }),
      ctx
    );
    expect(result.results).toEqual([{
      requestId: 'req-1',
      ok: true,
      actorUri: ACTOR,
      keyId: KEY_ID,
      privateKeyPem: 'PRIVATE'
    }]);
    expect(signOne).toHaveBeenCalledWith(ACTOR, KEY_ID, 'PRIVATE', request);
    expect(ctx.call.mock.calls.map(([name]) => name)).toEqual([
      'auth.account.findByWebId',
      'activitypub.actor.get',
      'keys.findPrivateKeyUri',
      'keys.container.get'
    ]);
    expect(ctx.call.mock.calls.some(([name]) => name.startsWith('actors.'))).toBe(false);
    expect(ctx.call.mock.calls.some(([name]) => name === 'ldp.remote.isRemote')).toBe(false);
    expect(ctx.call.mock.calls.some(([name]) => name === 'activitypub.actor.isLocal')).toBe(false);
  });
});
