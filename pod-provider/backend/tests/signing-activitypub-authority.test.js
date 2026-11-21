'use strict';

const signingSchema = require('../services/signing.service');

const ACTOR = 'http://localhost:3000/alice';
const KEY_ID = 'http://localhost:3000/public-key/alice-rsa';
const RSA_KEY_TYPE = 'https://www.w3.org/ns/auth/rsa#RSAKey';

function makeService(overrides = {}) {
  return {
    settings: signingSchema.settings,
    ...signingSchema.methods,
    ...overrides
  };
}

function localAccount(overrides = {}) {
  return {
    username: 'alice',
    webId: ACTOR,
    ...overrides
  };
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
    ['person account', localAccount(), localActor()],
    ['group account', localAccount({ group: true }), localActor({ type: 'Group' })]
  ])('accepts an exact local %s only after account and actor proof', async (_label, account, actor) => {
    const ctx = {
      call: jest.fn(async (action, params) => {
        if (action === 'auth.account.findByWebId') {
          expect(params).toEqual({ webId: ACTOR });
          return account;
        }
        if (action === 'activitypub.actor.get') {
          expect(params).toEqual({ actorUri: ACTOR, webId: 'system' });
          return actor;
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

  test('rejects a remote actor before actor lookup', async () => {
    const ctx = {
      call: jest.fn(async action => {
        if (action === 'auth.account.findByWebId') return null;
        throw new Error(`Unexpected action: ${action}`);
      })
    };

    const result = await makeService()._validateLocalActor(ctx, 'https://remote.example/users/alice');

    expect(result).toMatchObject({
      ok: false,
      error: 'ACTOR_NOT_LOCAL',
      retryable: false
    });
    expect(ctx.call).toHaveBeenCalledTimes(1);
  });

  test('rejects a same-host URL that is not an actual local account', async () => {
    const ctx = {
      call: jest.fn(async action => {
        if (action === 'auth.account.findByWebId') return null;
        throw new Error(`Unexpected action: ${action}`);
      })
    };

    const result = await makeService()._validateLocalActor(ctx, 'http://localhost:3000/not-a-user');

    expect(result).toMatchObject({
      ok: false,
      error: 'ACTOR_NOT_LOCAL',
      retryable: false
    });
  });

  test('fails closed and retryable when local account verification is unavailable', async () => {
    const ctx = {
      call: jest.fn(async () => {
        throw new Error('database unavailable');
      })
    };

    const result = await makeService()._validateLocalActor(ctx, ACTOR);

    expect(result).toEqual({
      ok: false,
      error: 'ACTOR_NOT_LOCAL',
      message: 'local account verification unavailable',
      retryable: true
    });
  });

  test('rejects an account whose resolved actor does not exactly match actorUri', async () => {
    const ctx = {
      call: jest.fn(async action => {
        if (action === 'auth.account.findByWebId') return localAccount();
        if (action === 'activitypub.actor.get') {
          return localActor({ id: 'http://localhost:3000/bob' });
        }
        throw new Error(`Unexpected action: ${action}`);
      })
    };

    const result = await makeService()._validateLocalActor(ctx, ACTOR);

    expect(result).toMatchObject({
      ok: false,
      error: 'ACTOR_NOT_LOCAL',
      retryable: false
    });
  });

  test('rejects non-HTTP actor identifiers and URL credentials before any lookup', async () => {
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

  test('resolves the exact actor-attached RSA key with dataset context', async () => {
    const ctx = {
      meta: { traceId: 'trace-1' },
      call: jest.fn(async (action, params, options) => {
        expect(action).toBe('keys.getOrCreateWebIdKeys');
        expect(params).toEqual({ webId: ACTOR, keyType: RSA_KEY_TYPE });
        expect(options).toEqual({
          meta: {
            traceId: 'trace-1',
            dataset: 'alice',
            webId: ACTOR
          }
        });
        return [rsaPrivateKey()];
      })
    };

    const result = await makeService()._resolveActivityPubSigningMaterial(
      ctx,
      ACTOR,
      localAccount(),
      localActor()
    );

    expect(result).toEqual({
      ok: true,
      keyId: KEY_ID,
      privateKeyPem: 'PRIVATE'
    });
  });

  test.each([
    ['wrong owner', rsaPrivateKey({ owner: 'http://localhost:3000/bob' })],
    ['wrong controller', rsaPrivateKey({ controller: 'http://localhost:3000/bob' })],
    ['missing private key', rsaPrivateKey({ privateKeyPem: undefined })],
    ['unattached public key', rsaPrivateKey({ 'rdfs:seeAlso': 'http://localhost:3000/public-key/other' })],
    ['non-HTTP public key', rsaPrivateKey({ 'rdfs:seeAlso': 'did:key:zBad' })]
  ])('rejects signing material with %s', async (_label, key) => {
    const ctx = {
      meta: {},
      call: jest.fn(async () => [key])
    };

    const result = await makeService()._resolveActivityPubSigningMaterial(
      ctx,
      ACTOR,
      localAccount(),
      localActor()
    );

    expect(result).toMatchObject({
      ok: false,
      error: 'KEY_UNAVAILABLE',
      retryable: false
    });
  });

  test('rejects ambiguous actor-controlled RSA keys', async () => {
    const ctx = {
      meta: {},
      call: jest.fn(async () => [
        rsaPrivateKey(),
        rsaPrivateKey({ id: 'http://localhost:3000/alice/data/key/private-rsa-2' })
      ])
    };

    const result = await makeService()._resolveActivityPubSigningMaterial(
      ctx,
      ACTOR,
      localAccount(),
      localActor()
    );

    expect(result).toEqual({
      ok: false,
      error: 'KEY_UNAVAILABLE',
      message: 'multiple actor-controlled RSA signing keys are attached to the actor',
      retryable: false
    });
  });

  test('marks key-service outages retryable without weakening authority', async () => {
    const ctx = {
      meta: {},
      call: jest.fn(async () => {
        throw new Error('key service unavailable');
      })
    };

    const result = await makeService()._resolveActivityPubSigningMaterial(
      ctx,
      ACTOR,
      localAccount(),
      localActor()
    );

    expect(result).toEqual({
      ok: false,
      error: 'KEY_UNAVAILABLE',
      message: 'RSA key lookup unavailable',
      retryable: true
    });
  });

  test('batch signing uses only deployed ActivityPods/SemApps authority services', async () => {
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
        if (action === 'keys.getOrCreateWebIdKeys') return [rsaPrivateKey()];
        throw new Error(`Unexpected action: ${action}`);
      })
    };

    const signOne = jest.fn(async (_ctx, actorUri, keyId, privateKeyPem, item) => ({
      requestId: item.requestId,
      ok: true,
      actorUri,
      keyId,
      privateKeyPem
    }));
    const service = makeService({ _auth: jest.fn(), _signOne: signOne });

    const result = await signingSchema.actions.signHttpRequestsBatch.handler.call(service, ctx);

    expect(result.results).toEqual([
      {
        requestId: 'req-1',
        ok: true,
        actorUri: ACTOR,
        keyId: KEY_ID,
        privateKeyPem: 'PRIVATE'
      }
    ]);
    expect(signOne).toHaveBeenCalledTimes(1);
    expect(ctx.call.mock.calls.map(([name]) => name)).toEqual([
      'auth.account.findByWebId',
      'activitypub.actor.get',
      'keys.getOrCreateWebIdKeys'
    ]);
    expect(ctx.call.mock.calls.some(([name]) => name.startsWith('actors.'))).toBe(false);
    expect(ctx.call.mock.calls.some(([name]) => name === 'ldp.remote.isRemote')).toBe(false);
    expect(ctx.call.mock.calls.some(([name]) => name === 'activitypub.actor.isLocal')).toBe(false);
  });
});
