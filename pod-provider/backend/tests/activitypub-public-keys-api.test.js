'use strict';

const crypto = require('crypto');
const service = require('../services/core/activitypub-public-keys.service');
const { acceptsActivityPubRepresentation } = service;

const ACTOR = 'https://activitypods.example/alice';
const KEY_ID = `${ACTOR}/keys/main`;
const SIGNING_KEY_ID = `${ACTOR}#main-key`;
const { publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const PUBLIC_KEY_PEM = publicKey.export({ type: 'spki', format: 'pem' });

function context({ publicKey = {}, rows } = {}) {
  return {
    params: { username: 'alice' },
    meta: {},
    call: jest.fn(async (action, params, options) => {
      if (action === 'auth.account.findByUsername') {
        expect(params).toEqual({ username: 'alice' });
        return { username: 'alice', webId: ACTOR };
      }
      if (action === 'activitypub.actor.get') {
        expect(params).toEqual({ actorUri: ACTOR, webId: 'system' });
        expect(options).toEqual({ meta: { dataset: 'alice', webId: 'system' } });
        return {
          id: ACTOR,
          publicKey: {
            id: KEY_ID,
            type: 'CryptographicKey',
            owner: ACTOR,
            controller: ACTOR,
            publicKeyPem: PUBLIC_KEY_PEM,
            ...publicKey
          }
        };
      }
      if (action === 'triplestore.query') {
        expect(params).toEqual(expect.objectContaining({
          accept: 'application/sparql-results+json',
          dataset: 'alice',
          webId: 'system'
        }));
        expect(params.query).toContain(`<${KEY_ID}> sec:owner ?owner`);
        return rows || [{
          owner: { value: ACTOR },
          controller: { value: ACTOR },
          publicKeyPem: { value: PUBLIC_KEY_PEM }
        }];
      }
      throw new Error(`Unexpected call ${action}`);
    })
  };
}

function actorContext({ actor = {}, keyDocument = {} } = {}) {
  return {
    params: { username: 'alice' },
    meta: {},
    call: jest.fn(async (action, params, options) => {
      if (action === 'auth.account.findByUsername') {
        expect(params).toEqual({ username: 'alice' });
        return { username: 'alice', webId: ACTOR };
      }
      if (action === 'activitypub.actor.get') {
        expect(params).toEqual({ actorUri: ACTOR, webId: 'anon' });
        expect(options).toEqual({ meta: { dataset: 'alice', webId: 'anon' } });
        return {
          '@context': 'https://www.w3.org/ns/activitystreams',
          id: ACTOR,
          type: 'Person',
          inbox: `${ACTOR}/inbox`,
          publicKey: KEY_ID,
          ...actor
        };
      }
      if (action === 'activitypub-public-keys.get') {
        expect(params).toEqual({ username: 'alice' });
        return {
          '@context': ['https://www.w3.org/ns/activitystreams', 'https://w3id.org/security/v1'],
          id: KEY_ID,
          type: 'CryptographicKey',
          owner: ACTOR,
          controller: ACTOR,
          publicKeyPem: PUBLIC_KEY_PEM,
          ...keyDocument
        };
      }
      throw new Error(`Unexpected call ${action}`);
    })
  };
}

describe('public ActivityPub key document', () => {
  test('registers an explicitly unauthenticated read-only key route', async () => {
    const broker = { call: jest.fn() };
    await service.started.call({ broker });
    expect(broker.call).toHaveBeenCalledWith(
      'api.addRoute',
      expect.objectContaining({
        route: expect.objectContaining({
          path: '/:username([^/.][^/]+)',
          authentication: false,
          authorization: false,
          onBeforeCall: expect.any(Function),
          aliases: { 'GET /': 'activitypub-public-keys.getActor' }
        }),
        toBottom: false
      })
    );
    expect(broker.call).toHaveBeenCalledWith(
      'api.addRoute',
      expect.objectContaining({
        route: expect.objectContaining({
          path: '/:username([^/.][^/]+)/keys/main',
          authentication: false,
          authorization: false,
          onBeforeCall: expect.any(Function),
          aliases: { 'GET /': 'activitypub-public-keys.get' }
        }),
        toBottom: false
      })
    );
    expect(broker.call).toHaveBeenCalledTimes(2);
  });

  test('selects the reduced actor only for explicit ActivityPub media types', () => {
    expect(acceptsActivityPubRepresentation('application/activity+json')).toBe(true);
    expect(acceptsActivityPubRepresentation('application/ld+json; profile="https://www.w3.org/ns/activitystreams"')).toBe(true);
    expect(acceptsActivityPubRepresentation('text/turtle, application/activity+json;q=0')).toBe(false);
    expect(acceptsActivityPubRepresentation('application/activity+json; q = 0.000')).toBe(false);
    expect(acceptsActivityPubRepresentation('application/activity+jsonx')).toBe(false);
    expect(acceptsActivityPubRepresentation('application/activity+json;q=bogus')).toBe(false);
    expect(acceptsActivityPubRepresentation('application/ld+json')).toBe(false);
    expect(acceptsActivityPubRepresentation('text/turtle')).toBe(false);
    expect(acceptsActivityPubRepresentation('*/*')).toBe(false);
    expect(acceptsActivityPubRepresentation(undefined)).toBe(false);
  });

  test('records HTTP content negotiation without trusting route parameters', async () => {
    const broker = { call: jest.fn() };
    await service.started.call({ broker });
    const actorRoute = broker.call.mock.calls[0][1].route;
    const ctx = { meta: {} };
    actorRoute.onBeforeCall(ctx, actorRoute, { headers: { accept: 'text/turtle' } });
    expect(ctx.meta).toEqual({
      activityPubActorRequest: false,
      activityPubActorAccept: 'text/turtle'
    });
  });

  test('delegates non-ActivityPub requests to the established WebID LDP handler', async () => {
    const ctx = {
      params: { username: 'alice' },
      meta: {
        activityPubActorRequest: false,
        activityPubActorAccept: 'text/turtle',
        headers: { prefer: 'return=representation' }
      },
      call: jest.fn().mockResolvedValue('webid turtle')
    };

    await expect(service.actions.getActor.handler(ctx)).resolves.toBe('webid turtle');
    expect(ctx.call).toHaveBeenCalledWith(
      'ldp.api.get',
      { username: 'alice', slugParts: [] },
      {
        meta: expect.objectContaining({
          activityPubActorRequest: false,
          activityPubActorAccept: 'text/turtle',
          headers: { prefer: 'return=representation', accept: 'text/turtle' },
          originalHeaders: { accept: 'text/turtle' }
        })
      }
    );
  });

  test('preserves RDF negotiation on the direct key URI', async () => {
    const broker = { call: jest.fn() };
    await service.started.call({ broker });
    const keyRoute = broker.call.mock.calls[1][1].route;
    const ctx = {
      params: { username: 'alice' },
      meta: { headers: { prefer: 'return=representation' } },
      call: jest.fn().mockResolvedValue('key turtle')
    };
    keyRoute.onBeforeCall(ctx, keyRoute, { headers: { accept: 'text/turtle' } });

    await expect(service.actions.get.handler(ctx)).resolves.toBe('key turtle');
    expect(ctx.call).toHaveBeenCalledWith(
      'ldp.api.get',
      { username: 'alice', slugParts: ['keys', 'main'] },
      {
        meta: expect.objectContaining({
          activityPubKeyRequest: false,
          activityPubKeyAccept: 'text/turtle',
          headers: { prefer: 'return=representation', accept: 'text/turtle' },
          originalHeaders: { accept: 'text/turtle' }
        })
      }
    );
  });

  test('serves the anonymous actor representation with only the validated embedded RSA key', async () => {
    const ctx = actorContext();
    const result = await service.actions.getActor.handler(ctx);

    expect(result).toEqual({
      '@context': ['https://www.w3.org/ns/activitystreams', 'https://w3id.org/security/v1'],
      id: ACTOR,
      type: 'Person',
      preferredUsername: 'alice',
      name: 'alice',
      inbox: `${ACTOR}/inbox`,
      publicKey: {
        id: SIGNING_KEY_ID,
        type: 'CryptographicKey',
        owner: ACTOR,
        controller: ACTOR,
        publicKeyPem: PUBLIC_KEY_PEM
      }
    });
    expect(ctx.meta.$responseType).toBe('application/activity+json');
    expect(ctx.meta.$responseHeaders).toEqual({ 'Cache-Control': 'no-store' });
  });

  test('normalizes an expanded JSON-LD actor to an Akkoma-compatible standard actor document', async () => {
    const ctx = actorContext({
      actor: {
        id: undefined,
        type: undefined,
        '@id': ACTOR,
        '@type': ['https://www.w3.org/ns/activitystreams#Person']
      }
    });
    const result = await service.actions.getActor.handler(ctx);

    expect(result.id).toBe(ACTOR);
    expect(result.type).toBe('Person');
    expect(result.preferredUsername).toBe('alice');
    expect(result.name).toBe('alice');
    expect(result.inbox).toBe(`${ACTOR}/inbox`);
    expect(result).not.toHaveProperty('@id');
    expect(result).not.toHaveProperty('@type');
  });

  test('does not publish provider-local JSON-LD contexts to remote actor consumers', async () => {
    const result = await service.actions.getActor.handler(actorContext({
      actor: {
        '@context': [
          'https://www.w3.org/ns/activitystreams',
          'https://activitypods.example/.well-known/context.jsonld'
        ]
      }
    }));

    expect(result['@context']).toEqual([
      'https://www.w3.org/ns/activitystreams',
      'https://w3id.org/security/v1'
    ]);
    expect(result['@context']).not.toContain('https://activitypods.example/.well-known/context.jsonld');
  });

  test('publishes an allowlisted actor document instead of leaking stored provider fields', async () => {
    const result = await service.actions.getActor.handler(actorContext({
      actor: {
        summary: 'stored profile field',
        outbox: 'https://mallory.example/outbox',
        providerInternalState: { enabled: true },
        'https://activitypods.example/ns#privateSetting': 'private'
      }
    }));

    expect(Object.keys(result).sort()).toEqual([
      '@context',
      'id',
      'inbox',
      'name',
      'preferredUsername',
      'publicKey',
      'type'
    ]);
    expect(result).not.toHaveProperty('summary');
    expect(result).not.toHaveProperty('outbox');
    expect(result).not.toHaveProperty('providerInternalState');
    expect(result).not.toHaveProperty('https://activitypods.example/ns#privateSetting');
  });

  test('publishes only validated same-origin standard actor collections', async () => {
    const result = await service.actions.getActor.handler(actorContext({
      actor: {
        outbox: `${ACTOR}/outbox`,
        followers: { id: `${ACTOR}/followers` },
        following: { '@id': `${ACTOR}/following` }
      }
    }));

    expect(result).toMatchObject({
      outbox: `${ACTOR}/outbox`,
      followers: `${ACTOR}/followers`,
      following: `${ACTOR}/following`
    });
  });

  test('preserves an existing non-empty local actor display name', async () => {
    const result = await service.actions.getActor.handler(actorContext({ actor: { name: 'Alice Example' } }));
    expect(result.name).toBe('Alice Example');
  });

  test.each([
    { actor: { privateKeyPem: 'private' } },
    { actor: { accessToken: 'token' } },
    { actor: { type: 'Document' } },
    { actor: { inbox: 'https://mallory.example/inbox' } },
    { keyDocument: { owner: 'https://activitypods.example/mallory' } },
    { keyDocument: { controller: 'https://activitypods.example/mallory' } },
    { keyDocument: { id: `${ACTOR}/keys/other` } },
    { keyDocument: { publicKeyPem: 'not a public key' } }
  ])('fails closed instead of serving unsafe actor/key material (%p)', async fixture => {
    await expect(service.actions.getActor.handler(actorContext(fixture))).rejects.toMatchObject({ code: 404 });
  });

  test('returns only the exact actor-owned RSA public verification method in direct and compatible embedded form', async () => {
    const ctx = context();
    const result = await service.actions.get.handler(ctx);
    expect(result).toEqual({
      '@context': ['https://www.w3.org/ns/activitystreams', 'https://w3id.org/security/v1'],
      id: KEY_ID,
      type: 'CryptographicKey',
      owner: ACTOR,
      controller: ACTOR,
      publicKeyPem: PUBLIC_KEY_PEM,
      publicKey: {
        id: KEY_ID,
        type: 'CryptographicKey',
        owner: ACTOR,
        controller: ACTOR,
        publicKeyPem: PUBLIC_KEY_PEM
      }
    });
    expect(ctx.meta.$responseType).toBe('application/activity+json');
    expect(ctx.meta.$responseHeaders).toEqual({ 'Cache-Control': 'no-store' });
  });

  test.each([
    { publicKey: { id: `${ACTOR}/keys/other` } },
    { rows: [{ owner: { value: 'https://activitypods.example/mallory' }, controller: { value: ACTOR }, publicKeyPem: { value: PUBLIC_KEY_PEM } }] },
    { rows: [{ owner: { value: ACTOR }, controller: { value: 'https://activitypods.example/mallory' }, publicKeyPem: { value: PUBLIC_KEY_PEM } }] },
    { rows: [{ owner: { value: ACTOR }, controller: { value: ACTOR }, publicKeyPem: { value: 'not a public key' } }] },
    { rows: [] },
    { rows: [{ owner: { value: ACTOR }, controller: { value: ACTOR }, publicKeyPem: { value: PUBLIC_KEY_PEM } }, { owner: { value: ACTOR }, controller: { value: ACTOR }, publicKeyPem: { value: PUBLIC_KEY_PEM } }] }
  ])('returns no key document for mismatched or invalid material (%p)', async fixture => {
    await expect(service.actions.get.handler(context(fixture))).rejects.toMatchObject({ code: 404 });
  });
});
