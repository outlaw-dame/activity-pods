'use strict';

const crypto = require('crypto');
const service = require('../services/core/activitypub-public-keys.service');

const ACTOR = 'https://activitypods.example/alice';
const KEY_ID = `${ACTOR}/keys/main`;
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
          aliases: { 'GET /': 'activitypub-public-keys.get' }
        }),
        toBottom: false
      })
    );
    expect(broker.call).toHaveBeenCalledTimes(2);
  });

  test('serves the anonymous actor representation with only the validated embedded RSA key', async () => {
    const ctx = actorContext();
    const result = await service.actions.getActor.handler(ctx);

    expect(result).toEqual({
      '@context': ['https://www.w3.org/ns/activitystreams', 'https://w3id.org/security/v1'],
      id: ACTOR,
      type: 'Person',
      preferredUsername: 'alice',
      inbox: `${ACTOR}/inbox`,
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
    expect(result.inbox).toBe(`${ACTOR}/inbox`);
    expect(result).not.toHaveProperty('@id');
    expect(result).not.toHaveProperty('@type');
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

  test('returns only the exact actor-owned RSA public verification method', async () => {
    const ctx = context();
    const result = await service.actions.get.handler(ctx);
    expect(result).toEqual({
      '@context': ['https://www.w3.org/ns/activitystreams', 'https://w3id.org/security/v1'],
      id: KEY_ID,
      type: 'CryptographicKey',
      owner: ACTOR,
      controller: ACTOR,
      publicKeyPem: PUBLIC_KEY_PEM
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
