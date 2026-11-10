const fs = require('fs');
const path = require('path');
const { Readable } = require('stream');
const {
  API_MARKER,
  MARKER,
  PATCHED_API_HASH,
  PATCHED_HASH,
  PRISTINE_API_HASH,
  sha256,
  patchApi,
  patchInbox
} = require('../scripts/patch-semapps-activitypub-inbox-actor-id');

const inboxPath = path.join(
  path.dirname(require.resolve('@semapps/activitypub/package.json')),
  'services/activitypub/subservices/inbox.js'
);
const apiPath = path.join(
  path.dirname(require.resolve('@semapps/activitypub/package.json')),
  'services/activitypub/subservices/api.js'
);
const pristineApiPath = path.join(
  __dirname,
  '../../../tests/node_modules/@semapps/activitypub/services/activitypub/subservices/api.js'
);

describe('SemApps ActivityPub inbox actor identifier compatibility patch', () => {
  test('is wired into local and container dependency installation', () => {
    const packageJson = require('../package.json');
    const dockerfile = fs.readFileSync(path.join(__dirname, '../../docker/backend.dockerfile'), 'utf8');
    expect(packageJson.scripts.postinstall).toContain('node scripts/patch-semapps-activitypub-inbox-actor-id.js');
    expect(dockerfile).toContain(
      'ADD backend/scripts/patch-semapps-activitypub-inbox-actor-id.js /app/backend/scripts/patch-semapps-activitypub-inbox-actor-id.js'
    );
  });

  test('normalizes only standard ActivityStreams entity identifiers before exact signer comparison', () => {
    const installed = fs.readFileSync(inboxPath, 'utf8');
    const result = patchInbox(installed);
    expect(result.changed).toBe(false);
    expect(result.source).toContain(MARKER);
    expect(result.source).toContain(
      'const authenticatedActorUri = ctx.meta.httpSignatureActorUri || ctx.meta.webId;'
    );
    expect(result.source).toContain('const parsedActivityActorUri = activityActorId(activity.actor);');
    expect(result.source).toContain('const directRawActivityActorUri = rawActivityActorId(ctx.meta.rawBody);');
    expect(result.source).toContain('const capturedRawActivityActorUri = activityActorId(ctx.meta.signedRawActivityActorUri);');
    expect(result.source).toContain('const rawActivityActorUri = directRawActivityActorUri || capturedRawActivityActorUri;');
    expect(result.source).toContain('parsedActivityActorUri !== rawActivityActorUri');
    expect(result.source).toContain('const activityActorUri = parsedActivityActorUri || rawActivityActorUri;');
    expect(result.source).toContain('if (activityActorUri !== authenticatedActorUri)');
    expect(result.source).toContain('Rejected ActivityPub inbox actor/signature mismatch');
    expect(result.source).toContain(
      "if (Array.isArray(value)) return value.length === 1 ? activityActorId(value[0]) : null;"
    );
    expect(result.source).toContain("if (!value || typeof value !== 'object') return null;");
    expect(result.source).toContain("if (id && atId && id !== atId) return null;");
    expect(sha256(result.source)).toBe(PATCHED_HASH);
  });

  test('captures the signed raw actor at the HTTP action boundary and propagates exact child metadata', async () => {
    const installed = fs.readFileSync(apiPath, 'utf8');
    const result = patchApi(installed);
    expect(result.changed).toBe(false);
    expect(result.source).toContain(API_MARKER);
    expect(sha256(result.source)).toBe(PATCHED_API_HASH);

    jest.resetModules();
    const api = require(apiPath);
    const ctx = {
      params: { actorSlug: 'alice', type: 'Accept' },
      meta: {
        requestUrl: '/alice/inbox',
        rawBody: JSON.stringify({ type: 'Accept', actor: 'https://remote.example/bob' }),
        httpSignatureActorUri: 'https://remote.example/bob'
      },
      call: jest.fn().mockResolvedValue(undefined)
    };
    await api.actions.inbox.call({ settings: { baseUri: 'https://local.example/' } }, ctx);
    expect(ctx.call).toHaveBeenCalledWith(
      'activitypub.inbox.post',
      { collectionUri: 'https://local.example/alice/inbox', type: 'Accept' },
      { meta: expect.objectContaining({
        rawBody: ctx.meta.rawBody,
        signedRawActivityActorUri: 'https://remote.example/bob',
        httpSignatureActorUri: 'https://remote.example/bob'
      }) }
    );
  });

  test('patches a pristine pinned API source exactly once', () => {
    const pristine = fs.readFileSync(pristineApiPath, 'utf8');
    expect(sha256(pristine)).toBe(PRISTINE_API_HASH);

    const result = patchApi(pristine);
    const occurrenceCount = needle => result.source.split(needle).length - 1;
    expect(result.changed).toBe(true);
    expect(sha256(result.source)).toBe(PATCHED_API_HASH);
    expect(occurrenceCount(API_MARKER)).toBe(1);
    expect(occurrenceCount('function normalizeActivityPubContentType(')).toBe(1);
    expect(occurrenceCount('function normalizeActivityPubAccept(')).toBe(1);
    expect(occurrenceCount('        normalizeActivityPubContentType,')).toBe(1);
    expect(occurrenceCount('        normalizeActivityPubAccept,')).toBe(1);
    expect(occurrenceCount('        negotiateAccept,')).toBe(1);
  });

  test('parses parameterized ActivityPub JSON without changing exact signed headers', async () => {
    jest.resetModules();
    const api = require(apiPath);
    const route = api.methods.getBoxesRoute.call({ settings: { podProvider: true } }, '/:username');
    const middleware = route.aliases['POST /inbox'].filter(item => typeof item === 'function');
    const body = JSON.stringify({
      '@context': 'https://www.w3.org/ns/activitystreams',
      id: 'https://remote.example/accepts/1',
      type: 'Accept',
      actor: 'https://remote.example/bob'
    });
    const req = Readable.from([Buffer.from(body)]);
    req.method = 'POST';
    req.originalUrl = '/alice/inbox';
    req.parsedUrl = '/alice/inbox';
    req.query = {};
    req.headers = {
      'content-type': 'application/ld+json; profile="https://www.w3.org/ns/activitystreams"',
      accept: 'application/ld+json; profile="https://www.w3.org/ns/activitystreams"'
    };
    req.$ctx = { meta: {} };
    req.$params = {};
    const run = fn => new Promise((resolve, reject) => {
      Promise.resolve(fn(req, {}, error => error ? reject(error) : resolve())).catch(reject);
    });
    for (const fn of middleware.slice(0, 8)) await run(fn);

    expect(req.$ctx.meta.originalHeaders['content-type']).toBe(
      'application/ld+json; profile="https://www.w3.org/ns/activitystreams"'
    );
    expect(req.$ctx.meta.headers['content-type']).toBe('application/ld+json');
    expect(req.$ctx.meta.originalHeaders.accept).toBe(
      'application/ld+json; profile="https://www.w3.org/ns/activitystreams"'
    );
    expect(req.$ctx.meta.headers.accept).toBe('application/ld+json');
    expect(req.$ctx.meta.rawBody).toBe(body);
    expect(req.$params.actor).toBe('https://remote.example/bob');
  });

  test('does not normalize unrelated JSON-LD profiles or disabled ActivityPub preferences', async () => {
    jest.resetModules();
    const api = require(apiPath);
    const route = api.methods.getBoxesRoute.call({ settings: { podProvider: true } }, '/:username');
    const middleware = route.aliases['POST /inbox'].filter(item => typeof item === 'function');
    for (const accept of [
      'application/ld+json; profile="https://example.com/not-activitystreams"',
      'application/activity+json;q=0'
    ]) {
      const req = Readable.from([Buffer.from('{}')]);
      req.method = 'POST';
      req.originalUrl = '/alice/inbox';
      req.parsedUrl = '/alice/inbox';
      req.query = {};
      req.headers = { 'content-type': 'application/activity+json', accept };
      req.$ctx = { meta: {} };
      req.$params = {};
      const run = fn => new Promise((resolve, reject) => {
        Promise.resolve(fn(req, {}, error => error ? reject(error) : resolve())).catch(reject);
      });
      await expect((async () => {
        for (const fn of middleware.slice(0, 8)) await run(fn);
      })()).rejects.toMatchObject({ code: 400, type: 'ACCEPT_NOT_SUPPORTED' });
      expect(req.$ctx.meta.originalHeaders.accept).toBe(accept);
      expect(req.$ctx.meta.headers.accept).toBe(accept);
    }
  });

  test('binds actor authorization to the authenticated principal before awaited broker calls', async () => {
    jest.resetModules();
    const inbox = require(inboxPath);
    const afterActorCheck = new Error('after actor authorization');
    const ctx = {
      params: {
        collectionUri: 'https://local.example/alice/inbox',
        actor: 'https://remote.example/bob'
      },
      meta: { webId: 'https://remote.example/bob' },
      call: jest.fn(async action => {
        if (action === 'ldp.resource.exist') {
          // Moleculer child calls share metadata and may update it while awaited.
          ctx.meta.webId = 'system';
          return true;
        }
        if (action === 'activitypub.collection.getOwner') throw afterActorCheck;
        throw new Error(`Unexpected action ${action}`);
      })
    };

    await expect(inbox.actions.post.call({ settings: { podProvider: true } }, ctx)).rejects.toBe(afterActorCheck);
    expect(ctx.call).toHaveBeenNthCalledWith(2, 'activitypub.collection.getOwner', {
      collectionUri: 'https://local.example/alice/inbox',
      collectionKey: 'inbox'
    });
  });

  test('prefers the request-scoped HTTP signature principal over mutated shared metadata', async () => {
    jest.resetModules();
    const inbox = require(inboxPath);
    const afterActorCheck = new Error('after actor authorization');
    const ctx = {
      params: {
        collectionUri: 'https://local.example/alice/inbox',
        actor: 'https://remote.example/bob'
      },
      meta: {
        webId: 'system',
        httpSignatureActorUri: 'https://remote.example/bob'
      },
      call: jest.fn(async action => {
        if (action === 'ldp.resource.exist') return true;
        if (action === 'activitypub.collection.getOwner') throw afterActorCheck;
        throw new Error(`Unexpected action ${action}`);
      })
    };

    await expect(inbox.actions.post.call({ settings: { podProvider: true } }, ctx)).rejects.toBe(afterActorCheck);
  });

  test.each([
    ['singleton string array', ['https://remote.example/bob']],
    ['singleton object array', [{ id: 'https://remote.example/bob' }]],
    ['singleton JSON-LD object array', [{ '@id': 'https://remote.example/bob' }]]
  ])('accepts the exact authenticated actor in a %s', async (_label, actor) => {
    jest.resetModules();
    const inbox = require(inboxPath);
    const afterActorCheck = new Error('after actor authorization');
    const ctx = {
      params: { collectionUri: 'https://local.example/alice/inbox', actor },
      meta: { httpSignatureActorUri: 'https://remote.example/bob', webId: 'system' },
      call: jest.fn(async action => {
        if (action === 'ldp.resource.exist') return true;
        if (action === 'activitypub.collection.getOwner') throw afterActorCheck;
        throw new Error(`Unexpected action ${action}`);
      })
    };

    await expect(inbox.actions.post.call({ settings: { podProvider: true } }, ctx)).rejects.toBe(afterActorCheck);
  });

  test('restores an exact signed raw-body actor when action middleware loses its representation', async () => {
    jest.resetModules();
    const inbox = require(inboxPath);
    const afterActorCheck = new Error('after actor authorization');
    const ctx = {
      params: { collectionUri: 'https://local.example/alice/inbox', type: 'Accept' },
      meta: {
        httpSignatureActorUri: 'https://remote.example/bob',
        webId: 'system',
        rawBody: JSON.stringify({ type: 'Accept', actor: 'https://remote.example/bob' })
      },
      call: jest.fn(async action => {
        if (action === 'ldp.resource.exist') return true;
        if (action === 'activitypub.collection.getOwner') throw afterActorCheck;
        throw new Error(`Unexpected action ${action}`);
      })
    };

    await expect(inbox.actions.post.call({ settings: { podProvider: true } }, ctx)).rejects.toBe(afterActorCheck);
  });

  test('restores the request-bound raw actor when child-action metadata drops the raw body', async () => {
    jest.resetModules();
    const inbox = require(inboxPath);
    const afterActorCheck = new Error('after actor authorization');
    const ctx = {
      params: { collectionUri: 'https://local.example/alice/inbox', type: 'Accept' },
      meta: {
        httpSignatureActorUri: 'https://remote.example/bob',
        webId: 'system',
        signedRawActivityActorUri: 'https://remote.example/bob'
      },
      call: jest.fn(async action => {
        if (action === 'ldp.resource.exist') return true;
        if (action === 'activitypub.collection.getOwner') throw afterActorCheck;
        throw new Error(`Unexpected action ${action}`);
      })
    };

    await expect(inbox.actions.post.call({ settings: { podProvider: true } }, ctx)).rejects.toBe(afterActorCheck);
  });

  test('rejects disagreement between direct raw bytes and the request-bound raw actor snapshot', async () => {
    jest.resetModules();
    const inbox = require(inboxPath);
    const logger = { warn: jest.fn() };
    const ctx = {
      params: { collectionUri: 'https://local.example/alice/inbox', type: 'Accept' },
      meta: {
        httpSignatureActorUri: 'https://remote.example/bob',
        signedRawActivityActorUri: 'https://remote.example/bob',
        rawBody: JSON.stringify({ type: 'Accept', actor: 'https://remote.example/mallory' })
      },
      call: jest.fn().mockResolvedValue(true)
    };
    await expect(inbox.actions.post.call({ settings: { podProvider: true }, logger }, ctx)).rejects.toMatchObject({
      type: 'INVALID_ACTOR'
    });
    expect(logger.warn).toHaveBeenCalledWith('Rejected ActivityPub inbox raw actor metadata mismatch', {
      authenticatedActorUri: 'https://remote.example/bob',
      directRawActivityActorUri: 'https://remote.example/mallory',
      capturedRawActivityActorUri: 'https://remote.example/bob'
    });
  });

  test('rejects when the action actor conflicts with the exact signed raw-body actor', async () => {
    jest.resetModules();
    const inbox = require(inboxPath);
    const logger = { warn: jest.fn() };
    const ctx = {
      params: {
        collectionUri: 'https://local.example/alice/inbox',
        actor: 'https://remote.example/bob'
      },
      meta: {
        httpSignatureActorUri: 'https://remote.example/bob',
        rawBody: JSON.stringify({ type: 'Accept', actor: 'https://remote.example/mallory' })
      },
      call: jest.fn().mockResolvedValue(true)
    };

    await expect(inbox.actions.post.call({ settings: { podProvider: true }, logger }, ctx)).rejects.toMatchObject({
      type: 'INVALID_ACTOR'
    });
    expect(ctx.call).toHaveBeenCalledTimes(1);
    expect(logger.warn).toHaveBeenCalledWith('Rejected ActivityPub inbox raw/action actor mismatch', {
      authenticatedActorUri: 'https://remote.example/bob',
      parsedActivityActorUri: 'https://remote.example/bob',
      rawActivityActorUri: 'https://remote.example/mallory'
    });
  });

  test.each([
    ['empty actor array', []],
    ['multi-actor array', ['https://remote.example/bob', 'https://remote.example/mallory']],
    ['conflicting singleton object', [{ id: 'https://remote.example/bob', '@id': 'https://remote.example/mallory' }]]
  ])('rejects a %s', async (_label, actor) => {
    jest.resetModules();
    const inbox = require(inboxPath);
    const ctx = {
      params: { collectionUri: 'https://local.example/alice/inbox', actor },
      meta: { httpSignatureActorUri: 'https://remote.example/bob', webId: 'system' },
      call: jest.fn().mockResolvedValue(true)
    };
    await expect(
      inbox.actions.post.call({ settings: { podProvider: true }, logger: { warn: jest.fn() } }, ctx)
    ).rejects.toMatchObject({ type: 'INVALID_ACTOR' });
    expect(ctx.call).toHaveBeenCalledTimes(1);
  });

  test('still rejects an activity actor that differs from the captured principal', async () => {
    jest.resetModules();
    const inbox = require(inboxPath);
    const ctx = {
      params: {
        collectionUri: 'https://local.example/alice/inbox',
        actor: 'https://remote.example/mallory'
      },
      meta: { webId: 'https://remote.example/bob' },
      call: jest.fn(async action => {
        if (action !== 'ldp.resource.exist') throw new Error(`Unexpected action ${action}`);
        ctx.meta.webId = 'https://remote.example/mallory';
        return true;
      })
    };

    await expect(
      inbox.actions.post.call({ settings: { podProvider: true }, logger: { warn: jest.fn() } }, ctx)
    ).rejects.toMatchObject({
      type: 'INVALID_ACTOR'
    });
    expect(ctx.call).toHaveBeenCalledTimes(1);
  });

  test('does not fall back to a mutated webId when a verified signature principal is present', async () => {
    jest.resetModules();
    const inbox = require(inboxPath);
    const ctx = {
      params: {
        collectionUri: 'https://local.example/alice/inbox',
        actor: 'https://remote.example/mallory'
      },
      meta: {
        webId: 'https://remote.example/mallory',
        httpSignatureActorUri: 'https://remote.example/bob'
      },
      call: jest.fn().mockResolvedValue(true)
    };

    const logger = { warn: jest.fn() };
    await expect(inbox.actions.post.call({ settings: { podProvider: true }, logger }, ctx)).rejects.toMatchObject({
      type: 'INVALID_ACTOR'
    });
    expect(ctx.call).toHaveBeenCalledTimes(1);
    expect(logger.warn).toHaveBeenCalledWith('Rejected ActivityPub inbox actor/signature mismatch', {
      authenticatedActorUri: 'https://remote.example/bob',
      activityActorUri: 'https://remote.example/mallory'
    });
  });
});
