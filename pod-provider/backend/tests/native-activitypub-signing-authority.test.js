'use strict';

const ORIGINAL_TOKEN = process.env.ACTIVITYPODS_TOKEN;

function loadSignatureSchema(token) {
  jest.resetModules();
  if (token === undefined) delete process.env.ACTIVITYPODS_TOKEN;
  else process.env.ACTIVITYPODS_TOKEN = token;
  return require('../utils/native-activitypub-signing');
}

afterAll(() => {
  if (ORIGINAL_TOKEN === undefined) delete process.env.ACTIVITYPODS_TOKEN;
  else process.env.ACTIVITYPODS_TOKEN = ORIGINAL_TOKEN;
});

describe('native ActivityPub signing authority adapter', () => {
  test('routes POST signing through the hardened signer and returns its exact key headers', async () => {
    const token = 'a'.repeat(64);
    const schema = loadSignatureSchema(token);
    const ctx = {
      params: {
        actorUri: 'https://activitypods/alice',
        method: 'POST',
        url: 'https://akkoma/users/bob/inbox?shared=true',
        body: '{"type":"Follow"}'
      },
      meta: { traceId: 'trace-1' },
      call: jest.fn(async (_action, params) => ({
        results: [{
          requestId: params.requests[0].requestId,
          ok: true,
          outHeaders: {
            Date: 'Thu, 20 Aug 2026 20:00:00 GMT',
            Digest: 'SHA-256=digest',
            Signature: 'keyId="https://activitypods/alice/data/public-key",signature="value"'
          }
        }]
      }))
    };

    await expect(schema.generateAuthorityBoundSignatureHeaders(ctx)).resolves.toEqual({
      Date: 'Thu, 20 Aug 2026 20:00:00 GMT',
      Digest: 'SHA-256=digest',
      Signature: 'keyId="https://activitypods/alice/data/public-key",signature="value"'
    });
    expect(ctx.call).toHaveBeenCalledWith(
      'signing.signHttpRequestsBatch',
      {
        requests: [expect.objectContaining({
          actorUri: 'https://activitypods/alice',
          method: 'POST',
          profile: 'ap_post_v1',
          target: { host: 'akkoma', path: '/users/bob/inbox', query: '?shared=true' },
          body: { bytes: '{"type":"Follow"}', encoding: 'utf8' },
          digest: { mode: 'server_compute' }
        })]
      },
      {
        meta: {
          traceId: 'trace-1',
          $headers: { authorization: `Bearer ${token}` }
        }
      }
    );
  });

  test('fails closed before broker access when the dedicated token is absent', async () => {
    const schema = loadSignatureSchema(undefined);
    const ctx = {
      params: {
        actorUri: 'https://activitypods/alice',
        method: 'POST',
        url: 'https://remote.example/inbox',
        body: '{}'
      },
      call: jest.fn()
    };

    await expect(schema.generateAuthorityBoundSignatureHeaders(ctx)).rejects.toMatchObject({
      code: 503,
      type: 'SIGNING_AUTH_NOT_CONFIGURED'
    });
    expect(ctx.call).not.toHaveBeenCalled();
  });

  test.each([
    [{ method: 'DELETE', url: 'https://remote.example/inbox', actorUri: 'https://activitypods/alice' }, 'INVALID_INPUT'],
    [{ method: 'POST', url: 'https://user:secret@remote.example/inbox', actorUri: 'https://activitypods/alice', body: '{}' }, 'INVALID_INPUT'],
    [{ method: 'POST', url: 'https://remote.example/inbox', actorUri: 'https://activitypods/alice' }, 'INVALID_INPUT']
  ])('rejects invalid native signing input %#', async (params, type) => {
    const schema = loadSignatureSchema('a'.repeat(64));
    try {
      schema.signingRequestFromSemApps(params);
      throw new Error('expected invalid signing input to be rejected');
    } catch (error) {
      expect(error).toMatchObject({ type });
    }
  });

  test('rejects malformed or incomplete signer responses', async () => {
    const schema = loadSignatureSchema('a'.repeat(64));
    const ctx = {
      params: {
        actorUri: 'https://activitypods/alice',
        method: 'POST',
        url: 'https://remote.example/inbox',
        body: '{}'
      },
      call: jest.fn(async (_action, params) => ({
        results: [{ requestId: params.requests[0].requestId, ok: true, outHeaders: { Date: 'date', Signature: 'sig' } }]
      }))
    };

    await expect(schema.generateAuthorityBoundSignatureHeaders(ctx)).rejects.toMatchObject({
      type: 'NATIVE_SIGNING_FAILED'
    });
  });
});
