jest.mock('../mixins/websocket', () => ({}));
jest.mock('../config/config', () => ({
  BASE_URL: 'https://local.example',
  FRONTEND_URL: 'https://app.local.example',
  PORT: 3000
}));

const apiService = require('../services/api');

describe('API HTTP signature principal propagation', () => {
  const request = headers => ({ headers, originalUrl: '/alice/inbox', method: 'POST' });

  test.each(['authenticate', 'authorize'])('%s preserves a verified signer in dedicated request metadata', async method => {
    const ctx = {
      meta: { httpSignatureActorUri: 'https://stale.example/actor' },
      call: jest.fn().mockResolvedValue({ isValid: true, actorUri: 'https://remote.example/alice' })
    };

    await apiService.methods[method](ctx, {}, request({ signature: 'keyId="remote"' }), {});

    expect(ctx.meta).toMatchObject({
      webId: 'https://remote.example/alice',
      httpSignatureActorUri: 'https://remote.example/alice'
    });
  });

  test('clears a stale signer before rejecting a failed signature', async () => {
    const ctx = {
      meta: { httpSignatureActorUri: 'https://stale.example/actor' },
      call: jest.fn().mockResolvedValue({ isValid: false })
    };

    await expect(
      apiService.methods.authenticate(ctx, {}, request({ signature: 'keyId="invalid"' }), {})
    ).rejects.toMatchObject({ code: 401 });
    expect(ctx.meta).toEqual({ webId: 'anon' });
  });

  test('clears a stale signer for an unsigned request', async () => {
    const ctx = { meta: { httpSignatureActorUri: 'https://stale.example/actor' }, call: jest.fn() };

    await apiService.methods.authenticate(ctx, {}, request({}), {});

    expect(ctx.meta).toEqual({ webId: 'anon' });
    expect(ctx.call).not.toHaveBeenCalled();
  });
});
