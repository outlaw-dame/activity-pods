'use strict';

const mockValues = new Map();

jest.mock('ioredis', () => {
  return class MockRedis {
    constructor() {
      this.status = 'ready';
    }

    async connect() {
      this.status = 'ready';
    }

    async set(key, value, px, ttl, nx) {
      expect(px).toBe('PX');
      expect(nx).toBe('NX');
      expect(ttl).toBeGreaterThanOrEqual(30_000);
      if (mockValues.has(key)) return null;
      mockValues.set(key, value);
      return 'OK';
    }

    async eval(script, keyCount, key, token) {
      expect(script).toContain("redis.call('GET', KEYS[1]) == ARGV[1]");
      expect(keyCount).toBe(1);
      if (mockValues.get(key) !== token) return 0;
      mockValues.delete(key);
      return 1;
    }

    async quit() {
      this.status = 'end';
    }

    disconnect() {
      this.status = 'end';
    }
  };
});

const AtprotoProvisioningReservationMiddleware = require('../middlewares/atproto-provisioning-reservation');

describe('ATProto provisioning reservation middleware', () => {
  beforeEach(() => mockValues.clear());

  test('blocks a concurrent same-account action before the second handler runs', async () => {
    const middleware = AtprotoProvisioningReservationMiddleware({
      redisUrl: 'redis://test/1',
      ttlMs: 60_000
    });

    let releaseFirst;
    const firstBarrier = new Promise(resolve => {
      releaseFirst = resolve;
    });
    const next = jest.fn(async ctx => {
      if (ctx.requestID === 'first') await firstBarrier;
      return { ok: true, requestID: ctx.requestID };
    });
    const wrapped = middleware.localAction(next, { name: 'signing.provisionAtprotoIdentity' });
    const canonicalAccountId = 'https://pods.example/alice';

    const first = wrapped({
      requestID: 'first',
      params: { canonicalAccountId }
    });
    await new Promise(resolve => setImmediate(resolve));

    await expect(
      wrapped({ requestID: 'second', params: { canonicalAccountId } })
    ).rejects.toMatchObject({ code: 409, type: 'IDENTITY_PROVISIONING_IN_PROGRESS' });
    expect(next).toHaveBeenCalledTimes(1);

    releaseFirst();
    await expect(first).resolves.toEqual({ ok: true, requestID: 'first' });

    await expect(
      wrapped({ requestID: 'third', params: { canonicalAccountId } })
    ).resolves.toEqual({ ok: true, requestID: 'third' });
    expect(next).toHaveBeenCalledTimes(2);

    await middleware.stopped();
  });

  test('does not serialize different canonical accounts', async () => {
    const middleware = AtprotoProvisioningReservationMiddleware({
      redisUrl: 'redis://test/1',
      ttlMs: 60_000
    });
    const next = jest.fn(async ctx => ctx.params.canonicalAccountId);
    const wrapped = middleware.localAction(next, { name: 'signing.provisionAtprotoIdentity' });

    await expect(Promise.all([
      wrapped({ params: { canonicalAccountId: 'https://pods.example/alice' } }),
      wrapped({ params: { canonicalAccountId: 'https://pods.example/bob' } })
    ])).resolves.toEqual([
      'https://pods.example/alice',
      'https://pods.example/bob'
    ]);
    expect(next).toHaveBeenCalledTimes(2);

    await middleware.stopped();
  });

  test('leaves unrelated actions untouched', async () => {
    const middleware = AtprotoProvisioningReservationMiddleware({ redisUrl: 'redis://test/1' });
    const next = jest.fn(async () => 'ok');
    expect(middleware.localAction(next, { name: 'signing.signHttpRequestsBatch' })).toBe(next);
  });
});
