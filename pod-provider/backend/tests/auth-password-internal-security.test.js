'use strict';

const authPasswordService = require('../services/auth-password-internal.service');

function service(overrides = {}) {
  return {
    settings: { bearerToken: 'p'.repeat(32) },
    failureBuckets: new Map(),
    overflowBlockedUntil: 0,
    ...authPasswordService.methods,
    ...overrides
  };
}

describe('internal password verification capability', () => {
  test('uses a credential distinct from the federation signing token', () => {
    const verifier = service();
    expect(() => verifier._auth({
      meta: { $headers: { authorization: `Bearer ${'s'.repeat(32)}` } }
    })).toThrow(expect.objectContaining({ code: 401, type: 'AUTH_FAILED' }));

    expect(() => verifier._auth({
      meta: { $headers: { authorization: `Bearer ${'p'.repeat(32)}` } }
    })).not.toThrow();
  });

  test('fails closed when the dedicated verifier credential is not configured', () => {
    const verifier = service({ settings: { bearerToken: null } });
    expect(() => verifier._auth({ meta: { $headers: {} } })).toThrow(
      expect.objectContaining({ code: 503, type: 'AUTH_VERIFY_NOT_CONFIGURED' })
    );
  });

  test('collapses missing-account and wrong-password outcomes to the same external result', async () => {
    const missing = service({ _auth: jest.fn() });
    const missingCtx = {
      params: { canonicalAccountId: 'https://pods.example/missing', password: 'guess' },
      meta: {},
      call: jest.fn().mockResolvedValueOnce(null)
    };
    await expect(
      authPasswordService.actions.verify.handler.call(missing, missingCtx)
    ).resolves.toEqual({ ok: false, reason: 'invalid_credentials' });
    expect(missingCtx.meta.$statusCode).toBe(401);
    expect(missingCtx.call).toHaveBeenCalledTimes(1);

    const wrong = service({ _auth: jest.fn() });
    const wrongCtx = {
      params: { canonicalAccountId: 'https://pods.example/alice', password: 'guess' },
      meta: {},
      call: jest.fn()
        .mockResolvedValueOnce({ webId: 'https://pods.example/alice', username: 'alice' })
        .mockRejectedValueOnce(new Error('invalid password'))
    };
    await expect(
      authPasswordService.actions.verify.handler.call(wrong, wrongCtx)
    ).resolves.toEqual({ ok: false, reason: 'invalid_credentials' });
    expect(wrongCtx.meta.$statusCode).toBe(401);
    expect(wrongCtx.call).toHaveBeenCalledTimes(2);
  });

  test('returns scope only after authoritative account lookup and password verification', async () => {
    const verifier = service({ _auth: jest.fn() });
    const canonicalAccountId = 'https://pods.example/alice';
    const ctx = {
      params: { canonicalAccountId, password: 'correct' },
      meta: {},
      call: jest.fn()
        .mockResolvedValueOnce({ webId: canonicalAccountId, username: 'alice' })
        .mockResolvedValueOnce(true)
    };
    await expect(
      authPasswordService.actions.verify.handler.call(verifier, ctx)
    ).resolves.toEqual({ ok: true, scope: 'full' });
    expect(ctx.call).toHaveBeenNthCalledWith(1, 'auth.account.findByWebId', { webId: canonicalAccountId });
    expect(ctx.call).toHaveBeenNthCalledWith(2, 'auth.account.verify', {
      username: 'alice',
      password: 'correct'
    });
  });

  test('rate-limits repeated failures using a bounded hashed account bucket', () => {
    const verifier = service();
    const key = 'bucket-key';
    for (let i = 0; i < 10; i += 1) verifier._recordFailure(key, 1000 + i);
    expect(verifier._isRateLimited(key, 2000)).toBe(true);
    expect(verifier.failureBuckets.get(key).failures).toBe(10);
  });

  test('bucket flooding never evicts an actively blocked account', () => {
    const verifier = service();
    const now = 10_000;
    const protectedKey = 'protected-real-account';
    verifier.failureBuckets.set(protectedKey, {
      failures: 10,
      windowStartedAt: now,
      lastFailureAt: now
    });
    for (let i = 0; i < 9_999; i += 1) {
      verifier.failureBuckets.set(`blocked-${i}`, {
        failures: 10,
        windowStartedAt: now,
        lastFailureAt: now + i + 1
      });
    }

    verifier._recordFailure('attacker-new-account', now + 100);

    expect(verifier.failureBuckets.size).toBe(10_000);
    expect(verifier.failureBuckets.has(protectedKey)).toBe(true);
    expect(verifier.failureBuckets.has('attacker-new-account')).toBe(false);
    expect(verifier.overflowBlockedUntil).toBe(now + 5 * 60 * 1000);
    expect(verifier._isRateLimited('another-untracked-account', now + 101)).toBe(true);
    expect(verifier._isRateLimited(protectedKey, now + 101)).toBe(true);
  });

  test('capacity pressure evicts only a non-blocked bucket when one exists', () => {
    const verifier = service();
    const now = 20_000;
    verifier.failureBuckets.set('protected', {
      failures: 10,
      windowStartedAt: now,
      lastFailureAt: now
    });
    verifier.failureBuckets.set('safe-to-evict', {
      failures: 1,
      windowStartedAt: now,
      lastFailureAt: now - 1
    });
    for (let i = 0; i < 9_998; i += 1) {
      verifier.failureBuckets.set(`blocked-${i}`, {
        failures: 10,
        windowStartedAt: now,
        lastFailureAt: now + i + 1
      });
    }

    verifier._recordFailure('new-account', now + 100);

    expect(verifier.failureBuckets.size).toBe(10_000);
    expect(verifier.failureBuckets.has('protected')).toBe(true);
    expect(verifier.failureBuckets.has('safe-to-evict')).toBe(false);
    expect(verifier.failureBuckets.get('new-account').failures).toBe(1);
    expect(verifier.overflowBlockedUntil).toBe(0);
  });
});