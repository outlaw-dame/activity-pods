'use strict';

const { queryState, resetQuery, validateRequest } =
  require('../services/utils/collective-consent-recovery');

const principal = 'https://provider.example/users/alice#me';
const app = 'https://paper.example/app';
const nonce = '11111111-1111-4111-8111-111111111111';

describe('offline consent mutation recovery is deny-preserving', () => {
  test('requires valid exact identities, positive safe CAS revision and recovery UUID', () => {
    expect(validateRequest({ principal, app, expectedRevision: 3, nonce }).current).toBe(3);
    expect(() => validateRequest({
      principal, app: 'http://insecure.example/app', expectedRevision: 3, nonce
    })).toThrow();
    expect(() => validateRequest({ principal, app, expectedRevision: -1, nonce })).toThrow();
    expect(() => validateRequest({ principal, app, expectedRevision: 3, nonce: 'not-uuid' })).toThrow();
    expect(() => validateRequest({
      principal, app, expectedRevision: Number.MAX_SAFE_INTEGER, nonce
    })).toThrow();
  });

  test('conditional recovery requires original revision, BLOCKED status, and pending markers', () => {
    const sparql = resetQuery({ principal, app, expectedRevision: 3, nonce });
    expect(sparql).toContain('collectiveConsentStatus "blocked"');
    expect(sparql).toContain('collectiveConsentRevision "3"');
    expect(sparql).toContain('collectiveConsentRevision "4"');
    expect(sparql).toContain('collectivePendingMutation ?pending');
    expect(sparql).toContain('collectiveRecoveryNonce');
    expect(sparql).not.toContain('collectiveConsentStatus "stable"');
    expect(sparql).not.toContain('AuthAccount');
  });
  test('state read is scoped to opaque per-user/app identity', () => {
    const first = queryState(principal, app);
    expect(first).toContain('collectivePendingMutation ?pending');
    expect(first).toContain('collectiveRecoveryNonce ?recovery');
    expect(first).not.toContain(principal);
    expect(first).not.toContain(app);
    expect(first).not.toEqual(queryState(principal, 'https://different.example/app'));
  });
});
