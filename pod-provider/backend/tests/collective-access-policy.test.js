'use strict';

const {
  parseApprovedApps, assertLiveCollectiveConsent
} = require('../services/utils/collective-access-policy');

const ALICE = 'https://provider.example/users/alice';
const APP_A = 'https://reader.example/app';
const APP_B = 'https://forum.example/app';

function fake({ account = { webId: ALICE }, registered = true,
  rights = ['apods:CreateGroup', 'apods:ReadGroups'], failed = null } = {}) {
  const calls = [];
  const ctx = {
    call: async (action, args) => {
      calls.push({ action, args });
      if (failed === action) throw new Error('upstream unavailable');
      if (action === 'auth.account.findByWebId') return account;
      if (action === 'app-registrations.isRegistered') return registered;
      if (action === 'access-authorizations.getSpecialRights') return rights;
      throw new Error('Unexpected action: ' + action);
    }
  };
  return { ctx, calls };
}
async function deny(promise, code) {
  await expect(promise).rejects.toMatchObject({ type: code, code: 403 });
}
function verify(ctx, operation = 'reserve', app = APP_A, approvedApps = [APP_A, APP_B]) {
  return assertLiveCollectiveConsent(ctx, { principal: ALICE, app, operation, approvedApps });
}

describe('collective provider app approval config', () => {
  test('default is closed; accepts multiple exact HTTPS app identifiers', () => {
    expect(parseApprovedApps('')).toEqual([]);
    expect(parseApprovedApps(APP_A + ',' + APP_B + ',' + APP_A)).toEqual([APP_A, APP_B]);
  });
  test.each([
    'http://reader.example/app', 'https://reader.example/app#fragment',
    'https://user:pass@reader.example/app', 'https://reader.example/app?permissions=all',
    'not-a-uri', 'https://reader.example/app space'
  ])('rejects invalid allowlist application URI %s', value => {
    expect(() => parseApprovedApps(value)).toThrow('invalid application URI');
  });
});

describe('live SAI consent gate', () => {
  test('requires verified local account, registration, approved app and exact consent', async () => {
    const f = fake();
    expect(await verify(f.ctx)).toBe(true);
    expect(f.calls.map(x => x.action)).toEqual([
      'auth.account.findByWebId',
      'app-registrations.isRegistered',
      'access-authorizations.getSpecialRights'
    ]);
    expect(f.calls[0].args).toEqual({ webId: ALICE });
    expect(f.calls[1].args).toEqual({ appUri: APP_A, podOwner: ALICE });
    expect(f.calls[2].args).toEqual({ appUri: APP_A, podOwner: ALICE });
  });
  test('rejects unapproved app before touching account data', async () => {
    const f = fake();
    await deny(verify(f.ctx, 'reserve', APP_B, [APP_A]), 'COLLECTIVE_APP_NOT_APPROVED');
    expect(f.calls).toHaveLength(0);
  });
  test.each([
    ['missing account', { account: null }, 'COLLECTIVE_USER_NOT_FOUND'],
    ['wrong local WebID', { account: { webId: 'https://provider.example/users/bob' } }, 'COLLECTIVE_USER_NOT_FOUND'],
    ['disabled local account', { account: { webId: ALICE, disabled: true } }, 'COLLECTIVE_USER_NOT_FOUND'],
    ['deleted local account', { account: { webId: ALICE, deleted: true } }, 'COLLECTIVE_USER_NOT_FOUND'],
    ['SemApps account tombstone', { account: { webId: ALICE, deletedAt: '2026-11-09T00:00:00Z' } }, 'COLLECTIVE_USER_NOT_FOUND'],
    ['SemApps suspension timestamp', { account: { webId: ALICE, suspendedAt: '2026-11-09T00:00:00Z' } }, 'COLLECTIVE_USER_NOT_FOUND'],
    ['suspended local account', { account: { webId: ALICE, status: 'suspended' } }, 'COLLECTIVE_USER_NOT_FOUND'],
    ['not registered', { registered: false }, 'COLLECTIVE_APP_NOT_REGISTERED'],
    ['no special rights', { rights: [] }, 'COLLECTIVE_APP_CONSENT_MISSING'],
    ['only broad ACL control', { rights: ['acl:Control'] }, 'COLLECTIVE_APP_CONSENT_MISSING'],
    ['unrelated group right', { rights: ['apods:ReadGroups'] }, 'COLLECTIVE_APP_CONSENT_MISSING'],
    ['malformed special rights', { rights: 'apods:CreateGroup' }, 'COLLECTIVE_APP_CONSENT_MISSING']
  ])('denies %s', async (_name, fixture, code) => {
    const f = fake(fixture);
    await deny(verify(f.ctx), code);
  });
  test('accepts exact persisted JSON-LD IRIs for each Group capability', async () => {
    const ns = 'http://activitypods.org/ns/core#';
    const f = fake({ rights: [ns + 'CreateGroup', ns + 'ReadGroups'] });
    expect(await verify(f.ctx, 'reserve')).toBe(true);
    expect(await verify(f.ctx, 'read')).toBe(true);
  });
  test.each([
    'https://activitypods.org/ns/core#CreateGroup',
    'http://activitypods.org/ns/core#CreateGroupExtra',
    'http://other.example/ns#CreateGroup',
    'apods:CreateGroupExtra',
    'APODS:CreateGroup'
  ])('never grants similarly named or noncanonical rights %s', async right => {
    const f = fake({ rights: [right] });
    await deny(verify(f.ctx, 'reserve'), 'COLLECTIVE_APP_CONSENT_MISSING');
  });

  test('membership management requires independently granted ManageMembers capability', async () => {
    const denied = fake({ rights: ['apods:CreateGroup', 'apods:ReadGroups'] });
    await deny(verify(denied.ctx, 'members'), 'COLLECTIVE_APP_CONSENT_MISSING');
    const allowed = fake({ rights: ['http://activitypods.org/ns/core#ManageMembers'] });
    expect(await verify(allowed.ctx, 'members')).toBe(true);
    await deny(verify(allowed.ctx, 'reserve'), 'COLLECTIVE_APP_CONSENT_MISSING');
  });
  test('read requires ReadGroups rather than CreateGroup', async () => {
    const f = fake({ rights: ['apods:CreateGroup'] });
    await deny(verify(f.ctx, 'read'), 'COLLECTIVE_APP_CONSENT_MISSING');
  });
  test('app-specific, separate grants are accepted by either approved app', async () => {
    const f = fake();
    expect(await verify(f.ctx, 'reserve', APP_B)).toBe(true);
    expect(f.calls[1].args.appUri).toBe(APP_B);
  });
  test.each(['auth.account.findByWebId', 'app-registrations.isRegistered',
    'access-authorizations.getSpecialRights'])('does not fail open when %s fails', async action => {
    const f = fake({ failed: action });
    await expect(verify(f.ctx)).rejects.toThrow('upstream unavailable');
  });
  test('never grants authorization to unrecognized operations', async () => {
    const f = fake();
    await deny(verify(f.ctx, 'advance'), 'COLLECTIVE_INVALID_CONSENT_OPERATION');
    expect(f.calls).toHaveLength(0);
  });
});
