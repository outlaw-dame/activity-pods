'use strict';

const { isClaimableGroup, isSafeGroupSlug } = require('../services/utils/group-ownership');
// The provider config requires deployment-specific environment variables.
// These action tests only need BASE_URL and must not depend on deployment config.
jest.mock('../config/config', () => ({ BASE_URL: 'https://pods.example', ENABLE_GROUPS: true }));
const providerConfig = require('../config/config');
const GroupsService = require('../services/groups');

const ALICE = 'https://pods.example/alice';
const BOB = 'https://pods.example/bob';
const GROUP = 'https://pods.example/photography';
const OTHER = 'https://pods.example/other';

function user(overrides = {}) {
  return { '@id': 'https://pods.example/.account/alice', username: 'alice', webId: ALICE, owns: [], ...overrides };
}
function group(overrides = {}) {
  return { webId: GROUP, group: true, owner: ALICE, ...overrides };
}
function context({ principal = ALICE, ownerAccount = user(), groupAccount = group(), groupUri = GROUP } = {}) {
  const calls = [];
  const ctx = {
    params: { username: 'alice', groupWebId: groupUri },
    meta: { webId: principal },
    call: jest.fn(async (action, params) => {
      calls.push({ action, params });
      if (action === 'auth.account.findByUsername') return ownerAccount;
      if (action === 'auth.account.findByWebId') return groupAccount;
      if (action === 'auth.account.update') return true;
      throw new Error('Unexpected service action: ' + action);
    })
  };
  return { ctx, calls };
}

describe('legacy group ownership authority', () => {
  test.each([
    ['empty group URI', { groupWebId: '', groupAccount: group() }],
    ['whitespace URI', { groupWebId: ' ' + GROUP, groupAccount: group() }],
    ['arbitrary remote URI', { groupWebId: 'https://remote.example/x', groupAccount: null }],
    ['unknown local group', { groupWebId: GROUP, groupAccount: null }],
    ['regular user actor', { groupWebId: GROUP, groupAccount: group({ group: false }) }],
    ['unregistered ID mismatch', { groupWebId: OTHER, groupAccount: group() }],
    ['disabled group', { groupWebId: GROUP, groupAccount: group({ disabled: true }) }],
    ['foreign group owner', { groupWebId: GROUP, groupAccount: group({ owner: BOB }) }],
    ['missing group owner', { groupWebId: GROUP, groupAccount: group({ owner: undefined }) }],
    ['array owner', { groupWebId: GROUP, groupAccount: group({ owner: [ALICE] }) }]
  ])('rejects %s', (_name, args) => {
    expect(isClaimableGroup({ ownerWebId: ALICE, ...args })).toBe(false);
  });

  test('accepts an exact provider-owned group and exact owner only', () => {
    expect(isClaimableGroup({ groupWebId: GROUP, groupAccount: group(), ownerWebId: ALICE })).toBe(true);
    expect(isClaimableGroup({ groupWebId: GROUP, groupAccount: group(), ownerWebId: BOB })).toBe(false);
  });

  test('system override applies only to an existing group identity, not arbitrary URLs', () => {
    expect(isClaimableGroup({ groupWebId: GROUP, groupAccount: group({ owner: BOB }), trustedProviderCall: true })).toBe(true);
    expect(isClaimableGroup({ groupWebId: GROUP, groupAccount: group({ group: false }), trustedProviderCall: true })).toBe(false);
    expect(isClaimableGroup({ groupWebId: OTHER, groupAccount: group(), trustedProviderCall: true })).toBe(false);
  });

  test.each(['../admin', '/settings', 'a/b', 'a%2Fb', 'http://evil.example', 'a?b', 'a#b', 'a b', '__proto__', '', 'a'.repeat(65), 'ä'])(
    'rejects unsafe group slug %s', slug => {
      expect(isSafeGroupSlug(slug)).toBe(false);
    }
  );
  test.each(['a', 'photography', 'photo-club', 'photo_club', 'A9'])(
    'accepts safe group slug %s', slug => {
      expect(isSafeGroupSlug(slug)).toBe(true);
    }
  );
});

describe('groups.claim action integration', () => {
  test('valid claim writes the exact canonical group URI', async () => {
    const { ctx, calls } = context();
    await GroupsService.actions.claim(ctx);
    expect(calls.filter(x => x.action === 'auth.account.update')).toEqual([{
      action: 'auth.account.update',
      params: { id: user()['@id'], owns: [GROUP] }
    }]);
  });

  test('replaying a claim does not append duplicates or write again', async () => {
    const { ctx, calls } = context({ ownerAccount: user({ owns: [GROUP] }) });
    await GroupsService.actions.claim(ctx);
    expect(calls.some(x => x.action === 'auth.account.update')).toBe(false);
  });

  test('denies claiming a group owned by another user (IDOR)', async () => {
    const { ctx, calls } = context({ groupAccount: group({ owner: BOB }) });
    await expect(GroupsService.actions.claim(ctx)).rejects.toThrow();
    expect(calls.some(x => x.action === 'auth.account.update')).toBe(false);
  });

  test('denies claiming arbitrary actor URLs, including a local Person', async () => {
    const { ctx, calls } = context({ groupAccount: group({ group: false }) });
    await expect(GroupsService.actions.claim(ctx)).rejects.toThrow();
    expect(calls.some(x => x.action === 'auth.account.update')).toBe(false);
  });

  test('rejects a caller impersonating an account before group lookup or mutation', async () => {
    const { ctx, calls } = context({ principal: BOB });
    await expect(GroupsService.actions.claim(ctx)).rejects.toThrow();
    expect(calls).toHaveLength(1);
    expect(calls[0].action).toBe('auth.account.findByUsername');
  });

  test('does not convert provider lookup failure into an authorized mutation', async () => {
    const { ctx } = context();
    ctx.call = jest.fn(async action => {
      if (action === 'auth.account.findByUsername') return user();
      throw new Error('Storage temporarily unavailable');
    });
    await expect(GroupsService.actions.claim(ctx)).rejects.toThrow('Storage temporarily unavailable');
    expect(ctx.call.mock.calls.some(([action]) => action === 'auth.account.update')).toBe(false);
  });
});

describe('groups.create preflight validation', () => {
  test('disabled provider rejects group creation at the authoritative action', async () => {
    const previous = providerConfig.ENABLE_GROUPS;
    providerConfig.ENABLE_GROUPS = false;
    try {
      const ctx = {
        params: { id: 'photography', type: 'foaf:Group' },
        meta: { webId: ALICE },
        call: jest.fn()
      };
      await expect(GroupsService.actions.create(ctx)).rejects.toThrow();
      expect(ctx.call).not.toHaveBeenCalled();
    } finally {
      providerConfig.ENABLE_GROUPS = previous;
    }
  });

  test.each(['../admin', '/profile', 'other/path', 'bad%2Fslug', 'a?b', 'a#b', '', 'x'.repeat(65)])(
    'rejects invalid slug before any provider mutation: %s', async id => {
      const ctx = {
        params: { id, type: 'foaf:Group' },
        meta: { webId: ALICE },
        call: jest.fn()
      };
      await expect(GroupsService.actions.create(ctx)).rejects.toThrow();
      expect(ctx.call).not.toHaveBeenCalled();
    }
  );

  test('rejects unauthenticated and system creation before any provider mutation', async () => {
    for (const webId of [undefined, null, 'system']) {
      const ctx = {
        params: { id: 'photography', type: 'foaf:Group' },
        meta: { webId },
        call: jest.fn()
      };
      await expect(GroupsService.actions.create(ctx)).rejects.toThrow();
      expect(ctx.call).not.toHaveBeenCalled();
    }
  });
});
