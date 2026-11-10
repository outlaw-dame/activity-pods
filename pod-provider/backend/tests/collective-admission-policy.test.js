'use strict';
const { transition, AdmissionPolicyError } = require('../services/utils/collective-admission-policy');

const owner = 'https://provider.example/users/owner';
const admin = 'https://provider.example/users/admin';
const moderator = 'https://provider.example/users/mod';
const alice = 'https://provider.example/users/alice';
const bob = 'https://provider.example/users/bob';
const base = {
  action: 'request', actor: alice, subject: alice,
  owner, actorRole: 'member', current: null, visibility: 'restricted'
};
function t(partial) { return transition({ ...base, ...partial }); }
function deny(input, code) {
  expect(() => t(input)).toThrow(AdmissionPolicyError);
  expect(() => t(input)).toThrow(code);
}
describe('Paper G2 admission policy: consent, moderation and non-activation', () => {
  test('public join is self-authenticated; restricted join needs approval', () => {
    expect(t({ visibility: 'public' })).toEqual({ role: 'member', status: 'active' });
    expect(t({ visibility: 'restricted' })).toEqual({ role: 'member', status: 'requested' });
    deny({ actor: bob, subject: alice }, 'GROUP_ADMISSION_SELF_REQUIRED');
    deny({ visibility: 'private' }, 'GROUP_ADMISSION_INVITE_REQUIRED');
  });
  test('a manager invitation cannot force membership; target must accept', () => {
    const invited = t({
      action: 'invite', actor: admin, actorRole: 'admin',
      subject: alice, visibility: 'private'
    });
    expect(invited).toEqual({ role: 'member', status: 'invited' });
    deny({ action: 'accept', actor: bob, subject: alice, current: invited },
      'GROUP_ADMISSION_SELF_REQUIRED');
    expect(t({ action: 'accept', current: invited, visibility: 'private' }))
      .toEqual({ status: 'active', role: 'member' });
  });
  test('requests are self-initiated and moderator approval can complete them', () => {
    const requested = t({});
    expect(t({ action: 'approve', actor: moderator, actorRole: 'moderator',
      subject: alice, current: requested })).toEqual({
      role: 'member', status: 'active'
    });
    deny({ action: 'approve', actor: alice, current: requested },
      'GROUP_ADMISSION_SEPARATE_APPROVER_REQUIRED');
    deny({ action: 'approve', actor: bob, subject: alice, current: requested },
      'GROUP_ADMISSION_INSUFFICIENT_ROLE');
  });
  test('withdraw, decline and leave remain direct self decisions', () => {
    expect(t({ action: 'withdraw', current: { role: 'member', status: 'requested' } }))
      .toEqual({ status: 'left', role: 'member' });
    expect(t({ action: 'decline', current: { role: 'member', status: 'invited' } }))
      .toEqual({ status: 'left', role: 'member' });
    expect(t({ action: 'leave', current: { role: 'member', status: 'active' } }))
      .toEqual({ status: 'left', role: 'member' });
    deny({ action: 'leave', current: null }, 'GROUP_ADMISSION_INVALID_TRANSITION');
  });
  test('moderators cannot act on peer moderators or administrators', () => {
    deny({ action: 'remove', actor: moderator, actorRole: 'moderator',
      current: { role: 'moderator', status: 'active' }
    }, 'GROUP_ADMISSION_INSUFFICIENT_ROLE');
    deny({ action: 'ban', actor: moderator, actorRole: 'moderator',
      current: { role: 'admin', status: 'active' }
    }, 'GROUP_ADMISSION_INSUFFICIENT_ROLE');
    expect(t({ action: 'ban', actor: admin, actorRole: 'admin',
      current: { role: 'moderator', status: 'active' }
    })).toEqual({ role: 'member', status: 'banned' });
  });
  test('ban and unban never implicitly reactivate a member', () => {
    const banned = t({ action: 'ban', actor: owner, actorRole: 'owner',
      subject: alice, current: { role: 'member', status: 'active' }
    });
    expect(banned).toEqual({ role: 'member', status: 'banned' });
    for (const action of ['request', 'invite', 'accept', 'approve']) {
      deny({ action, current: banned }, 'GROUP_ADMISSION_BANNED');
    }
    deny({ action: 'unban', actor: moderator, actorRole: 'moderator',
      current: banned }, 'GROUP_ADMISSION_INSUFFICIENT_ROLE');
    expect(t({ action: 'unban', actor: admin, actorRole: 'admin',
      current: banned })).toEqual({ role: 'member', status: 'left' });
  });
  test('owner is immutable; neither role nor member action can transfer ownership', () => {
    deny({ action: 'ban', actor: admin, actorRole: 'admin', subject: owner },
      'GROUP_ADMISSION_IMMUTABLE_OWNER');
    deny({ action: 'remove', actor: owner, actorRole: 'owner',
      current: { role: 'owner', status: 'active' }
    }, 'GROUP_ADMISSION_IMMUTABLE_OWNER');
    deny({ actor: owner, actorRole: 'admin' }, 'GROUP_ADMISSION_ROLE_MISMATCH');
    deny({ action: 'promote', actor: owner, actorRole: 'owner' },
      'GROUP_ADMISSION_INVALID_INPUT');
  });
  test('following is not membership and no method can create that transition', () => {
    deny({ action: 'follow' }, 'GROUP_ADMISSION_INVALID_INPUT');
    deny({ action: 'boost' }, 'GROUP_ADMISSION_INVALID_INPUT');
  });
  test('invalid snapshots and role substitution fail closed', () => {
    deny({ actorRole: 'superadmin' }, 'GROUP_ADMISSION_INVALID_INPUT');
    deny({ visibility: 'unlisted' }, 'GROUP_ADMISSION_INVALID_INPUT');
    deny({ current: { status: 'wat', role: 'member' } },
      'GROUP_ADMISSION_INVALID_STATE');
    deny({ current: { status: 'active', role: 'owner' } },
      'GROUP_ADMISSION_IMMUTABLE_OWNER');
  });
  test('no mutation of input snapshots and output is immutable', () => {
    const current = Object.freeze({ role: 'member', status: 'invited' });
    const result = t({ action: 'accept', current });
    expect(Object.isFrozen(result)).toBe(true);
    expect(current).toEqual({ role: 'member', status: 'invited' });
  });
});
