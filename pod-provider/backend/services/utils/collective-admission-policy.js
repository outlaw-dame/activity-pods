'use strict';

/**
 * IO-free, app-neutral admission policy. Inputs MUST be snapshots obtained
 * from the authoritative provider; this module cannot authenticate users,
 * validate remote signatures, issue SAI rights, or commit membership epochs.
 *
 * No operation can force an unconsenting actor into active membership.
 * Following a Group is explicitly NOT a membership transition.
 */
const ACTIONS = new Set([
  'request', 'invite', 'accept', 'approve', 'withdraw', 'decline',
  'leave', 'remove', 'ban', 'unban'
]);
const STATES = new Set(['requested', 'invited', 'active', 'banned', 'left']);
const ROLES = new Set(['owner', 'admin', 'moderator', 'member']);
const VISIBILITIES = new Set(['public', 'restricted', 'private']);
class AdmissionPolicyError extends Error {
  constructor(code) {
    super(code);
    this.name = 'AdmissionPolicyError';
    this.code = code;
  }
}
function fail(code) { throw new AdmissionPolicyError(code); }
function validActorUri(value) {
  if (typeof value !== 'string' || value.length < 9 || value.length > 2048) return false;
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i);
    if (code <= 32 || code === 127 || code === 92) return false;
  }
  try {
    const u = new URL(value);
    return u.protocol === 'https:' && u.href === value &&
      !u.username && !u.password && !u.search;
  } catch { return false; }
}
function assertAuthority({ actor, subject, owner, actorRole, current, visibility, action }) {
  if (!ACTIONS.has(action) || !VISIBILITIES.has(visibility) ||
      !ROLES.has(actorRole) ||
      !validActorUri(actor) || !validActorUri(subject) || !validActorUri(owner)) {
    fail('GROUP_ADMISSION_INVALID_INPUT');
  }
  // No self-assertion of persisted role is permitted; caller must have
  // separately verified this snapshot in a single revision/fenced transaction.
  if ((actor === owner) !== (actorRole === 'owner')) {
    fail('GROUP_ADMISSION_ROLE_MISMATCH');
  }
  if (subject === owner || current?.role === 'owner') {
    fail('GROUP_ADMISSION_IMMUTABLE_OWNER');
  }
  if (current !== null && current !== undefined &&
      (!STATES.has(current.status) || !ROLES.has(current.role))) {
    fail('GROUP_ADMISSION_INVALID_STATE');
  }
}
function assertMayModerate(actorRole, currentRole) {
  const tier = { owner: 4, admin: 3, moderator: 2, member: 1 };
  if (tier[actorRole] <= 1 || tier[actorRole] <= tier[currentRole || 'member']) {
    fail('GROUP_ADMISSION_INSUFFICIENT_ROLE');
  }
}
function transition(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    fail('GROUP_ADMISSION_INVALID_INPUT');
  }
  const { action, actor, subject, owner, actorRole, visibility } = input;
  const current = input.current ?? null;
  assertAuthority({ action, actor, subject, owner, actorRole,
    current, visibility });
  const self = actor === subject;
  const state = current?.status ?? 'absent';
  const role = current?.role ?? 'member';
  function next(status, nextRole = role) {
    return Object.freeze({ status, role: nextRole });
  }

  // A ban remains binding across invitations and new requests. Unban
  // returns to "left", never directly to active membership.
  if (state === 'banned' && action !== 'unban') {
    fail('GROUP_ADMISSION_BANNED');
  }
  switch (action) {
    case 'request':
      if (!self || actorRole !== 'member') fail('GROUP_ADMISSION_SELF_REQUIRED');
      if (!['absent', 'left'].includes(state)) fail('GROUP_ADMISSION_INVALID_TRANSITION');
      if (visibility === 'private') fail('GROUP_ADMISSION_INVITE_REQUIRED');
      return next(visibility === 'public' ? 'active' : 'requested', 'member');
    case 'invite':
      if (self) fail('GROUP_ADMISSION_SEPARATE_INVITER_REQUIRED');
      assertMayModerate(actorRole, 'member');
      if (!['absent', 'left', 'requested'].includes(state)) {
        fail('GROUP_ADMISSION_INVALID_TRANSITION');
      }
      return next('invited', 'member');
    case 'accept':
      if (!self) fail('GROUP_ADMISSION_SELF_REQUIRED');
      if (state !== 'invited') fail('GROUP_ADMISSION_INVALID_TRANSITION');
      return next('active', role);
    case 'approve':
      if (self) fail('GROUP_ADMISSION_SEPARATE_APPROVER_REQUIRED');
      assertMayModerate(actorRole, 'member');
      if (state !== 'requested') fail('GROUP_ADMISSION_INVALID_TRANSITION');
      return next('active', 'member');
    case 'withdraw':
      if (!self) fail('GROUP_ADMISSION_SELF_REQUIRED');
      if (state !== 'requested') fail('GROUP_ADMISSION_INVALID_TRANSITION');
      return next('left', 'member');
    case 'decline':
      if (!self) fail('GROUP_ADMISSION_SELF_REQUIRED');
      if (state !== 'invited') fail('GROUP_ADMISSION_INVALID_TRANSITION');
      return next('left', 'member');
    case 'leave':
      if (!self) fail('GROUP_ADMISSION_SELF_REQUIRED');
      if (state !== 'active') fail('GROUP_ADMISSION_INVALID_TRANSITION');
      return next('left', 'member');
    case 'remove':
      if (self) fail('GROUP_ADMISSION_SELF_REMOVAL_NOT_MODERATION');
      assertMayModerate(actorRole, role);
      if (!['active', 'invited', 'requested'].includes(state)) {
        fail('GROUP_ADMISSION_INVALID_TRANSITION');
      }
      return next('left', 'member');
    case 'ban':
      if (self) fail('GROUP_ADMISSION_SELF_BAN');
      assertMayModerate(actorRole, role);
      return next('banned', 'member');
    case 'unban':
      if (self) fail('GROUP_ADMISSION_SELF_UNBAN');
      // Moderators cannot unban someone because removal of a ban is a
      // separate authority decision and must not activate the member.
      if (!['owner', 'admin'].includes(actorRole)) {
        fail('GROUP_ADMISSION_INSUFFICIENT_ROLE');
      }
      if (state !== 'banned') fail('GROUP_ADMISSION_INVALID_TRANSITION');
      return next('left', 'member');
    default:
      fail('GROUP_ADMISSION_INVALID_INPUT');
  }
}
module.exports = Object.freeze({ ACTIONS, STATES, ROLES, VISIBILITIES,
  AdmissionPolicyError, transition });
