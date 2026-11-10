'use strict';

/**
 * G2 membership cursor-chain validator for INTERNAL authoritative snapshots.
 * It cannot authenticate the page producer: the future Group membership
 * service must do that before passing any page to this pure verifier.
 * This module creates no membership records, activities or delivery jobs.
 *
 * Page cursor is the exact last actor URI (stable keyset), never OFFSET.
 * Pages are sorted globally by exact actor URI, including across Pod cells.
 */
const crypto = require('node:crypto');
const MAX_PAGE = 1000;
const MAX_PAGES = 100000;

function fail(message) { throw new TypeError('Invalid Group membership snapshot: ' + message); }
function actorUri(raw) {
  if (typeof raw !== 'string' || raw.length > 2048 ||
      /[\u0000-\u0020\u007f\\]/u.test(raw)) fail('invalid actor URI');
  let parsed;
  try { parsed = new URL(raw); } catch { fail('invalid actor URI'); }
  if (parsed.protocol !== 'https:' || parsed.href !== raw || parsed.username ||
      parsed.password || parsed.search || parsed.hash) fail('invalid actor URI');
  return raw;
}
function initialGroupSnapshot({ groupActorUri, membershipRevision }) {
  actorUri(groupActorUri);
  if (!Number.isSafeInteger(membershipRevision) || membershipRevision < 1) {
    fail('invalid membership revision');
  }
  return Object.freeze({
    version: 'paper.groups.membership-snapshot-chain.v1',
    groupActorUri, membershipRevision, lastActor: null,
    pageCount: 0, recipientCount: 0, completed: false,
    digest: crypto.createHash('sha256')
      .update(JSON.stringify(['paper.groups.membership-snapshot-chain.v1',
        groupActorUri, membershipRevision])).digest('hex')
  });
}
function acceptGroupSnapshotPage(state, page) {
  if (!state || state.version !== 'paper.groups.membership-snapshot-chain.v1' ||
      !page || typeof page !== 'object' || Array.isArray(page) ||
      state.completed || state.pageCount >= MAX_PAGES) fail('invalid or completed page chain');
  if (page.groupActorUri !== state.groupActorUri ||
      page.membershipRevision !== state.membershipRevision) {
    fail('Group identity or membership revision changed during scan');
  }
  if (!Array.isArray(page.actorUris) || page.actorUris.length > MAX_PAGE ||
      typeof page.hasMore !== 'boolean') fail('page size or continuation invalid');
  if (page.actorUris.length === 0 && (page.hasMore || state.pageCount > 0)) {
    // A single empty first page is valid for an empty Group snapshot.
    fail('empty or silently truncated page');
  }
  let cursor = state.lastActor;
  for (let i = 0; i < page.actorUris.length; i++) {
    if (!Object.hasOwn(page.actorUris, i)) fail('sparse membership page');
    const next = actorUri(page.actorUris[i]);
    if (cursor !== null && next <= cursor) fail('unsorted, duplicate or overlapping membership page');
    cursor = next;
  }
  const requiredCursor = page.hasMore ? cursor : null;
  if (page.nextCursor !== requiredCursor) fail('page cursor mismatch');
  const digest = crypto.createHash('sha256')
    .update(JSON.stringify([state.digest, page.actorUris, page.hasMore, requiredCursor]))
    .digest('hex');
  return Object.freeze({
    ...state, pageCount: state.pageCount + 1,
    recipientCount: state.recipientCount + page.actorUris.length,
    lastActor: cursor, completed: !page.hasMore, digest
  });
}
module.exports = Object.freeze({
  initialGroupSnapshot, acceptGroupSnapshotPage, MAX_PAGE
});
