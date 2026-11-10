'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const {
  initialGroupSnapshot, acceptGroupSnapshotPage, MAX_PAGE
} = require('../utils/collective-membership-cursor');

const groupActorUri = 'https://paper.example/groups/cg_0123456789abcdef0123456789abcdef';
const start = () => initialGroupSnapshot({ groupActorUri, membershipRevision: 7 });
const actor = i => 'https://remote.example/people/u' + String(i).padStart(6, '0');
function page(ids, hasMore, revision = 7) {
  return {
    groupActorUri, membershipRevision: revision, actorUris: ids,
    hasMore, nextCursor: hasMore ? ids[ids.length - 1] : null
  };
}
test('continuous 1000-member page + 1-member page seals with consistent revision', () => {
  const firstIds = Array.from({ length: MAX_PAGE }, (_, i) => actor(i));
  const first = acceptGroupSnapshotPage(start(), page(firstIds, true));
  assert.equal(first.completed, false);
  assert.equal(first.recipientCount, 1000);
  assert.equal(first.lastActor, actor(999));
  const final = acceptGroupSnapshotPage(first, page([actor(1000)], false));
  assert.equal(final.completed, true);
  assert.equal(final.recipientCount, 1001);
  assert.equal(final.pageCount, 2);
  assert.match(final.digest, /^[0-9a-f]{64}$/);
  assert.throws(() => acceptGroupSnapshotPage(final, page([actor(1001)], false)), /completed/);
});
test('empty Group allows only one empty final page', () => {
  const state = acceptGroupSnapshotPage(start(), page([], false));
  assert.equal(state.completed, true);
  assert.equal(state.recipientCount, 0);
  assert.throws(() => acceptGroupSnapshotPage(start(), page([], true)), /empty/);
});
test('denies overlaps, duplicates, descending cursors and revision drift', () => {
  const state = acceptGroupSnapshotPage(start(), page([actor(1), actor(2)], true));
  assert.throws(() => acceptGroupSnapshotPage(state, page([actor(2), actor(3)], false)), /overlapping/);
  assert.throws(() => acceptGroupSnapshotPage(state, page([actor(3)], false, 8)), /revision/);
  assert.throws(() => acceptGroupSnapshotPage(start(), page([actor(2), actor(1)], false)), /unsorted/);
  assert.throws(() => acceptGroupSnapshotPage(start(), page([actor(1), actor(1)], false)), /duplicate/);
});
test('rejects altered nextCursor and oversized or sparse pages', () => {
  assert.throws(() => acceptGroupSnapshotPage(start(), {
    ...page([actor(1)], true), nextCursor: actor(2)
  }), /cursor/);
  assert.throws(() => acceptGroupSnapshotPage(start(),
    page(Array.from({ length: 1001 }, (_, i) => actor(i)), false)), /size/);
  const sparse = new Array(2);
  sparse[0] = actor(0);
  assert.throws(() => acceptGroupSnapshotPage(start(), page(sparse, false)), /sparse/);
});
