'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { planGroupFanout } = require('../utils/collective-fanout-plan');

const groupActorUri = 'https://paper.example/groups/cg_0123456789abcdef0123456789abcdef';
function local(i) {
  return {
    actorUri: 'https://paper.example/users/u' + i,
    inboxUri: 'https://paper.example/users/u' + i + '/inbox',
    dataset: 'pod' + Math.floor(i / 8)
  };
}
function remote(i) {
  return {
    actorUri: 'https://remote.example/users/u' + i,
    inboxUrl: 'https://remote.example/users/u' + i + '/inbox',
    sharedInboxUrl: 'https://remote.example/inbox',
    targetDomain: 'remote.example'
  };
}
const plan = (localRecipients, remoteRecipients, visibility = 'public', rev = 1) =>
  planGroupFanout({
    intentId: 'paper-group-native-test-0001', groupActorUri,
    membershipRevision: rev, visibility, localRecipients, remoteRecipients
  });

test('1000 local members use bounded Pod-dataset batches without remote destinations', () => {
  const p = plan(Array.from({ length: 1000 }, (_, i) => local(i)), []);
  assert.equal(p.localRecipientCount, 1000);
  assert.equal(p.remoteBatches.length, 0);
  assert(p.localBatches.every(b => b.recipients.length <= 32));
  assert.equal(p.localBatches.reduce((a, b) => a + b.recipients.length, 0), 1000);
  assert.equal(p.dispatchable, false);
});
test('1000 same-domain public members produce exactly one sharedInbox destination intent', () => {
  const p = plan([], Array.from({ length: 1000 }, (_, i) => remote(i)));
  assert.equal(p.remoteBatches.length, 1);
  assert.equal(p.remoteBatches[0].recipientActors.length, 1000);
  assert.equal(p.remoteBatches[0].destination, 'https://remote.example/inbox');
});
test('nonpublic Group deliveries never use an instance-wide sharedInbox', () => {
  for (const visibility of ['unlisted', 'members']) {
    const p = plan([], [remote(1), remote(2)], visibility);
    assert.equal(p.remoteBatches.length, 2);
    assert(p.remoteBatches.every(b => b.mode === 'actorInbox'));
  }
});
test('conflicting/duplicate identities and malformed destinations fail closed', () => {
  assert.throws(() => plan([local(1), local(1)], []), /duplicate/);
  assert.throws(() => plan([local(1)], [{ ...remote(2), actorUri: local(1).actorUri }]), /duplicate/);
  assert.throws(() => plan([], [{ ...remote(1), targetDomain: 'wrong.example' }]), /mismatch/);
  assert.throws(() => plan([], [{ ...remote(1), sharedInboxUrl: 'http://remote.example/inbox' }]), /mismatch/);
  assert.throws(() => plan(Array.from({ length: 1001 }, (_, i) => local(i)), []), /at most 1000/);
  assert.throws(() => plan([local(1)], [], 'members', 0), /revision/);
});
test('cross-cell input ordering does not change plan identity', () => {
  const locals = Array.from({ length: 16 }, (_, i) => local(i));
  const remotes = Array.from({ length: 20 }, (_, i) => remote(i));
  assert.deepEqual(plan(locals, remotes), plan(locals.slice().reverse(), remotes.slice().reverse()));
  assert.notEqual(plan(locals, remotes, 'public', 1).fingerprint,
    plan(locals, remotes, 'public', 2).fingerprint);
});
