'use strict';

const {
  planGroupFanout, MAX_RECIPIENTS, MAX_LOCAL_BATCH, MAX_REMOTE_BATCH
} = require('../utils/collective-fanout-plan');

const groupActorUri = 'https://paper.example/groups/cg_0123456789abcdef0123456789abcdef';
const intentId = 'paper-g2-test-intent-00001';
const actor = (i, domain) => 'https://' + domain + '/users/u' + i;
const local = i => ({
  actorUri: actor(i, 'paper.example'),
  dataset: 'p' + Math.floor(i / 8),
  inboxUri: actor(i, 'paper.example') + '/inbox'
});
const remote = (i, domain = 'remote.example') => ({
  actorUri: actor(i, domain), inboxUrl: actor(i, domain) + '/inbox',
  sharedInboxUrl: 'https://' + domain + '/inbox', targetDomain: domain
});
function plan(localRecipients, remoteRecipients, visibility = 'public', revision = 1) {
  return planGroupFanout({
    intentId, groupActorUri, membershipRevision: revision,
    visibility, localRecipients, remoteRecipients
  });
}

describe('Paper G2 local and remote bounded fan-out planning', () => {
  test.each([1, 10, 100, 1000])('plans %i local members without remote delivery', n => {
    const recipients = Array.from({ length: n }, (_, i) => local(i));
    const result = plan(recipients, []);
    expect(result.recipientCount).toBe(n);
    expect(result.remoteBatches).toHaveLength(0);
    expect(result.localBatches.flatMap(b => b.recipients)).toHaveLength(n);
    expect(result.localBatches.every(b => b.recipients.length <= MAX_LOCAL_BATCH)).toBe(true);
    expect(new Set(result.localBatches.flatMap(b => b.recipients.map(r => r.actorUri))).size).toBe(n);
    expect(result.localBatches.every(b => b.recipients.every(r => r.dataset === b.dataset))).toBe(true);
    expect(result.fingerprint).toMatch(/^[0-9a-f]{64}$/);
  });
  test.each([1, 10, 100, 1000])('plans %i public remote members with sharedInbox grouping', n => {
    const recipients = Array.from({ length: n }, (_, i) => remote(i));
    const result = plan([], recipients);
    expect(result.localBatches).toHaveLength(0);
    expect(result.remoteRecipientCount).toBe(n);
    expect(result.remoteBatches).toHaveLength(Math.ceil(n / MAX_REMOTE_BATCH));
    expect(result.remoteBatches.every(b =>
      b.destination === 'https://remote.example/inbox' && b.mode === 'sharedInbox')).toBe(true);
    expect(result.remoteBatches.flatMap(b => b.recipientActors)).toHaveLength(n);
  });
  test('members-only and unlisted groups never use sharedInbox', () => {
    for (const visibility of ['members', 'unlisted']) {
      const result = plan([], [remote(1), remote(2)], visibility);
      expect(result.remoteBatches).toHaveLength(2);
      expect(result.remoteBatches.every(b => b.mode === 'actorInbox')).toBe(true);
      expect(result.remoteBatches.every(b => b.recipientActors.length === 1)).toBe(true);
    }
  });
  test('source order does not change fingerprint or groupings', () => {
    const localRecipients = Array.from({ length: 100 }, (_, i) => local(i));
    const remoteRecipients = Array.from({ length: 120 }, (_, i) => remote(i));
    const a = plan(localRecipients, remoteRecipients);
    const b = plan(localRecipients.slice().reverse(), remoteRecipients.slice().reverse());
    expect(a).toEqual(b);
    expect(plan(localRecipients, remoteRecipients, 'public', 2).fingerprint)
      .not.toBe(a.fingerprint);
  });
  test('mixed recipients partition by Pod dataset and remote destination', () => {
    const mixed = plan([local(1), local(9)], [
      remote(1), remote(2, 'second.example'), remote(3, 'second.example')
    ]);
    expect(mixed.localBatches).toHaveLength(2);
    expect(mixed.remoteBatches).toHaveLength(2);
    expect(mixed.localRecipientCount).toBe(2);
    expect(mixed.remoteRecipientCount).toBe(3);
    expect(mixed.remoteBatches.find(b => b.targetDomain === 'second.example')
      .recipientActors).toHaveLength(2);
  });
  test('rejects local/remote overlap and duplicate actors', () => {
    expect(() => plan([local(1), local(1)], [])).toThrow('duplicate');
    expect(() => plan([local(1)], [{ ...remote(2), actorUri: local(1).actorUri }]))
      .toThrow('duplicate');
  });
  test('bounds input rather than allocating unbounded batches', () => {
    expect(MAX_RECIPIENTS).toBe(1000);
    expect(() => plan(Array.from({ length: 1001 }, (_, i) => local(i)), []))
      .toThrow('at most 1000');
    const sparse = new Array(2);
    sparse[0] = local(1);
    expect(() => plan(sparse, [])).toThrow('sparse');
  });
  test('refuses malformed policy, destination and member input', () => {
    expect(() => plan([local(1)], [], 'private')).toThrow('visibility');
    expect(() => plan([local(1)], [], 'members', 0)).toThrow('revision');
    expect(() => plan([], [{ ...remote(1), inboxUrl: 'http://169.254.169.254/latest' }]))
      .toThrow('endpoint');
    expect(() => plan([], [{ ...remote(1), sharedInboxUrl: 'https://other.example/inbox' }]))
      .toThrow('mismatch');
    expect(() => plan([], [{ ...remote(1), targetDomain: 'elsewhere.example' }]))
      .toThrow('mismatch');
    expect(() => plan([{ ...local(1), dataset: '../../settings' }], []))
      .toThrow('dataset');
    expect(() => plan([{ ...local(1), webId: 'secret' }], []))
      .toThrow('local recipient');
  });
  test('contains no broker, network, queue or redis I/O per recipient', () => {
    const fs = require('node:fs');
    const path = require('node:path');
    const source = fs.readFileSync(path.join(__dirname, '../utils/collective-fanout-plan.js'), 'utf8');
    expect(source).not.toMatch(/ctx\.call\(|broker\.call\(|fetch\(|axios\(|new Redis\(|\.createJob\(/u);
    expect(plan([local(1)], [remote(1)]).recipientCount).toBe(2);
  });
});
