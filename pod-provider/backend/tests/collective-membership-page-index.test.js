'use strict';
const crypto = require('node:crypto');
const index = require('../utils/collective-membership-page-index');

const groupId = 'cg_' + 'f'.repeat(32);
const owner = 'https://paper.example/users/alice#me';
const app = 'https://paper.example/app';
const member = i => 'https://members.example/users/u' + String(i).padStart(6, '0');
function page(start = 0, count = 100, hasMore = true, cursor = null) {
  return index.encodePage({
    groupId, revision: 17, cursor, hasMore,
    members: Array.from({ length: count }, (_, i) => ({
      actorUri: member(start + i), role: 'member'
    }))
  });
}
function result(p) {
  return [{ epoch: { value: String(p.revision) },
    pageJson: { value: p.json }, pageDigest: { value: p.digest } }];
}
describe('G2 immutable provider membership page projection', () => {
  test('canonical direct lookup is deterministic and bounded by one page', () => {
    const first = page();
    const second = page(100, 100, false, first.nextCursor);
    expect(first.members).toHaveLength(100);
    expect(first.nextCursor).toBe(member(99));
    expect(second.nextCursor).toBeNull();
    expect(index.pageSubject(groupId, 17, null)).toBe(first.subject);
    expect(index.pageSubject(groupId, 17, first.nextCursor)).toBe(second.subject);
    expect(first.subject).not.toBe(second.subject);
    expect(index.decodeRead(result(second), {
      groupId, revision: 17, cursor: first.nextCursor
    })).toEqual({
      groupId, membershipRevision: 17, members: second.members,
      nextCursor: null, hasMore: false
    });
  });
  test('read SPARQL retains same-group consent, unique active owner and epoch fences', () => {
    const sparql = index.readPageQuery({ groupId, owner, app, revision: 17 });
    expect(sparql).toContain('collectiveIndexedMembershipEpoch ?epoch');
    expect(sparql).toContain('collectiveMembershipEpoch ?epoch');
    expect(sparql).toContain('collectiveConsentStatus "stable"');
    expect(sparql).toContain('collectivePendingMutation');
    expect(sparql).toContain('AuthAccount');
    expect(sparql).toContain('FILTER NOT EXISTS { ?otherOwnerAccount');
    expect(sparql).toContain(index.pageSubject(groupId, 17, null));
    expect(sparql).not.toContain('ORDER BY');
    expect(sparql).not.toContain('OFFSET');
    expect(sparql).not.toContain('CollectiveMembershipV1');
  });
  test('publication is same-dataset owner/epoch/consent conditional', () => {
    const q = index.publishQuery({ groupId, owner, app, revision: 17 });
    expect(q).toContain('collectiveIndexedMembershipEpoch ?oldIndexEpoch');
    expect(q).toContain('FILTER(xsd:integer(?epoch) = 17)');
    expect(q).toContain('collectiveConsentStatus "stable"');
    expect(q).toContain('AuthAccount');
    expect(q).not.toContain('SERVICE');
  });
  test('tampering, stale revisions, duplicate rows and unauthorized cursors fail closed', () => {
    const p = page();
    const cases = [
      [], [result(p)[0], result(p)[0]],
      [{ ...result(p)[0], epoch: { value: '18' } }],
      [{ ...result(p)[0], pageJson: { value: p.json + ' ' } }],
      [{ ...result(p)[0], pageDigest: { value: crypto.randomBytes(32).toString('hex') } }]
    ];
    for (const rows of cases) {
      expect(() => index.decodeRead(rows, { groupId, revision: 17 }))
        .toThrow();
    }
    expect(() => index.decodeRead(result(p), {
      groupId, revision: 17, cursor: member(99)
    })).toThrow('MEMBERSHIP_INDEX_CORRUPT');
  });
  test('invalid actor, roles, ordering, oversized pages are rejected before persistence', () => {
    expect(() => index.encodePage({
      groupId, revision: 17, members: [
        { actorUri: member(2), role: 'member' },
        { actorUri: member(1), role: 'member' }
      ], hasMore: false
    })).toThrow('ORDER');
    expect(() => index.encodePage({
      groupId, revision: 17, members: [
        { actorUri: member(2), role: 'superuser' }
      ], hasMore: false
    })).toThrow('ROLE');
    expect(() => index.encodePage({
      groupId, revision: 17, members: [
        { actorUri: 'http://insecure.example/actor', role: 'member' }
      ], hasMore: false
    })).toThrow();
    expect(() => page(0, 101)).toThrow('SIZE');
    expect(() => page(0, 1, true, member(100))).toThrow('CURSOR');
  });
  test('staging is fixed-subject/immutable and never publishes the revision pointer', () => {
    const p = page();
    const q = index.stagePageQuery(p);
    expect(q).toContain('INSERT DATA');
    expect(q).toContain(p.subject);
    expect(q).not.toContain('collectiveIndexedMembershipEpoch');
    expect(q).not.toContain('DELETE');
    expect(q).not.toContain('SERVICE');
    expect(() => index.stagePageQuery({ ...p, json: '{}' })).toThrow();
  });
});
