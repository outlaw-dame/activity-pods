'use strict';
const rdf = require('../utils/collective-membership-rdf');
const delta = require('../utils/collective-membership-delta-snapshot');
const groupId = 'cg_' + 'f'.repeat(32);
const anotherGroup = 'cg_' + 'e'.repeat(32);
const owner = 'https://provider.example/users/owner';
const app = 'https://provider.example/app';
const actor = i => 'https://remote.example/users/u' + i;
function row(uri, role, status, epoch = '4', base = '1', count = '2', group = groupId) {
  return {
    epoch: { value: epoch }, baseEpoch: { value: base },
    deltaCount: { value: count },
    member: { value: rdf.memberSubject(group, uri).slice(1, -1) },
    actor: { value: uri },
    role: { value: role }, status: { value: status }
  };
}
describe('G2 group-local bounded TDB2 delta read', () => {
  test('sparql uses direct Group subject and existing SAI/account authority', () => {
    const s = delta.readDeltaSnapshotQuery({ groupId, owner, app });
    expect(s).toContain('collectiveIndexChangedMember ?member');
    expect(s).toContain('collectiveIndexedMembershipEpoch ?baseEpoch');
    expect(s).toContain('collectiveConsentStatus "stable"');
    expect(s).toContain('AuthAccount');
    expect(s).toContain('LIMIT 514');
    expect(s).not.toContain('ORDER BY');
    expect(s).not.toContain('OFFSET');
    expect(s).not.toContain('SERVICE');
  });
  test('one atomic query result yields ordered upserts/removals and exact revision', () => {
    const rows = [row(actor(2), 'moderator', 'active'), row(actor(1), 'member', 'banned')];
    const result = delta.decodeDeltaSnapshot(rows, { groupId, owner });
    expect(result).toEqual({
      groupId, baseRevision: 1, membershipRevision: 4, deltaCount: 2,
      changes: [
        { actorUri: actor(1), kind: 'remove' },
        { actorUri: actor(2), kind: 'upsert', role: 'moderator' }
      ]
    });
  });
  test('empty revision-matched overlay requires one row and count zero', () => {
    expect(delta.decodeDeltaSnapshot([
      { epoch: '1', baseEpoch: '1', deltaCount: '0' }
    ], { groupId, owner }).changes).toEqual([]);
    expect(() => delta.decodeDeltaSnapshot([
      { epoch: '2', baseEpoch: '1', deltaCount: '1' }
    ], { groupId, owner })).toThrow('INCOMPLETE');
  });
  test('fail closed on cross-group actor, owner elevation, double-change and bogus epochs', () => {
    const good = [row(actor(2), 'member', 'active'), row(actor(1), 'member', 'left')];
    const corruptions = [
      [row(actor(2), 'member', 'active', '4', '1', '2', anotherGroup), good[1]],
      [row(actor(2), 'owner', 'active'), good[1]],
      [row(owner, 'member', 'active'), good[1]],
      [good[0], good[0]],
      [good[0], { ...good[1], epoch: '5' }],
      [good[0], { ...good[1], baseEpoch: '5' }],
      [good[0], { ...good[1], deltaCount: '3' }],
      [good[0], { ...good[1], status: 'invited' }],
    ];
    for (const rows of corruptions) {
      expect(() => delta.decodeDeltaSnapshot(rows, { groupId, owner })).toThrow();
    }
  });
  test('bound row limit and row-count guard prevent partial or unlimited group scans', () => {
    expect(() => delta.decodeDeltaSnapshot([], { groupId, owner })).toThrow();
    expect(() => delta.decodeDeltaSnapshot([
      row(actor(1), 'member', 'active', '3', '4', '1')
    ], { groupId, owner })).toThrow();
    expect(() => delta.decodeDeltaSnapshot([
      row(actor(1), 'member', 'active', '4', '1', '513')
    ], { groupId, owner })).toThrow();
    const tooMany = Array.from({ length: 514 }, (_, i) =>
      row(actor(i), 'member', 'active', '515', '1', '513'));
    expect(() => delta.decodeDeltaSnapshot(tooMany, { groupId, owner })).toThrow();
  });
  test('delta mutation links changed member to Group without altering legacy path', () => {
    const receipt = '00000000-0000-4000-8000-000000000001';
    const params = { groupId, owner, app, member: actor(1), role: 'member',
      status: 'active', expectedEpoch: 1, receipt };
    const indexed = rdf.mutateQuery({ ...params, indexDelta: true });
    const plain = rdf.mutateQuery(params);
    expect(indexed).toContain('collectiveIndexChangedMember');
    expect(indexed).toContain('FILTER(BOUND(?wasChanged) = BOUND(?wasGroupIndexed))');
    expect(indexed).toContain('FILTER(?newDeltaCount >= 0 && ?newDeltaCount <= 512)');
    expect(plain).not.toContain('collectiveIndexChangedMember');
  });
});
