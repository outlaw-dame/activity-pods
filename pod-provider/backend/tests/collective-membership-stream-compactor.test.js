'use strict';
const { stageCompactedMembership, readCompactionBaseQuery, decodeCompactionBase } =
  require('../utils/collective-membership-stream-compactor');
const index = require('../utils/collective-membership-page-index');
const groupId = 'cg_' + 'f'.repeat(32);
const owner = 'https://provider.example/users/owner';
const actor = i => 'https://a.example/users/' + String(i).padStart(7, '0');
const baseRevision = 17, membershipRevision = 21;
function base(count = 220, long = false) {
  const items = [{ actorUri: owner, role: 'owner' }];
  for (let i = 0; i < count; i++) items.push({
    actorUri: actor(i) + (long ? '/' + 'a'.repeat(850) : ''), role: 'member'
  });
  return items.sort((a, b) => a.actorUri < b.actorUri ? -1 : 1);
}
function fixture(items, changes = []) {
  const pages = [];
  let cursor = null;
  for (let start = 0; start < items.length;) {
    const pack = index.packPage({
      groupId, revision: baseRevision, cursor, members: items.slice(start, start + 101),
      sourceHasMore: start + 101 < items.length,
    });
    start += pack.consumedCount;
    pages.push(pack.page);
    cursor = pack.page.nextCursor;
  }
  const byCursor = new Map(pages.map(page => [page.cursor, page]));
  let reads = 0;
  const persisted = [];
  const inputs = {
    groupId, owner,
    deltaSnapshot: { groupId, baseRevision, membershipRevision,
      deltaCount: changes.length, changes },
    expectedBaseCount: items.length,
    async readBasePage({ groupId: asked, revision, cursor }) {
      reads++;
      expect(asked).toBe(groupId);
      expect(revision).toBe(baseRevision);
      const item = byCursor.get(cursor);
      if (!item) throw new Error('Missing verified base snapshot page');
      return { groupId, membershipRevision: baseRevision,
        members: item.members, hasMore: item.hasMore, nextCursor: item.nextCursor };
    },
    async stagePages(batch) {
      expect(batch.length).toBeGreaterThan(0);
      expect(batch.length).toBeLessThanOrEqual(20);
      for (const page of batch) {
        expect(Buffer.byteLength(page.json)).toBeLessThanOrEqual(index.MAX_PAGE_BYTES);
        expect(page.digest).toMatch(/^[0-9a-f]{64}$/);
        persisted.push(page);
      }
    }
  };
  return { inputs, persisted, pages, get reads() { return reads; } };
}
describe('G2 streaming compaction bounded memory and verified staging', () => {
  test('compactor may read old immutable base only under exact live epoch, owner and SAI fence', () => {
    const query = readCompactionBaseQuery({
      groupId, owner, app: 'https://provider.example/app',
      baseRevision, membershipRevision, cursor: null
    });
    expect(query).toContain('collectiveConsentStatus "stable"');
    expect(query).toContain('AuthAccount');
    expect(query).toContain('collectiveIndexedMembershipEpoch ?baseEpoch');
    expect(query).toContain('FILTER(xsd:integer(?epoch) = 21)');
    expect(query).toContain('FILTER(xsd:integer(?baseEpoch) = 17)');
    expect(query).not.toContain('ORDER BY');
    expect(query).not.toContain('OFFSET');
    const page = index.encodePage({
      groupId, revision: baseRevision, cursor: null, members: [
        { actorUri: owner, role: 'owner' } ], hasMore: false
    });
    const rows = [{
      epoch: { value: String(membershipRevision) },
      baseEpoch: { value: String(baseRevision) },
      pageJson: { value: page.json },
      pageDigest: { value: page.digest }
    }];
    expect(decodeCompactionBase(rows, {
      groupId, baseRevision, membershipRevision, cursor: null
    }).members).toEqual(page.members);
    expect(() => decodeCompactionBase([{...rows[0],epoch:{value:'22'}}],{
      groupId, baseRevision, membershipRevision
    })).toThrow('BASE_UNAVAILABLE');
    expect(() => decodeCompactionBase([{...rows[0],
      pageDigest:{value:'0'.repeat(64)}}],{
      groupId, baseRevision, membershipRevision
    })).toThrow();
  });
  test('stages complete immutable sorted base and preserves owner; idempotent deterministic manifest', async () => {
    const before = base();
    const fixture1 = fixture(before);
    const manifest = await stageCompactedMembership(fixture1.inputs);
    expect(manifest.memberCount).toBe(before.length);
    expect(manifest.baseMemberCount).toBe(before.length);
    expect(manifest.membershipRevision).toBe(membershipRevision);
    expect(fixture1.reads).toBe(fixture1.pages.length);
    const flattened = fixture1.persisted.flatMap(p => p.members);
    expect(flattened).toEqual(before);
    expect(fixture1.persisted.at(-1).hasMore).toBe(false);
    expect(fixture1.persisted.every((p, i) => i === 0 ||
      p.cursor === fixture1.persisted[i-1].nextCursor)).toBe(true);
    const fixture2 = fixture(before);
    expect(await stageCompactedMembership(fixture2.inputs)).toEqual(manifest);
    expect(fixture2.persisted.map(p => p.digest))
      .toEqual(fixture1.persisted.map(p => p.digest));
  });
  test('applies changed roles, removals and a new remote actor exactly once', async () => {
    const before = base();
    const changes = [
      { actorUri: actor(1), kind: 'remove' },
      { actorUri: actor(2), kind: 'upsert', role: 'moderator' },
      { actorUri: actor(99999), kind: 'upsert', role: 'member' },
    ];
    const f = fixture(before, changes);
    const manifest = await stageCompactedMembership(f.inputs);
    const rows = f.persisted.flatMap(p => p.members);
    expect(manifest.memberCount).toBe(before.length);
    expect(rows.some(x => x.actorUri === actor(1))).toBe(false);
    expect(rows.find(x => x.actorUri === actor(2)).role).toBe('moderator');
    expect(rows.some(x => x.actorUri === actor(99999))).toBe(true);
    expect(rows.filter(x => x.actorUri === owner)).toEqual([{actorUri: owner, role:'owner'}]);
  });
  test('long remote URIs produce variable 32KiB chunks without loss', async () => {
    const before = base(250, true);
    const f = fixture(before);
    const manifest = await stageCompactedMembership(f.inputs);
    expect(manifest.memberCount).toBe(before.length);
    expect(f.persisted.length).toBeGreaterThan(3);
    expect(f.persisted.flatMap(p => p.members)).toEqual(before);
  });
  test('rejects missing and inconsistent input pages; cannot publish a partial snapshot', async () => {
    const f = fixture(base());
    f.inputs.expectedBaseCount += 1;
    await expect(stageCompactedMembership(f.inputs)).rejects.toThrow('COUNT_MISMATCH');
    const g = fixture(base());
    const read = g.inputs.readBasePage;
    g.inputs.readBasePage = async params => {
      const page = await read(params);
      return params.cursor === null ? {...page, nextCursor: 'https://corrupt.example/'} : page;
    };
    await expect(stageCompactedMembership(g.inputs)).rejects.toThrow('CURSOR');
    const h = fixture(base());
    h.inputs.stagePages = async () => { throw new Error('Simulated worker SIGKILL before any acknowledgment'); };
    await expect(stageCompactedMembership(h.inputs)).rejects.toThrow('Simulated worker SIGKILL');
  });
  test('owner must occur exactly once, immutable and under the authorized owner URI', async () => {
    const missing = fixture(base().filter(x => x.actorUri !== owner));
    await expect(stageCompactedMembership(missing.inputs)).rejects.toThrow('OWNER_CORRUPT');
    const wrong = fixture([{ actorUri: 'https://actor.example/bogus', role: 'owner' },
      {actorUri: actor(0), role:'member'}].sort((a,b)=>a.actorUri < b.actorUri?-1:1));
    await expect(stageCompactedMembership(wrong.inputs)).rejects.toThrow('OWNER_CORRUPT');
    const f = fixture(base(), [{actorUri:owner,kind:'remove'}]);
    await expect(stageCompactedMembership(f.inputs)).rejects.toThrow('OWNER_IMMUTABLE');
  });
  test('10k members stage via bounded page callbacks without per-actor IO', async () => {
    const before = base(10000);
    const f = fixture(before);
    const manifest = await stageCompactedMembership(f.inputs);
    expect(manifest.memberCount).toBe(before.length);
    expect(f.reads).toBe(f.pages.length);
    expect(f.reads).toBeLessThan(110);
    expect(f.persisted.length).toBeLessThan(110);
    expect(f.persisted.flatMap(p => p.members)).toEqual(before);
  });
});
