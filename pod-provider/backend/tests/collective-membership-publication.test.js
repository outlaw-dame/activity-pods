'use strict';
const pub = require('../utils/collective-membership-publication');
const groupId = 'cg_' + 'a'.repeat(32);
const owner = 'https://provider.example/users/owner';
const app = 'https://provider.example/app';
const manifest = Object.freeze({
  schema: 'paper.groups.compaction-manifest.v1',
  groupId, baseRevision: 2, membershipRevision: 5,
  baseMemberCount: 300, memberCount: 301, pageCount: 4,
  digest: 'a'.repeat(64)
});
describe('G2 sealed index publication authority', () => {
  test('sealing requires exact live epoch, old index, owner and consent', () => {
    const q = pub.sealManifestQuery({ groupId, owner, app, manifest });
    expect(q).toContain('FILTER(xsd:integer(?epoch) = 5)');
    expect(q).toContain('FILTER(xsd:integer(?activeBase) = 2)');
    expect(q).toContain('collectiveConsentStatus "stable"');
    expect(q).toContain('AuthAccount');
    expect(q).toContain('FILTER NOT EXISTS');
    expect(q).not.toContain('ORDER BY');
    expect(q).not.toContain('SERVICE');
  });
  test('conditional publication checks sealed digest and exact old/new versions', () => {
    const q = pub.publishSealedManifestQuery({ groupId, owner, app, manifest });
    expect(q).toContain('collectiveManifestDigest "' + manifest.digest + '"');
    expect(q).toContain('FILTER(xsd:integer(?epoch) = 5)');
    expect(q).toContain('FILTER(xsd:integer(?previousBase) = 2)');
    expect(q).toContain('collectiveIndexChangedMember ?changedMember');
    expect(q).toContain('collectiveIndexDeltaCount "0"^^xsd:integer');
    expect(q).toContain('collectiveManifestPublished true');
    expect(q).toContain('collectiveConsentStatus "stable"');
    expect(q).not.toContain('ORDER BY');
    expect(q).not.toContain('OFFSET');
  });
  test('receipt readback has the same owner, account, consent and epoch conditions', () => {
    const q = pub.readPublicationQuery({ groupId, owner, app, manifest });
    expect(q).toContain('collectiveManifestPublished true');
    expect(q).toContain('collectiveManifestDigest "' + manifest.digest + '"');
    expect(q).toContain('collectiveIndexedMembershipEpoch ?epoch');
    expect(q).toContain('collectiveConsentStatus "stable"');
    expect(q).toContain('LIMIT 2');
  });
  test('invalid identity, group or malformed manifest cannot seal or publish', () => {
    for (const broken of [
      { ...manifest, membershipRevision: 1 },
      { ...manifest, pageCount: 0 },
      { ...manifest, pageCount: 10001 },
      { ...manifest, digest: 'not-a-digest' },
      { ...manifest, memberCount: -1 },
      { ...manifest, groupId: 'cg_' + 'f'.repeat(32) },
      { ...manifest, schema: 'other' }
    ]) {
      expect(() => pub.sealManifestQuery({ groupId, owner, app, manifest: broken })).toThrow();
      expect(() => pub.publishSealedManifestQuery({
        groupId, owner, app, manifest: broken
      })).toThrow();
    }
  });
  test('one group and epoch have a single deterministic manifest IRI', () => {
    const a = pub.subject(groupId, 5);
    expect(a).toBe(pub.subject(groupId, 5));
    expect(a).not.toBe(pub.subject(groupId, 6));
    expect(a).not.toBe(pub.subject('cg_' + 'e'.repeat(32), 5));
  });
});
