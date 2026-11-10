'use strict';

/**
 * Non-activated, provider-only two-step manifest publication contract.
 *
 * An authenticated worker must first verify every persisted immutable page
 * with verifyStagedCompactionManifest(). Only then may it seal that exact
 * digest/size/revision as a durable TDB2 record. Publication is one
 * authorization- and membership-epoch-fenced Fuseki UPDATE.
 *
 * This does not implement a worker, a lease, a registry or garbage
 * collection. Do not use it to activate Groups until multi-writer tests
 * prove the actual integration and publication receipt behavior.
 */
const rdf = require('./collective-membership-rdf');
const { MAX_BASE_PAGES } = require('./collective-membership-stream-compactor');

const NS = 'http://activitypods.org/ns/core#';
const XSD = 'http://www.w3.org/2001/XMLSchema#';
function fail(code) { throw new TypeError(code); }
function verifyManifest(manifest, expectedGroupId) {
  rdf.validateId(expectedGroupId);
  if (!manifest || manifest.schema !== 'paper.groups.compaction-manifest.v1' ||
      manifest.groupId !== expectedGroupId ||
      !Number.isSafeInteger(manifest.baseRevision) || manifest.baseRevision < 1 ||
      !Number.isSafeInteger(manifest.membershipRevision) ||
      manifest.membershipRevision < manifest.baseRevision ||
      !Number.isSafeInteger(manifest.pageCount) ||
      manifest.pageCount < 1 || manifest.pageCount > MAX_BASE_PAGES ||
      !Number.isSafeInteger(manifest.memberCount) || manifest.memberCount < 1 ||
      !Number.isSafeInteger(manifest.baseMemberCount) ||
      manifest.baseMemberCount < 1 ||
      !/^[0-9a-f]{64}$/u.test(manifest.digest)) {
    fail('GROUP_MANIFEST_INVALID');
  }
  return manifest;
}
function subject(groupId, epoch) {
  rdf.validateId(groupId);
  if (!Number.isSafeInteger(epoch) || epoch < 1) fail('GROUP_MANIFEST_EPOCH');
  // The manifest has a stable subject for one group/epoch. Conflicting
  // publishers cannot create alternate committed manifests for that epoch.
  return '<urn:apods:collective-index-manifest:' + groupId + ':' + epoch + '>';
}
function authorizedWhere(groupId, owner, app) {
  const base = rdf.readEpochQuery({ groupId, owner, app });
  const start = base.indexOf('WHERE {');
  if (start === -1 || !base.endsWith('} LIMIT 2')) fail('GROUP_AUTHORITY_TEMPLATE_DRIFT');
  return base.slice(start + 7, -9);
}
function sealManifestQuery({ groupId, owner, app, manifest }) {
  const m = verifyManifest(manifest, groupId);
  const g = rdf.groupSubject(groupId);
  const s = subject(groupId, m.membershipRevision);
  const where = authorizedWhere(groupId, owner, app);
  return 'PREFIX apods: <' + NS + '> PREFIX xsd: <' + XSD + '> ' +
    'INSERT { ' + s + ' a apods:CollectiveCompactionManifestV1 ; ' +
      'apods:collectiveManifestDigest ' + JSON.stringify(m.digest) + ' ; ' +
      'apods:collectiveManifestPages "' + m.pageCount + '"^^xsd:integer ; ' +
      'apods:collectiveManifestMembers "' + m.memberCount + '"^^xsd:integer ; ' +
      'apods:collectiveManifestBaseRevision "' + m.baseRevision + '"^^xsd:integer . } ' +
    'WHERE { ' + where +
      'FILTER(xsd:integer(?epoch) = ' + m.membershipRevision + ') ' +
      g + ' apods:collectiveIndexedMembershipEpoch ?activeBase . ' +
      'FILTER(xsd:integer(?activeBase) = ' + m.baseRevision + ') ' +
      'FILTER NOT EXISTS { ' + s + ' ?existingPredicate ?existingValue . } }';
}
function publishSealedManifestQuery({ groupId, owner, app, manifest }) {
  const m = verifyManifest(manifest, groupId);
  const g = rdf.groupSubject(groupId);
  const s = subject(groupId, m.membershipRevision);
  const where = authorizedWhere(groupId, owner, app);
  // This is a single TDB2 transaction. An intervening member mutation
  // invalidates ?epoch and prevents pointer publication or delta reset.
  // No broad scan: only the Group's own <=512 changedMember links.
  return 'PREFIX apods: <' + NS + '> PREFIX xsd: <' + XSD + '> ' +
    'DELETE { ' + g + ' apods:collectiveIndexedMembershipEpoch ?previousBase ; ' +
      'apods:collectiveIndexDeltaCount ?oldCount ; ' +
      'apods:collectiveIndexChangedMember ?changedMember . ' +
      '?changedMember apods:collectiveChangedSinceIndex true . } ' +
    'INSERT { ' + g + ' apods:collectiveIndexedMembershipEpoch ?epoch ; ' +
      'apods:collectiveIndexDeltaCount "0"^^xsd:integer . ' +
      s + ' apods:collectiveManifestPublished true . } ' +
    'WHERE { ' + where +
      'FILTER(xsd:integer(?epoch) = ' + m.membershipRevision + ') ' +
      g + ' apods:collectiveIndexedMembershipEpoch ?previousBase ; ' +
      'apods:collectiveIndexDeltaCount ?oldCount . ' +
      'FILTER(xsd:integer(?previousBase) = ' + m.baseRevision + ') ' +
      'FILTER(xsd:integer(?oldCount) >= 0 && xsd:integer(?oldCount) <= 512) ' +
      s + ' a apods:CollectiveCompactionManifestV1 ; ' +
      'apods:collectiveManifestDigest ' + JSON.stringify(m.digest) + ' ; ' +
      'apods:collectiveManifestPages "' + m.pageCount + '"^^xsd:integer ; ' +
      'apods:collectiveManifestMembers "' + m.memberCount + '"^^xsd:integer ; ' +
      'apods:collectiveManifestBaseRevision "' + m.baseRevision + '"^^xsd:integer . ' +
      'FILTER NOT EXISTS { ' + s + ' apods:collectiveManifestPublished true . } ' +
      'OPTIONAL { ' + g + ' apods:collectiveIndexChangedMember ?changedMember . ' +
        '?changedMember apods:collectiveMemberGroup ' + JSON.stringify(groupId) +
        ' ; apods:collectiveChangedSinceIndex true . } }';
}
function readPublicationQuery({ groupId, owner, app, manifest }) {
  const m = verifyManifest(manifest, groupId);
  const g = rdf.groupSubject(groupId);
  const s = subject(groupId, m.membershipRevision);
  const where = authorizedWhere(groupId, owner, app);
  return 'PREFIX apods: <' + NS + '> PREFIX xsd: <' + XSD + '> ' +
    'SELECT ?epoch WHERE { ' + where +
    'FILTER(xsd:integer(?epoch) = ' + m.membershipRevision + ') ' +
    g + ' apods:collectiveIndexedMembershipEpoch ?epoch ; ' +
    'apods:collectiveIndexDeltaCount "0"^^xsd:integer . ' +
    s + ' apods:collectiveManifestDigest ' + JSON.stringify(m.digest) + ' ; ' +
    'apods:collectiveManifestPublished true . } LIMIT 2';
}
module.exports = Object.freeze({
  verifyManifest, subject, sealManifestQuery,
  publishSealedManifestQuery, readPublicationQuery
});
