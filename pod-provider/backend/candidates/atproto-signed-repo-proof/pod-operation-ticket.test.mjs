import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { test } from 'node:test';
import { createPodOperationTicketAuthority } from './pod-operation-ticket.mjs';
import {
  consentGuard, consentSubject, safeEpoch, readConsentQuery,
  bootstrapConsentQuery, beginRevocationQuery, parseConsentRows
} from './pod-consent-fence.mjs';

const accountId = 'https://paper.example.org/alice';
const appUri = 'https://paper.example.org/app';
const grantUri = 'https://paper.example.org/alice/data/access-grants/one';
const did = 'did:plc:' + 'a'.repeat(24);
const rootCid = 'bafyre' + 'a'.repeat(53);
const rev = '2222222222222';
const scope = Object.freeze({
  accountId, appUri, grantUri, did, epoch: '1',
  operation: 'project', rootCid, rev
});
const consent = consentSubject(accountId, appUri);

test('provider HMAC ticket is 30-second, operation and exact immutable-head scoped', () => {
  let now = 10_000_000;
  const secret = crypto.randomBytes(32);
  const authority = createPodOperationTicketAuthority({ secret, now: () => now });
  const signed = authority.issue(scope);
  assert.equal(authority.verify(signed, scope).accountId, accountId);
  for(const mismatch of [
    { ...scope, rootCid: 'bafyre' + 'b'.repeat(53) },
    { ...scope, rev: '3333333333333' },
    { ...scope, epoch: '2' },
    { ...scope, operation: 'revoke', rootCid: null, rev: null },
    { ...scope, appUri: 'https://evil.example/app' },
    { ...scope, grantUri: 'https://evil.example/grant' },
    { ...scope, did: 'did:plc:' + 'b'.repeat(24) }
  ]) {
    assert.throws(() => authority.verify(signed, mismatch),
      e => e.code === 'POD_PROJECTION_PROVIDER_UNAUTHORIZED');
  }
  const tampered = signed.slice(0,-1) + (signed.endsWith('A') ? 'B' : 'A');
  assert.throws(() => authority.verify(tampered, scope), e =>
    e.code === 'POD_PROJECTION_PROVIDER_UNAUTHORIZED');
  now += 30001;
  assert.throws(() => authority.verify(signed, scope), e =>
    e.code === 'POD_PROJECTION_PROVIDER_UNAUTHORIZED');
  assert.throws(() => createPodOperationTicketAuthority({ secret: 'short' }), /Missing or invalid/);
});

test('per-Pod grant fence uses exact grant, epoch and active revision; revocation increments', () => {
  const guard = consentGuard({ subjectUri: consent, grantUri, revision: '1' });
  assert.match(guard, /FILTER EXISTS/);
  assert.match(guard, /repoConsentStatus "active"/);
  assert.match(guard, /repoConsentRevision "1"\^\^xsd:integer/);
  assert.match(readConsentQuery({ subjectUri: consent }), /LIMIT 3/);
  assert.match(bootstrapConsentQuery({ subjectUri: consent, grantUri }), /FILTER NOT EXISTS/);
  const blocked = beginRevocationQuery({ subjectUri: consent, grantUri, revision: '1' });
  assert.match(blocked, /repoConsentStatus "blocked"/);
  assert.match(blocked, /repoConsentRevision "2"\^\^xsd:integer/);
  assert.throws(() => safeEpoch('9223372036854775808'), /Invalid SAI consent revision/);
  assert.throws(() => safeEpoch('01'), /Invalid SAI consent revision/);
  assert.throws(() => beginRevocationQuery({
    subjectUri: consent, grantUri, revision: '9223372036854775807'
  }), /Consent epoch exhausted/);
  assert.throws(() => consentGuard({
    subjectUri: consent + '> } UNION {', grantUri, revision: '1'
  }), /Invalid/);
});

test('duplicate, ambiguous, changed-grant and malformed RDF permission state fails closed', () => {
  const row = {
    status: { value: 'active' }, revision: { value: '1' },
    grant: { value: grantUri }
  };
  assert.equal(parseConsentRows([row], { grantUri }).revision, '1');
  for(const rows of [[], [row, row], [{ ...row, grant: { value: 'https://evil.example/grant' } }]]) {
    assert.throws(() => parseConsentRows(rows, { grantUri }));
  }
  assert.throws(() => parseConsentRows([
    { ...row, revision: { value: 'not-a-number' } }
  ], { grantUri }));
});
