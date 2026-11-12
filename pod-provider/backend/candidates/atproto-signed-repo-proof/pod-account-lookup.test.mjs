import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  buildCanonicalPodAccountLookup, parseCanonicalPodAccount
} from './pod-account-lookup.mjs';

const webId = 'https://paper.example.org/alice';
const valid = {
  account: { type: 'uri', value: 'urn:AuthAccount:123e4567-e89b-42d3-a456-426614174000' },
  username: { type: 'literal', value: 'alice' }
};
test('canonical per-Pod account lookup is targeted, bounds ambiguity at two and never CONSTRUCTs full RDF', () => {
  const q = buildCanonicalPodAccountLookup(webId);
  assert.match(q, /SELECT \?account \?username/);
  assert.match(q, /semapps:AuthAccount/);
  assert.match(q, /semapps:webId "https:\/\/paper.example.org\/alice"/);
  assert.match(q, /LIMIT 2$/);
  assert.doesNotMatch(q, /CONSTRUCT|OFFSET|SELECT \*/);
  assert.equal(parseCanonicalPodAccount([valid], webId).username, 'alice');
});
test('ambiguous, absent and malformed canonical account results cannot select an owner', () => {
  for (const rows of [[], [valid, valid], null, [
    { account: { value: 'urn:evil:alice' }, username: { value: 'alice' } }
  ], [
    { account: valid.account, username: { value: '../../malicious' } }
  ]]) {
    assert.throws(() => parseCanonicalPodAccount(rows, webId),
      error => error.code === 'POD_PROJECTION_OWNER_UNKNOWN');
  }
});
test('SPARQL injection and forged WebID location are refused', () => {
  for (const bad of [
    'https://paper.example.org/alice" } UNION { ?s ?p ?o }',
    'https://paper.example.org/alice#me',
    'https://paper.example.org/alice?x=y',
    'http://paper.example.org/alice',
    'https://admin@paper.example.org/alice'
  ]) {
    assert.throws(() => buildCanonicalPodAccountLookup(bad),
      error => error.code === 'POD_PROJECTION_OWNER_UNKNOWN');
  }
});
