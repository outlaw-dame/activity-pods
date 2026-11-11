'use strict';

const {
  LOCAL_READY_TIMEOUT_MS,
  ONTOLOGY_PENDING_PATTERN
} = require('../scripts/patch-semapps-ldp-local-registry-bootstrap');

describe('ADSP P2 local LDP registry bootstrap readiness', () => {
  test('keeps the retry horizon bounded to the frozen recovery ceiling', () => {
    expect(LOCAL_READY_TIMEOUT_MS).toBe(30000);
  });

  test.each([
    'Could not expand all types (Note). Is an ontology missing or not registered yet on the local context ?',
    'Could not expand predicate (as:actor). Is an ontology missing or not registered yet on the local context ?',
    'No registered ontology found for resourceType https://www.w3.org/ns/activitystreams#Note'
  ])('recognizes transient ontology bootstrap state: %s', message => {
    expect(ONTOLOGY_PENDING_PATTERN.test(message)).toBe(true);
  });

  test.each([
    'Permission denied',
    'Fuseki unavailable',
    'No registered ontology found',
    'No registered ontology found for namespace https://example.invalid/'
  ])('does not retry unrelated startup failures: %s', message => {
    expect(ONTOLOGY_PENDING_PATTERN.test(message)).toBe(false);
  });
});
