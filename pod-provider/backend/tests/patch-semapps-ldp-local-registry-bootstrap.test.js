'use strict';

const {
  LOCAL_READY_TIMEOUT_MS,
  ONTOLOGY_PENDING_PATTERN,
  patchRegisteredContainers
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


describe('ADSP P2 registered Pod container event hardening', () => {
  const upstream = [
    "this.logger.info('Trying to register container', options.path);",
    "await ctx.call('ldp.container.createAndAttach', { containerUri: urlJoin(storageUrl, options.path), options, webId });",
    '            } catch (error) {',
    '              // pass',
    '            }'
  ].join('\n');

  test('replaces the upstream silent discard with bounded, fail-visible retries', () => {
    const first = patchRegisteredContainers(upstream);
    expect(first.changed).toBe(true);
    expect(first.source).toContain('ADSP_P2_REGISTERED_CONTAINERS_RETRY');
    expect(first.source).toContain('for (const pauseMs of [60, 180, 540])');
    expect(first.source).toContain('if (lastError) {');
    expect(first.source).toContain('throw lastError;');
    expect(first.source).not.toContain('// pass');
    expect(patchRegisteredContainers(first.source)).toEqual({source:first.source,changed:false});
  });

  test('fails closed on unexpected SemApps source instead of silently skipping', () => {
    expect(() => patchRegisteredContainers('const source = null;')).toThrow(/contract changed/);
    expect(() => patchRegisteredContainers('ADSP_P2_REGISTERED_CONTAINERS_RETRY')).toThrow(/Incomplete/);
  });
});
