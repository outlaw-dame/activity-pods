'use strict';

const fs = require('fs');
const path = require('path');

const auth = fs.readFileSync(path.join(__dirname, '../services/core/auth.js'), 'utf8');

// A regression guard on the real signup emitter, not a replacement lifecycle
// handler. Registration consumers are distributed over separate service groups
// and must resolve the correct RDF dataset from their own WebID parameters.
describe('cross-replica Solid signup event context', () => {
  test('publishes exactly one canonical registration event with cleared routing metadata', () => {
    const emits = [...auth.matchAll(/ctx\.emit\(\s*['"]auth\.registered['"]/g)];
    expect(emits).toHaveLength(1);
    expect(auth).toMatch(
      /ctx\.emit\(\s*'auth\.registered'\s*,\s*\{\s*webId\s*,\s*profileData\s*,\s*accountData\s*\}\s*,\s*\{\s*meta:\s*\{\s*webId:\s*null\s*,\s*dataset:\s*null\s*\}\s*\}\s*\)/
    );
  });

  test('retains the actual account identity and its full completion barrier', () => {
    expect(auth).toContain("await ctx.call('auth.account.attachWebId',");
    expect(auth).toContain("callBootstrapReadiness('auth-agent.waitForResourceCreation', { webId })");
    expect(auth).toContain("callBootstrapReadiness('agent-registry.waitForResourceCreation', { webId })");
    expect(auth).toContain("callBootstrapReadiness('auth-registry.waitForResourceCreation', { webId })");
    expect(auth).toContain("callBootstrapReadiness('data-registry.waitForResourceCreation', { webId })");
    expect(auth).toContain("callBootstrapReadiness('type-indexes.awaitCreateComplete', { webId })");
  });
});
