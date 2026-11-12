'use strict';

const fs = require('node:fs');
const path = require('node:path');

test('direct SAI deletion calls retain the authenticated Moleculer parent context', () => {
  const services = ['access-authorizations', 'data-authorizations'];
  let inspected = 0;
  for (const service of services) {
    const file = path.join(__dirname, '../services/sai', service + '.js');
    const source = fs.readFileSync(file, 'utf8');
    const calls = Array.from(source.matchAll(/await this\.actions\.delete\(/gu));
    expect(calls.length).toBeGreaterThan(0);
    for (const call of calls) {
      const end = source.indexOf(');', call.index);
      expect(end).toBeGreaterThan(call.index);
      const argumentsSource = source.slice(call.index, end);
      expect(argumentsSource).toContain('{ parentCtx: ctx }');
      inspected++;
    }
  }
  expect(inspected).toBe(4);
});

test('native owner scope is registered only at the authenticated SAI action boundary', () => {
  const source = fs.readFileSync(
    path.join(__dirname, '../services/sai/auth-agent.js'), 'utf8'
  );
  const matches = source.match(/authorizeOwnerSaiAction\(ctx, \{ owner: webId, app: appUri \}\)/gu);
  expect(matches).toHaveLength(3);
  expect(source.match(/releaseOwnerContext\(\)/gu)).toHaveLength(3);
});
