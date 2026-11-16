import assert from 'node:assert/strict';
import { test } from 'node:test';
import { resolveLoginReturn } from './loginNavigationPolicy.mjs';

const config = { backendUrl: 'https://pods.example', frontendOrigin: 'https://pods-ui.example' };
test('keeps frontend routes and exact provider OIDC return URLs', () => {
  assert.deepEqual(resolveLoginReturn('/authorize?client_id=https%3A%2F%2Fapp.example', config),
    { mode: 'internal', url: '/authorize?client_id=https%3A%2F%2Fapp.example' });
  assert.deepEqual(resolveLoginReturn('https://pods.example/.oidc/interaction/123', config),
    { mode: 'external', url: 'https://pods.example/.oidc/interaction/123' });
});
test('rejects lookalike hosts, credentials, backslashes and unsafe schemes', () => {
  for (const value of ['https://pods.example.attacker.test/path', 'https://pods.example@attacker.test/',
    '//attacker.test', '/\\attacker.test', 'https://pods.example:444/path',
    'javascript:alert(1)', 'data:text/html,test', 'https://user:pass@pods.example/path',
    '\thttps://pods.example/path', 'https://pods.example/\npath',
    '/safe/..//attacker.test/path', '/safe/%2e%2e//attacker.test/path',
    'https://pods-ui.example//attacker.test/path']) {
    assert.deepEqual(resolveLoginReturn(value, config), { mode: 'internal', url: '/network' }, value);
  }
});
