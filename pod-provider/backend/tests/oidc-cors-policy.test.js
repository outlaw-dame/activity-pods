'use strict';
const { allowedOrigin } = require('../config/oidc-cors-policy');

const app = 'https://app.example.org';
const client = {
  redirectUris: [app + '/callback', 'https://second.example.org/path?source=oidc']
};

test('only a registered redirect origin may use the client token endpoint from a browser', () => {
  expect(allowedOrigin(app, client)).toBe(true);
  expect(allowedOrigin('https://second.example.org', client)).toBe(true);
  expect(allowedOrigin('https://attacker.example.org', client)).toBe(false);
  expect(allowedOrigin('https://app.example.org.evil.net', client)).toBe(false);
  expect(allowedOrigin('https://app.example.org:444', client)).toBe(false);
});

test('malformed and opaque browser origins are denied', () => {
  for (const origin of [
    null, undefined, '', '*', 'null', 'file://', 'https://app.example.org/',
    'https://app.example.org/path', 'https://app.example.org?x=1',
    'https://app.example.org#x', 'http://app.example.org',
    'https://user:pass@app.example.org', 'https://app.example.org@evil.net'
  ]) {
    expect(allowedOrigin(origin, client)).toBe(false);
  }
});

test('client metadata is required and cannot be used as a wildcard', () => {
  expect(allowedOrigin(app, null)).toBe(false);
  expect(allowedOrigin(app, {})).toBe(false);
  expect(allowedOrigin(app, { redirectUris: [app + '/callback', '*'] })).toBe(true);
  expect(allowedOrigin(app, { redirectUris: Array(33).fill(app + '/callback') })).toBe(false);
  expect(allowedOrigin(app, { redirectUris: ['https://other.example.org/cb'] })).toBe(false);
});

test('registered redirect URLs are compared by parsed origin, not spelling', () => {
  for (const uri of [
    'https://app.example.org',
    'https://app.example.org:443/callback',
    'https://APP.EXAMPLE.ORG/callback',
    'https://APP.EXAMPLE.ORG:443/callback?source=auth'
  ]) {
    expect(allowedOrigin(app, { redirectUris: [uri] })).toBe(true);
  }
  expect(allowedOrigin('https://attacker.example.org', {
    redirectUris: ['https://APP.EXAMPLE.ORG/callback']
  })).toBe(false);
});

test('registered redirect normalization never allows unsafe characters or origins', () => {
  for (const raw of [
    'https://app.example.org\\@evil.example/callback',
    'https://app.example.org\r\n.evil.example/callback',
    'https://app.example.org/callback#fragment',
    'https://user:pass@app.example.org/callback',
    'https://app.example.org.evil.example/callback',
    'http://app.example.org/callback',
    'https://other.example.org/callback',
    '*'
  ]) {
    expect(allowedOrigin(app, { redirectUris: [raw] })).toBe(false);
  }
});

test('localhost redirects are permitted only in explicit development mode', () => {
  const dev = { redirectUris: ['http://localhost:3000/callback'] };
  expect(allowedOrigin('http://localhost:3000', dev)).toBe(false);
  expect(allowedOrigin('http://localhost:3000', dev, { allowLocalhost: true })).toBe(true);
  expect(allowedOrigin('http://127.0.0.1:3000', dev, { allowLocalhost: true })).toBe(false);
  expect(allowedOrigin('http://10.0.0.5:3000', { redirectUris: ['http://10.0.0.5:3000/cb'] }, { allowLocalhost: true })).toBe(false);
});

test('the provider uses the policy rather than an unconditional allow-all function', () => {
  const fs = require('node:fs');
  const path = require('node:path');
  const source = fs.readFileSync(path.join(__dirname, '../services/solid/solid-oidc.js'), 'utf8');
  expect(source).toMatch(/config\.clientBasedCORS\s*=/);
  expect(source).toMatch(/allowedOrigin\(origin, client/);
  expect(source).not.toMatch(/clientBasedCORS\s*=\s*\([^)]*\)\s*=>\s*true/u);
});
