import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  trustedAppStatusUrl,
  trustedAppAuthorizationCallback
} from './authorizationNavigationPolicy.mjs';

const provider = {
  backendUrl: 'https://pods.example.org',
  webId: 'https://pods.example.org/alice/profile/card#me',
  oidcIssuer: 'https://pods.example.org',
  appUri: 'https://memory.example.org/app#main'
};

test('builds app-status strictly from provider frontend config and URL-encodes the app URI', () => {
  assert.equal(trustedAppStatusUrl(provider),
    'https://pods.example.org/.well-known/app-status?appUri=https%3A%2F%2Fmemory.example.org%2Fapp%23main');
  assert.equal(trustedAppStatusUrl({ ...provider, oidcIssuer: undefined }),
    trustedAppStatusUrl(provider));
});

test('issuer metadata must never change the Authorization-bearing request origin', () => {
  for (const oidcIssuer of [
    'https://attacker.example', 'https://pods.example.org.evil.example',
    'https://user:secret@pods.example.org',
    'http://pods.example.org',
    'javascript:alert(1)',
    'https://pods.example.org/path?next=https://evil.example',
    'https://pods.example.org/#malicious',
    ['https://pods.example.org', 'https://evil.example'],
  ]) {
    assert.throws(
      () => trustedAppStatusUrl({ ...provider, oidcIssuer }),
      /SAI_(URL_UNTRUSTED|OIDC_ISSUER_MISMATCH)/
    );
  }
});

test('a remote WebID cannot direct the provider bearer to another Pod', () => {
  for (const webId of [
    'https://evil.example/alice#me', 'http://pods.example.org/alice#me',
    'https://user:secret@pods.example.org/alice#me',
    'file:///home/user/alice', 'https://pods.example.org.evil.example/alice#me',
  ]) {
    assert.throws(() => trustedAppStatusUrl({ ...provider, webId }), /SAI_/);
  }
});

test('provider app-status request stays at the root even with path-scoped issuer claims', () => {
  const url = trustedAppStatusUrl({
    ...provider, oidcIssuer: 'https://pods.example.org/oidc'
  });
  assert.equal(new URL(url).pathname, '/.well-known/app-status');
});

test('rejects malformed, credential-bearing and unsafe app resource identifiers', () => {
  for (const appUri of [
    'javascript:alert(1)', 'http://memory.example.org/app',
    'https://user:secret@memory.example.org/app',
    'https://memory.example.org/app\n',
    undefined,
  ]) {
    assert.throws(() => trustedAppStatusUrl({ ...provider, appUri }), /SAI_/);
  }
});

test('supports explicit loopback HTTP provider development without remote HTTP egress', () => {
  const url = trustedAppStatusUrl({
    backendUrl: 'http://localhost:3000',
    webId: 'http://localhost:3000/alice/profile/card#me',
    oidcIssuer: 'http://localhost:3000',
    appUri: 'http://localhost:3001/memory-app'
  });
  assert.equal(new URL(url).origin, 'http://localhost:3000');
  assert.equal(new URL(url).pathname, '/.well-known/app-status');
});

test('native app callback must be a canonical HTTPS URL controlled by the SAI app origin', () => {
  assert.equal(
    trustedAppAuthorizationCallback(
      'https://memory.example.org/sai/app#main',
      'https://memory.example.org/account/continue?state=a%2Bb#app'
    ),
    'https://memory.example.org/account/continue?state=a%2Bb#app'
  );
});

test('rejects callback phishing, custom schemes, credential URLs and off-origin redirects', () => {
  const app = 'https://memory.example.org/app';
  for (const callback of [
    'javascript:alert(1)',
    'http://memory.example.org/callback',
    'https://evil.example/callback',
    'https://memory.example.org.evil.example/callback',
    'https://evil.example@memory.example.org/callback',
    'https://user:secret@memory.example.org/callback',
    'https://memory.example.org/callback\r\n',
    'httpx://memory.example.org/callback',
    '//memory.example.org/callback',
    '/callback',
    '',
  ]) {
    assert.throws(() => trustedAppAuthorizationCallback(app, callback), /SAI_/);
  }
});

test('rejects callback when the claimed SAI app identifier is not a trusted URL', () => {
  assert.throws(
    () => trustedAppAuthorizationCallback('http://evil.example/app', 'https://evil.example/callback'),
    /SAI_/
  );
  assert.throws(
    () => trustedAppAuthorizationCallback('https://bad:pass@example.org/app', 'https://example.org/callback'),
    /SAI_/
  );
});
