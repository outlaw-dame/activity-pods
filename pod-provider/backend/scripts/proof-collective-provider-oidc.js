'use strict';

/**
 * Actual disposable Solid-OIDC authorization-code interaction.
 *
 * Exercises real native provider discovery, OIDC client registration,
 * browser-style cookies/redirects, existing user authentication through
 * /.oidc/login-completed, PKCE exchange and JOSE signature verification.
 * No synthetic issuer, mocked JWT service, or passkey-based step-up.
 *
 * The HTTP client emulates navigation to the existing frontend login screen.
 * It does not assert a Playwright-rendered user interface or Group API release.
 */
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { SignJWT, generateKeyPair, exportJWK, createRemoteJWKSet, jwtVerify } = require('jose');

const base = 'https://paper-e2e.test:3443';
const app = 'https://app-e2e.test:3443';
const callback = app + '/callback';
const timeoutMs = 30000;

function random(size = 24) { return crypto.randomBytes(size).toString('base64url'); }
function challenge(value) { return crypto.createHash('sha256').update(value).digest('base64url'); }
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));

async function response(url, options = {}) {
  return fetch(url, {
    ...options,
    redirect: 'manual',
    signal: AbortSignal.timeout(timeoutMs)
  });
}
async function json(res) {
  const raw = await res.text();
  try { return raw ? JSON.parse(raw) : null; } catch { return { text: raw.slice(0, 500) }; }
}
function ensure(res, body, expected, label) {
  if (!expected.includes(res.status)) {
    throw new Error(label + ': HTTP ' + res.status + ' ' + JSON.stringify(body).slice(0, 700));
  }
}
class CookieJar {
  constructor() { this.cookies = new Map(); }
  capture(res) {
    for (const header of res.headers.getSetCookie()) {
      const first = header.split(';', 1)[0];
      const at = first.indexOf('=');
      if (at > 0) {
        const name = first.slice(0, at);
        const val = first.slice(at + 1);
        if (!val) this.cookies.delete(name);
        else this.cookies.set(name, val);
      }
    }
  }
  async request(url, options = {}) {
    const cookie = [...this.cookies].map(([k, v]) => k + '=' + v).join('; ');
    const res = await response(url, {
      ...options,
      headers: { ...options.headers, ...(cookie ? { cookie } : {}) }
    });
    this.capture(res);
    return res;
  }
}
async function signup() {
  const password = 'G1OIDC!' + random(16);
  for (let attempt = 0; attempt < 12; attempt++) {
    const seed = crypto.randomBytes(16).toString('hex');
    const digest = crypto.createHash('sha256').update(seed).digest('hex');
    const numeric = (BigInt('0x' + digest.slice(0, 16)) % 10000000000000000n)
      .toString().padStart(16, '0');
    const username = 'p8ms' + numeric;
    const res = await response(base + '/auth/signup', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ username, email: username + '@example.invalid', password })
    });
    const data = await json(res);
    if ([200, 201].includes(res.status)) {
      assert(data?.webId && data?.token, 'Signup did not return native WebID and session');
      return { webId: data.webId, token: data.token };
    }
    // Non-idempotent signup may only be retried after explicit moderation denial.
    if (res.status !== 422 || data?.type !== 'USERNAME_NOT_ALLOWED') {
      throw new Error('Native OIDC signup failed: HTTP ' + res.status +
        ' ' + JSON.stringify(data).slice(0, 400));
    }
  }
  throw new Error('Moderation rejected all bounded username candidates');
}
async function proof(keyPair, method, uri, nonce) {
  const claims = { htm: method, htu: uri, jti: crypto.randomUUID() };
  if (nonce) claims.nonce = nonce;
  return new SignJWT(claims)
    .setProtectedHeader({ typ: 'dpop+jwt', alg: 'ES256', jwk: keyPair.publicJwk })
    .setIssuedAt(Math.floor(Date.now() / 1000))
    .sign(keyPair.privateKey);
}

async function providerDatasetQuery(dataset, query) {
  const origin = (process.env.FUSEKI_URL ||
    process.env.SEMAPPS_SPARQL_ENDPOINT || 'http://fuseki_test:3030/')
    .replace(/\/+$/u, '');
  const credentials = 'Basic ' + Buffer.from(
    (process.env.FUSEKI_USER || process.env.SEMAPPS_JENA_USER || 'admin') +
    ':' + (process.env.FUSEKI_PASSWORD || process.env.SEMAPPS_JENA_PASSWORD || 'admin')
  ).toString('base64');
  const res = await fetch(origin + '/' + encodeURIComponent(dataset) + '/query', {
    method: 'POST',
    headers: { authorization: credentials,
      'content-type': 'application/sparql-query',
      accept: 'application/sparql-results+json' },
    body: query,
    signal: AbortSignal.timeout(20000)
  });
  if (!res.ok) throw new Error('Native Pod RDF assertion query failed: HTTP ' + res.status);
  return (await res.json()).results.bindings;
}

async function main() {
  const discoveryRes = await response(base + '/.well-known/openid-configuration');
  const discovery = await json(discoveryRes);
  ensure(discoveryRes, discovery, [200], 'OIDC discovery');
  for (const field of ['issuer', 'authorization_endpoint', 'token_endpoint',
    'registration_endpoint', 'jwks_uri']) {
    assert(typeof discovery[field] === 'string', 'Missing OIDC ' + field);
  }
  const person = await signup();
  // The existing Solid-OIDC adapter recognizes dereferenceable HTTPS Client
  // ID Documents. Use the very same URI registered through native SAI.
  // Never substitute an unrelated dynamically assigned opaque client ID.
  const canonicalClientId = app + '/app';

  const verifier = random(48);
  const state = random(20);
  const nonce = random(20);
  const authorization = new URL(discovery.authorization_endpoint);
  for (const [k, v] of Object.entries({
    client_id: canonicalClientId,
    redirect_uri: callback,
    response_type: 'code',
    scope: 'openid profile webid',
    state,
    nonce,
    code_challenge: challenge(verifier),
    code_challenge_method: 'S256'
  })) authorization.searchParams.set(k, v);

  const browser = new CookieJar();
  let current = authorization.href;
  let loginInteraction, resume;
  for (let step = 0; step < 12; step++) {
    const u = new URL(current);
    if (u.pathname === '/login') {
      loginInteraction = u.searchParams.get('interaction_id');
      resume = u.searchParams.get('redirect');
      break;
    }
    const res = await browser.request(current);
    if (![301, 302, 303, 307, 308].includes(res.status)) {
      throw new Error('OIDC authorization did not redirect to native login screen: HTTP ' +
        res.status + ' ' + JSON.stringify(await json(res)).slice(0, 600));
    }
    const location = res.headers.get('location');
    if (!location) throw new Error('OIDC redirect missing Location');
    current = new URL(location, current).href;
  }
  if (!loginInteraction || !resume) {
    throw new Error('Native OIDC login interaction not reached through browser redirects');
  }

  // Existing frontend submits the authenticated local user's token to this
  // native service; there is no new Group credential issuer.
  const logged = await browser.request(base + '/.oidc/login-completed', {
    method: 'POST', headers: {
      'content-type': 'application/json',
      authorization: 'Bearer ' + person.token
    },
    body: JSON.stringify({ interactionId: loginInteraction })
  });
  const loggedBody = await json(logged);
  ensure(logged, loggedBody, [200, 201, 204], 'Native Solid-OIDC login-completed');

  current = new URL(resume, base).href;
  let code;
  for (let step = 0; step < 16; step++) {
    const u = new URL(current);
    if (u.origin === app && u.pathname === '/callback') {
      assert.equal(u.searchParams.get('state'), state, 'OIDC state mismatch');
      code = u.searchParams.get('code');
      if (!code) throw new Error('OIDC callback missing authorization code');
      break;
    }
    const res = await browser.request(current);
    if (![301, 302, 303, 307, 308].includes(res.status)) {
      throw new Error('OIDC resume did not redirect to callback: HTTP ' + res.status +
        ' ' + JSON.stringify(await json(res)).slice(0, 550));
    }
    current = new URL(res.headers.get('location'), current).href;
  }
  if (!code) throw new Error('OIDC interaction did not generate an authorization code');

  const keyPair = await generateKeyPair('ES256', { extractable: true });
  keyPair.publicJwk = await exportJWK(keyPair.publicKey);
  const tokenRequest = new URLSearchParams({
    grant_type: 'authorization_code',
    client_id: canonicalClientId,
    code,
    redirect_uri: callback,
    code_verifier: verifier
  });
  let tokens;
  for (let attempt = 0; attempt < 2; attempt++) {
    const suppliedNonce = attempt ? tokens?.nonce : null;
    const res = await response(discovery.token_endpoint, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded',
        DPoP: await proof(keyPair, 'POST', discovery.token_endpoint, suppliedNonce) },
      body: tokenRequest.toString()
    });
    const data = await json(res);
    if (res.ok) {
      tokens = data;
      break;
    }
    const challengeNonce = res.headers.get('dpop-nonce');
    if (attempt === 0 && res.status === 401 && challengeNonce) {
      tokens = { nonce: challengeNonce };
      continue;
    }
    throw new Error('Native Solid-OIDC code exchange: HTTP ' + res.status + ' ' +
      JSON.stringify(data).slice(0, 600));
  }
  assert(tokens?.id_token, 'Native Solid-OIDC did not issue an ID token');
  const keySet = createRemoteJWKSet(new URL(discovery.jwks_uri));
  const verified = await jwtVerify(tokens.id_token, keySet, {
    issuer: discovery.issuer,
    audience: canonicalClientId
  });
  assert.equal(verified.payload.webid, person.webId,
    'OIDC token WebID does not match authenticated user');
  assert.equal(verified.payload.sub, person.webId,
    'OIDC signed subject does not match authenticated user');
  assert.equal(verified.payload.azp, canonicalClientId,
    'OIDC authorized app does not match its registered client identifier');
  assert.equal(canonicalClientId, app + '/app',
    'Solid-OIDC and SAI must share one exact app URI');
  // Do not accept disjoint success from two unrelated test users: the very
  // WebID in the signed native OIDC token must grant the same canonical
  // app URI through the existing native SAI registration endpoint.
  const consent = await response(base + '/.auth-agent/register-app', {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      authorization: 'Bearer ' + person.token
    },
    body: JSON.stringify({
      appUri: canonicalClientId,
      acceptedAccessNeeds: [],
      acceptedSpecialRights: ['apods:CreateGroup', 'apods:ReadGroups', 'apods:ManageMembers']
    })
  });
  ensure(consent, await json(consent), [200, 201], 'Same-user SAI consent');
  const dataset = new URL(person.webId).pathname.split('/').filter(Boolean)[0];
  assert(/^p8ms[0-9]{16}$/u.test(dataset), 'Unexpected disposable Pod dataset');
  const authRows = await providerDatasetQuery(dataset,
    'SELECT ?right WHERE { ?authorization ' +
    '<http://www.w3.org/ns/solid/interop#grantedBy> ?principal ; ' +
    '<http://www.w3.org/ns/solid/interop#grantee> ?app ; ' +
    '<http://activitypods.org/ns/core#hasSpecialRights> ?right . ' +
    'FILTER(STR(?principal) = ' + JSON.stringify(person.webId) + ' && ' +
    'STR(?app) = ' + JSON.stringify(canonicalClientId) + ') }');
  assert(authRows.some(row =>
    row.right.value === 'http://activitypods.org/ns/core#CreateGroup'),
  'Native same-user SAI Group capability not persisted on the user Pod');
  assert(authRows.some(row =>
    row.right.value === 'http://activitypods.org/ns/core#ManageMembers'),
  'Native same-user SAI ManageMembers right not persisted on the user Pod');
  const subjectHash = crypto.createHash('sha256').update(
    JSON.stringify([person.webId, canonicalClientId, 'apods:CreateGroup'])
  ).digest('hex');
  const ledgerRows = await providerDatasetQuery('settings',
    'PREFIX apods: <http://activitypods.org/ns/core#> ' +
    'SELECT ?revision ?status ?pending WHERE { ' +
    '<urn:apods:collective-consent:' + subjectHash + '> ' +
    'apods:collectiveConsentRevision ?revision ; ' +
    'apods:collectiveConsentStatus ?status . ' +
    'OPTIONAL { <urn:apods:collective-consent:' + subjectHash + '> ' +
    'apods:collectivePendingMutation ?pending . } } LIMIT 2');
  assert.equal(ledgerRows.length, 1, 'Same-user provider consent ledger absent/ambiguous');
  assert.equal(ledgerRows[0].status.value, 'stable');
  assert(!ledgerRows[0].pending, 'Same-user SAI mutation did not finish');
  assert(Number(ledgerRows[0].revision.value) >= 2,
    'Same-user SAI registration did not advance consent revision');

  console.log(JSON.stringify({
    ok: true, proof: 'real-provider-solid-oidc-authorization-code',
    webId: person.webId,
    issuer: discovery.issuer,
    clientIdType: 'https-url',
    flow: 'native interaction cookie, PKCE, issuer JWKS verified, same-user SAI consent for exact client URI',
    caveat: 'This automates native HTTP browser interactions, not a rendered frontend/Playwright UI'
  }));
}
main().catch(error => {
  console.error('[G1 native Solid-OIDC acceptance] ' + error.message);
  process.exitCode = 1;
});
