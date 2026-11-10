'use strict';

/**
 * Actual Pod provider HTTP acceptance check: signup, the provider's normal
 * SAI registration/upgrade/removal endpoints, and Fuseki's persisted datasets.
 * Uses a disposable HTTPS proxy + a real remote JSON-LD app document.
 *
 * The Pod provider is NOT mocked. Solid-OIDC discovery is checked, but this
 * proof uses the signup session token for the three SAI HTTP requests; it
 * does not yet establish the full Solid-OIDC authorization-code ceremony.
 */
const assert = require('node:assert/strict');
const crypto = require('node:crypto');

const provider = 'https://paper-e2e.test:3443';
const application = 'https://app-e2e.test:3443/app';
const fuseki = process.env.FUSEKI_URL || 'http://127.0.0.1:3040';
const admin = 'Basic ' + Buffer.from(
  (process.env.FUSEKI_USER || 'admin') + ':' + (process.env.FUSEKI_PASSWORD || 'admin')
).toString('base64');

async function api(url, { method = 'GET', body, token } = {}) {
  const res = await fetch(url, {
    method, redirect: 'manual',
    headers: {
      ...(body ? { 'content-type': 'application/json' } : {}),
      ...(token ? { authorization: 'Bearer ' + token } : {})
    },
    body: body ? JSON.stringify(body) : undefined,
    signal: AbortSignal.timeout(60000)
  });
  const txt = await res.text();
  let data;
  try { data = txt ? JSON.parse(txt) : null; } catch { data = txt.slice(0, 700); }
  return { status: res.status, data, headers: res.headers };
}
async function query(dataset, sparql) {
  const response = await fetch(fuseki.replace(/\/$/u, '') + '/' + encodeURIComponent(dataset) + '/query', {
    method: 'POST',
    headers: { authorization: admin,
      'content-type': 'application/sparql-query',
      accept: 'application/sparql-results+json' },
    body: sparql,
    signal: AbortSignal.timeout(20000)
  });
  const text = await response.text();
  if (!response.ok) throw new Error('SPARQL query failed (' + response.status + '): ' + text.slice(0, 450));
  return JSON.parse(text).results.bindings;
}
async function ledger(principal) {
  const hash = crypto.createHash('sha256')
    .update(JSON.stringify([principal, application, 'apods:CreateGroup']))
    .digest('hex');
  const subject = '<urn:apods:collective-consent:' + hash + '>';
  const rows = await query('settings',
    'PREFIX apods: <http://activitypods.org/ns/core#> ' +
    'SELECT ?rev ?status ?pending WHERE { ' + subject +
    ' apods:collectiveConsentRevision ?rev ; apods:collectiveConsentStatus ?status . ' +
    'OPTIONAL { ' + subject + ' apods:collectivePendingMutation ?pending . } }');
  assert(rows.length >= 1, 'Consent revision ledger missing');
  assert(rows.every(r => !r.pending), 'Pending SAI mutation remains after completed HTTP operation');
  assert(rows.every(r => r.status.value === 'stable'), 'Consent revision ledger must be stable');
  return Number(rows[0].rev.value);
}
async function authorizationRows(username, principal) {
  const prefix = 'http://www.w3.org/ns/solid/interop#';
  const ns = 'http://activitypods.org/ns/core#';
  return query(username,
    'SELECT ?resource ?right WHERE { ?resource <' + prefix + 'grantedBy> ?person ; ' +
    '<' + prefix + 'grantee> ?app ; <' + ns + 'hasSpecialRights> ?right . ' +
    'FILTER(STR(?person) = ' + JSON.stringify(principal) + ' && ' +
    'STR(?app) = ' + JSON.stringify(application) + ') }');
}
async function registrationRows(username, principal) {
  const ns = 'http://www.w3.org/ns/solid/interop#';
  return query(username,
    'SELECT ?resource WHERE { ?resource <' + ns + 'registeredBy> ?person ; ' +
    '<' + ns + 'registeredAgent> ?app . FILTER(STR(?person) = ' +
    JSON.stringify(principal) + ' && STR(?app) = ' +
    JSON.stringify(application) + ') }');
}
async function doSai(path, token, acceptedSpecialRights) {
  const res = await api(provider + '/.auth-agent/' + path, {
    method: 'POST', token, body: {
      appUri: application,
      ...(acceptedSpecialRights === null ? {} :
        { acceptedAccessNeeds: [], acceptedSpecialRights })
    }
  });
  if (res.status < 200 || res.status >= 300) {
    throw new Error('SAI ' + path + ': HTTP ' + res.status + ' ' +
      JSON.stringify(res.data).slice(0, 1100));
  }
  return res.data;
}
async function main() {
  assert.equal(process.env.PROVIDER_COLLECTIVES_CONSENT_BRIDGE_ENABLED, 'true',
    'The disposable Pod-provider backend must start with the SAI bridge enabled');
  // The Solid-OIDC service dynamically registers its routes after initializing
  // the provider and loading JWKs. Readiness of "/" is not OIDC readiness.
  const deadline = Date.now() + 150000;
  let discovery;
  do {
    try {
      discovery = await api(provider + '/.well-known/openid-configuration');
      if (discovery.status === 200 && discovery.data?.issuer) break;
    } catch (error) {
      if (Date.now() >= deadline) throw error;
    }
    if (Date.now() >= deadline) {
      throw new Error('Native Solid-OIDC discovery did not become ready: HTTP ' +
        (discovery?.status ?? 'network error') + ' ' +
        JSON.stringify(discovery?.data).slice(0, 650));
    }
    await new Promise(resolve => setTimeout(resolve, 2000));
  } while (true);
  assert(discovery.data.issuer, 'Native Solid-OIDC discovery missing issuer');
  // Match the proven, moderation-compatible Phase 8 username shape. Only a
  // definitive 422 USERNAME_NOT_ALLOWED may be retried; signup 5xx/timeouts
  // are ambiguous and must never be replayed.
  const password = 'G1Test!' + crypto.randomBytes(12).toString('hex');
  let signup, username;
  for (let attempt = 0; attempt < 12; attempt++) {
    const seed = crypto.randomBytes(16).toString('hex');
    const digest = crypto.createHash('sha256').update(seed).digest('hex');
    const digits = (BigInt('0x' + digest.slice(0, 16)) % 10000000000000000n)
      .toString().padStart(16, '0');
    username = 'p8ms' + digits;
    signup = await api(provider + '/auth/signup', {
      method: 'POST', body: {
        username, email: username + '@example.invalid', password
      }
    });
    if (signup.status === 200 || signup.status === 201) break;
    if (signup.status !== 422 || signup.data?.type !== 'USERNAME_NOT_ALLOWED') {
      throw new Error('Native Pod signup failed ambiguously/unexpectedly: HTTP ' +
        signup.status + ' ' + JSON.stringify(signup.data).slice(0, 650));
    }
  }
  if (signup.status !== 200 && signup.status !== 201) {
    throw new Error('Native Pod signup failed: HTTP ' + signup.status + ' ' +
      JSON.stringify(signup.data).slice(0, 1500));
  }
  const { token, webId } = signup.data || {};
  assert(token && webId && webId.startsWith(provider + '/'), 'Signup did not return HTTPS WebID and token');
  const before = await registrationRows(username, webId);
  assert.equal(before.length, 0, 'Unexpected app registration before consent');

  await doSai('register-app', token, ['apods:CreateGroup', 'apods:ReadGroups']);
  const reg = await registrationRows(username, webId);
  assert.equal(reg.length, 1, 'Native SAI registration not persisted on Pod');
  const rights = await authorizationRows(username, webId);
  if (!rights.some(row => row.right.value === 'http://activitypods.org/ns/core#CreateGroup')) {
    // Only print synthetic CI Pod graph statements. Never print credentials,
    // session tokens, password hashes or unrelated user profile data.
    const debug = await query(username,
      'SELECT ?subject ?predicate ?object WHERE { ?subject ?predicate ?object . ' +
      'FILTER(' +
      'CONTAINS(LCASE(STR(?predicate)), "specialrights") || ' +
      'CONTAINS(LCASE(STR(?predicate)), "grantedby") || ' +
      'CONTAINS(LCASE(STR(?predicate)), "grantee") || ' +
      'CONTAINS(LCASE(STR(?predicate)), "hasaccessneedgroup")' +
      ') } LIMIT 50');
    const current = await query('settings',
      'PREFIX apods: <http://activitypods.org/ns/core#> ' +
      'SELECT ?r ?status WHERE { ?s apods:collectiveConsentRevision ?r ; ' +
      'apods:collectiveConsentStatus ?status . } LIMIT 10');
    console.error('[G1 SAI diagnostics] ' + JSON.stringify({
      matchingPodStatements: debug.map(row => ({
        subject: row.subject.value, predicate: row.predicate.value, object: row.object.value
      })),
      ledger: current.map(row => [row.r.value, row.status.value])
    }));
    throw new Error('Native SAI CreateGroup authorization not persisted');
  }
  const revision1 = await ledger(webId);
  assert(revision1 >= 2, 'Expected registration and grant mutation revisions');

  await doSai('upgrade-app', token, []);
  assert.equal((await authorizationRows(username, webId)).length, 0,
    'Upgrade denying Group rights must remove original SAI authorization');
  const revision2 = await ledger(webId);
  assert(revision2 > revision1, 'Revoke must advance ledger revision');

  await doSai('upgrade-app', token, ['apods:CreateGroup', 'apods:ReadGroups']);
  assert((await authorizationRows(username, webId)).some(x => x.right.value === 'http://activitypods.org/ns/core#CreateGroup'),
    'Regrant did not persist SAI CreateGroup right');
  const revision3 = await ledger(webId);
  assert(revision3 > revision2, 'Regrant must advance ledger revision');

  await doSai('remove-app', token, null);
  assert.equal((await authorizationRows(username, webId)).length, 0,
    'Unregister must delete all Group rights');
  assert.equal((await registrationRows(username, webId)).length, 0,
    'Unregister must delete app registration');
  const revision4 = await ledger(webId);
  assert(revision4 > revision3, 'Unregister must advance ledger revision');

  console.log(JSON.stringify({
    ok: true,
    proof: 'real-provider-https-sai-http-persistence',
    webId, // Public test-only WebID; never print token/password
    registrationRevisions: [revision1, revision2, revision3, revision4],
    issuer: discovery.data.issuer,
    caveat: 'Native Solid-OIDC discovery and session signup; full authorization-code browser ceremony not included'
  }));
}
main().catch(error => {
  console.error('[G1 provider HTTP acceptance] ' + error.message);
  process.exitCode = 1;
});
