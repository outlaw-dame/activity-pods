'use strict';

const assert = require('node:assert/strict');
const { randomBytes, createHash } = require('node:crypto');
const { createRequire } = require('node:module');
const backend = createRequire(require.resolve('../../pod-provider/backend/package.json'));
const { createLocalSignupApp } = backend('./candidates/local-signup-app');

const origin = 'https://paper.example.org';
const random = () => randomBytes(32).toString('base64url');

// Real loopback services only. The operator owns the invitation key and worker
// credentials. Neither enters the browser. CI's isolated UI test is check.cjs.
async function verifyLocalBrowserSignup({ browser, issueInvitation, finishProvisioning }) {
  if (process.env.NODE_ENV !== 'test' || process.env.PAPER_BROWSER_ENROLLMENT_DISPOSABLE !== 'confirmed') {
    throw Error('Disposable signup environment required');
  }
  const app = createLocalSignupApp();
  const username = 'claimtest-' + randomBytes(5).toString('hex');
  const email = username + '@example.test';
  const password = random();
  const verifier = random();
  const state = random();
  const nonce = random();
  const request = async (url, options = {}) => {
    assert.equal(new URL(url).origin, origin);
    const response = await fetch(url, { ...options, redirect: 'error', signal: AbortSignal.timeout(8000) });
    assert.equal(response.status, 200);
    return response.json();
  };
  const discovery = await request(origin + '/.oidc/auth/.well-known/openid-configuration');
  assert.equal(discovery.issuer, origin + '/');
  const start = new URL(discovery.authorization_endpoint);
  assert.equal(start.origin, origin);
  start.search = new URLSearchParams({
    client_id: app.appUri, redirect_uri: app.returnUri, response_type: 'code', scope: 'openid webid',
    is_signup: 'true', nonce, state, code_challenge_method: 'S256',
    code_challenge: createHash('sha256').update(verifier).digest('base64url')
  });

  const page = await browser.newPage();
  try {
    await page.goto(start.href);
    const form = new URL(page.url());
    assert.equal(form.origin + form.pathname, origin + '/login');
    const interaction = form.searchParams.get('interaction_id');
    assert.ok(interaction);
    await page.getByPlaceholder('username').fill(username);
    await page.getByLabel('E-Mail').fill(email);
    await page.getByLabel('Password', { exact: true }).fill(password);
    await page.getByLabel('Local signup invitation').fill(await issueInvitation({ username, email }));
    const [created] = await Promise.all([
      page.waitForResponse(r => r.url() === origin + '/api/accounts/create', { timeout: 140000 }),
      page.locator('button[type=submit]').click()
    ]);
    assert.equal(created.status(), 202);
    await page.getByRole('button', { name: 'Allow access' }).click();
    await page.getByText('Your consent was recorded.', { exact: false }).waitFor();
    await finishProvisioning({ username, webId: origin + '/' + username });
    await page.getByRole('link', { name: 'Continue to sign in' }).click({ timeout: 30000 });
    await page.getByRole('textbox', { name: 'Username or E-Mail' }).fill(username);
    assert.equal(new URL(page.url()).searchParams.get('interaction_id'), interaction);
    await page.getByLabel('Password', { exact: true }).fill(password);
    await Promise.all([
      page.waitForURL(u => u.origin + u.pathname === app.returnUri, { timeout: 20000 }),
      page.locator('button[type=submit]').click()
    ]);
    const callback = new URL(page.url());
    assert.equal(callback.searchParams.get('state'), state);
    const code = callback.searchParams.get('code');
    assert.ok(code && !callback.searchParams.has('error'));
    const tokens = await request(discovery.token_endpoint, {
      method: 'POST',
      body: new URLSearchParams({ client_id: app.appUri, grant_type: 'authorization_code',
        redirect_uri: app.returnUri, code, code_verifier: verifier })
    });
    const { jwtVerify, createLocalJWKSet } = backend('jose');
    const { payload } = await jwtVerify(tokens.id_token, createLocalJWKSet(await request(discovery.jwks_uri)), {
      issuer: discovery.issuer, audience: app.appUri, algorithms: ['ES256']
    });
    assert.equal(payload.nonce, nonce);
    assert.equal(payload.sub, origin + '/' + username);
    assert.equal(payload.webid, payload.sub);
  } finally {
    await page.close();
  }
}

module.exports = { verifyLocalBrowserSignup };
