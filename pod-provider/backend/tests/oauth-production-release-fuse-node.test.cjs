'use strict';
const assert = require('node:assert/strict');
const test = require('node:test');

// The native provider config needs these nonsecret values without loading a
// developer's .env. The test never uses production accounts or credentials.
process.env.SEMAPPS_AVAILABLE_LOCALES ||= 'en';
process.env.SEMAPPS_AUTH_RESERVED_USER_NAMES ||= 'admin,root';

const pgEpoch = require('../utils/oauth-pg-epoch-policy');
const oauthToken = require('../services/oauth/oauth-token.service');
const oauthAuthorization = require('../services/oauth/oauth-authorization.service');
const oauthConsent = require('../services/oauth/oauth-consent.service');
const oauthCode = require('../services/oauth/oauth-code-store.service');
const oauthRefresh = require('../services/oauth/oauth-refresh-session.service');
const { generateKeyPair, exportJWK, SignJWT } = require('jose');

const OWNER = 'https://paper.example.org/users/fuse-proof';
const CLIENT = 'https://client.example.org/oauth';
const GRANT = 'x'.repeat(32);
const SCOPE = 'atproto repo:app.bsky.feed.post?action=create';
const FLAGS = [
  'NODE_ENV', 'PAPER_OAUTH_PG_EPOCH_DISPOSABLE',
  'PAPER_OAUTH_PG_RESTORE_DISPOSABLE',
  'PAPER_OAUTH_EPOCH_REDIS_DISPOSABLE',
  'PAPER_OAUTH_WITNESS_DISPOSABLE'
];

async function withEnvironment(patch, fn) {
  const saved = new Map(FLAGS.map(k => [k, process.env[k]]));
  try {
    for (const k of FLAGS) {
      if (patch[k] === undefined) delete process.env[k];
      else process.env[k] = patch[k];
    }
    return await fn();
  } finally {
    for (const [k, v] of saved) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  }
}
function closed(error) {
  return error?.code === 503 && error?.type === 'PDS_OAUTH_RELEASE_GATE_CLOSED';
}
function noCall() {
  assert.fail('A protected authorization action was invoked after closed gate');
}
const AUTHORIZATION = { canonicalAccountId: OWNER, clientId: CLIENT,
  scope: SCOPE, consentGrantId: GRANT };

test('production and development cannot enable the Redis-only PDS OAuth issuer', async () => {
  for (const mode of ['production', 'development']) {
    for (const overrides of [
      { NODE_ENV: mode },
      {
        NODE_ENV: mode,
        PAPER_OAUTH_PG_EPOCH_DISPOSABLE: 'confirmed',
        PAPER_OAUTH_PG_RESTORE_DISPOSABLE: 'confirmed',
        PAPER_OAUTH_EPOCH_REDIS_DISPOSABLE: 'confirmed',
        PAPER_OAUTH_WITNESS_DISPOSABLE: 'confirmed'
      }
    ]) {
      await withEnvironment(overrides, async () => {
        assert.throws(() => pgEpoch.enabled(), closed);
        await assert.rejects(
          pgEpoch.current({ call: noCall }, AUTHORIZATION), closed);
        await assert.rejects(
          pgEpoch.verify({ call: noCall }, {
            ...AUTHORIZATION, oauthPgRevision: '1'
          }), closed);
      });
    }
  }
});

test('closed production issuer refuses approval, consent and code/token minting before side effects', async () => {
  await withEnvironment({ NODE_ENV: 'production' }, async () => {
    await assert.rejects(
      oauthToken.actions.exchange.handler({
        params: { grant_type: 'authorization_code' }, call: noCall
      }), closed);
    await assert.rejects(
      oauthAuthorization.actions.authorize.handler({
        params: { decision: 'approve' }, call: noCall
      }), closed);
    await assert.rejects(
      oauthConsent.actions.upsert.handler.call({ redis: { set: noCall } }, {
        params: AUTHORIZATION
      }), closed);
    await assert.rejects(
      oauthCode.actions.issueCode.handler.call({ redis: { set: noCall } }, {
        params: AUTHORIZATION, call: noCall
      }), closed);
    await assert.rejects(
      oauthToken.methods.issueAccessToken.call({}, AUTHORIZATION,
        { call: noCall }), closed);
    await assert.rejects(
      oauthRefresh.actions.issueRefreshToken.handler.call({
        redis: { eval: noCall }
      }, { params: { ...AUTHORIZATION, did: 'did:plc:' + 'q'.repeat(24),
        dpopJkt: 'a'.repeat(43) }, call: noCall }), closed);
  });
});

test('valid signed pre-release JWT plus restored Redis consent is always inactive in production', async () => {
  await withEnvironment({ NODE_ENV: 'production' }, async () => {
    const issuer = 'https://paper.example.org';
    const audience = 'https://pds.example.org';
    const { privateKey, publicKey } = await generateKeyPair('ES256');
    const publicJwk = { ...await exportJWK(publicKey), alg: 'ES256' };
    const token = await new SignJWT({
      canonical_account_id: OWNER, client_id: CLIENT, scope: SCOPE,
      consent_grant_id: GRANT, cnf: { jkt: 'a'.repeat(43) }
    })
      .setProtectedHeader({ typ: 'at+jwt', alg: 'ES256' })
      .setSubject('did:plc:' + 'q'.repeat(24))
      .setIssuer(issuer).setAudience(audience)
      .setIssuedAt().setExpirationTime('10m')
      .sign(privateKey);
    const calls = [];
    const state = { settings: { issuer, audience } };
    const result = await oauthToken.actions.introspectAccessToken.handler.call(
      state, { params: { token }, call: async name => {
        calls.push(name);
        if (name === 'jwk.get') return { publicJwk };
        if (name === 'oauth-consent.get') return {
          ...AUTHORIZATION, grantId: GRANT, revoked: false
        };
        noCall();
      } }
    );
    assert.deepEqual(result, { active: false });
    assert.deepEqual(calls, ['jwk.get', 'oauth-consent.get']);
  });
});

test('owner/operator revocation remains possible when new grants are closed', async () => {
  await withEnvironment({ NODE_ENV: 'production' }, async () => {
    let calls = 0;
    const result = await oauthConsent.actions.revoke.handler.call({
      settings: { keyPrefix: 'oauth:grant', ttlSec: 1800 },
      redis: { eval: async () => { calls += 1; return 1; } }
    }, { params: { canonicalAccountId: OWNER, clientId: CLIENT } });
    assert.deepEqual(result, { revoked: true });
    assert.equal(calls, 1);
  });
});

test('disposable test mode remains compatible without production authority', async () => {
  await withEnvironment({ NODE_ENV: 'test' }, () => {
    assert.equal(pgEpoch.enabled(), false);
  });
});
