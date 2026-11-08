'use strict';

/**
 * The existing Solid-OIDC identity is the ONLY app login for Group creation.
 * Real ES256 JWTs are verified using the provider's existing jwk action.
 * SAI and reservation writes in this test are explicit provider-service
 * doubles. Durable real Fuseki/lease behavior has a separate workflow.
 */
const { generateKeyPair, exportJWK, SignJWT } = require('jose');
const jwkService = require('../services/core/jwk');
const groupApi = require('../services/collective-reservations-api.service');
const { assertLiveCollectiveConsent } = require('../services/utils/collective-access-policy');

const ISSUER = 'https://provider.example';
const APP = 'https://paper.example/app';
const PERSON = ISSUER + '/users/alice#me';
const SECRET = 'a'.repeat(48);
const REQUEST_KEY = 'r'.repeat(32);

async function signedIdentity(override = {}) {
  const key = await generateKeyPair('ES256');
  const publicJwk = await exportJWK(key.publicKey);
  const now = Math.floor(Date.now() / 1000);
  const claims = { sub: PERSON, webid: PERSON, azp: APP, ...override };
  const token = await new SignJWT(claims)
    .setProtectedHeader({ alg: 'ES256' })
    .setIssuer(ISSUER).setAudience(APP)
    .setIssuedAt(now - 120).setExpirationTime(now + 3600)
    .sign(key.privateKey);
  return { publicJwk, token };
}

function provider(token, publicJwk) {
  let rights = [];
  let registered = true;
  const seen = [];
  const jwtInstance = { publicJwk, settings: { alg: 'ES256' } };
  const ctx = {
    params: { displayName: 'Provider-owned Group' },
    meta: {
      webId: APP, impersonatedUser: PERSON,
      tokenPayload: { sub: PERSON, webid: PERSON, azp: APP },
      $collectivesAuthHeader: 'Bearer ' + token,
      $collectivesIdempotencyKey: REQUEST_KEY
    },
    async call(action, params) {
      seen.push(action);
      if (action === 'jwk.verifyToken') {
        return jwkService.actions.verifyToken.call(jwtInstance, { params });
      }
      if (action === 'collective-reservations.reserve') {
        await assertLiveCollectiveConsent(ctx, {
          principal: params.principal, app: params.app,
          operation: 'reserve', approvedApps: [APP]
        });
        return { canonicalGroupId: 'cg_' + 'b'.repeat(32), stage: 'reserved' };
      }
      if (action === 'auth.account.findByWebId') return { webId: PERSON };
      if (action === 'app-registrations.isRegistered') return registered;
      if (action === 'access-authorizations.getSpecialRights') return rights;
      throw new Error('Unexpected provider action ' + action);
    }
  };
  const instance = { settings: {
    enabled: true, providerOrigin: ISSUER, grantSecret: SECRET
  }};
  return {
    seen,
    approve() { rights = ['apods:CreateGroup']; },
    revoke() { rights = []; },
    unregister() { registered = false; },
    reserve() { return groupApi.actions.reserve.handler.call(instance, ctx); }
  };
}

describe('Existing Solid-OIDC + SAI → provider-owned Groups', () => {
  test('authenticated app denied before SAI consent; approved, then revoked', async () => {
    const signed = await signedIdentity();
    const h = provider(signed.token, signed.publicJwk);
    await expect(h.reserve()).rejects.toMatchObject({ type: 'COLLECTIVE_APP_CONSENT_MISSING' });
    h.approve();
    expect((await h.reserve()).stage).toBe('reserved');
    h.revoke();
    await expect(h.reserve()).rejects.toMatchObject({ type: 'COLLECTIVE_APP_CONSENT_MISSING' });
    expect(h.seen.filter(x => x === 'jwk.verifyToken')).toHaveLength(3);
  });

  test('unregistering the app revokes Group authority without a new login ceremony', async () => {
    const signed = await signedIdentity();
    const h = provider(signed.token, signed.publicJwk);
    h.approve();
    h.unregister();
    await expect(h.reserve()).rejects.toMatchObject({ type: 'COLLECTIVE_APP_NOT_REGISTERED' });
  });

  test('wrong provider signature rejects request before any SAI or storage operation', async () => {
    const a = await signedIdentity();
    const b = await signedIdentity();
    const h = provider(b.token, a.publicJwk);
    h.approve();
    await expect(h.reserve()).rejects.toMatchObject({ type: 'COLLECTIVE_AUTHENTICATION_REQUIRED' });
    expect(h.seen).toEqual(['jwk.verifyToken']);
  });

  test('signed subject differing from WebID cannot create a Group', async () => {
    const a = await signedIdentity({ sub: ISSUER + '/users/other#me' });
    const h = provider(a.token, a.publicJwk);
    h.approve();
    await expect(h.reserve()).rejects.toMatchObject({ type: 'COLLECTIVE_AUTHENTICATION_REQUIRED' });
  });
});
