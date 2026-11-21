const crypto = require('crypto');
const { MoleculerError } = require('moleculer').Errors;
const { SignJWT, importJWK, jwtVerify } = require('jose');
const { nowEpochSec, parseIntWithBounds, parseBoolean } = require('../../utils/oauth-security');
const CONFIG = require('../../config/config');
const pgEpoch = require('../../utils/oauth-pg-epoch-policy');

const baseUrl = process.env.SEMAPPS_HOME_URL || CONFIG.BASE_URL || '';
const CONSENT_GRANT=/^[A-Za-z0-9_-]{32}$/u;
async function requireCurrentConsent(ctx,{canonicalAccountId,clientId,scope,consentGrantId}){
  if(!CONSENT_GRANT.test(consentGrantId||'')){
    throw new MoleculerError('Consent generation missing',400,'INVALID_GRANT');
  }
  // This is a READ of the owner-approved epoch, not cached session state.
  // Never issue a fresh token from an older consent that was revoked and
  // later reapproved under a new generation.
  const grant=await ctx.call('oauth-consent.get',{canonicalAccountId,clientId});
  if(!grant||grant.revoked!==false||grant.grantId!==consentGrantId||
     grant.canonicalAccountId!==canonicalAccountId||
     grant.clientId!==clientId||grant.scope!==scope){
    throw new MoleculerError('Consent has changed',400,'INVALID_GRANT');
  }
  return grant;
}

function base64UrlSha256(input) {
  return crypto.createHash('sha256').update(String(input), 'utf8').digest('base64url');
}

module.exports = {
  name: 'oauth-token',
  dependencies: ['oauth-code-store', 'oauth-refresh-session', 'oauth-dpop-nonce', 'oauth-consent', 'jwk'],

  settings: {
    issuer: process.env.OAUTH_ISSUER || baseUrl,
    resource: process.env.OAUTH_PROTECTED_RESOURCE_URL || baseUrl,
    audience: process.env.OAUTH_TOKEN_AUDIENCE || process.env.OAUTH_PROTECTED_RESOURCE_URL || baseUrl,
    accessTtlSec: parseIntWithBounds(process.env.OAUTH_ACCESS_TTL_SECONDS, 3600, 60, 7200, 'OAUTH_ACCESS_TTL_SECONDS'),
    allowLocalhostHttp: parseBoolean(process.env.OAUTH_ENABLE_LOCALHOST_DEV, false)
  },

  actions: {
    exchange: {
      params: {
        grant_type: { type: 'string', min: 1 },
        client_id: { type: 'string', min: 1 },
        redirect_uri: { type: 'string', optional: true },
        code: { type: 'string', optional: true },
        code_verifier: { type: 'string', optional: true },
        refresh_token: { type: 'string', optional: true },
        dpop_proof: { type: 'string', min: 10 },
        dpop_nonce: { type: 'string', optional: true },
        htm: { type: 'string', min: 1 },
        htu: { type: 'string', min: 1 }
      },
      async handler(ctx) {
        const input = ctx.params;
        const proof = await ctx.call('oauth-dpop-nonce.verifyProof', {
          proofJwt: input.dpop_proof,
          htm: input.htm,
          htu: input.htu,
          audience: this.settings.audience,
          nonce: input.dpop_nonce
        });

        if (input.grant_type === 'authorization_code') {
          return this.handleAuthorizationCode(ctx, input, proof.jkt);
        }

        if (input.grant_type === 'refresh_token') {
          return this.handleRefreshToken(ctx, input, proof.jkt);
        }

        throw new MoleculerError('Unsupported grant_type', 400, 'INVALID_GRANT');
      }
    },

    introspectAccessToken: {
      params: {
        token: { type: 'string', min: 20 }
      },
      async handler(ctx) {
        const token = String(ctx.params.token).trim();
        const { publicJwk } = await ctx.call('jwk.get');
        const publicKey = await importJWK(publicJwk, String(publicJwk.alg || 'ES256'));

        try {
          const { payload } = await jwtVerify(token, publicKey, {
            issuer: this.settings.issuer,
            audience: this.settings.audience,
            // The same JWK provider can sign other Solid/OIDC JWT classes.
            // A protected-resource access token MUST have the type emitted
            // by issueAccessToken, not merely a valid issuer+audience.
            typ: 'at+jwt',
            algorithms: [String(publicJwk.alg || 'ES256')]
          });

          const grantId=payload.consent_grant_id;
          if(!CONSENT_GRANT.test(grantId||''))return {active:false};
          await requireCurrentConsent(ctx,{
            canonicalAccountId:payload.canonical_account_id,
            clientId:payload.client_id,scope:payload.scope,consentGrantId:grantId
          });
          await pgEpoch.verify(ctx,{
            canonicalAccountId:payload.canonical_account_id,
            clientId:payload.client_id,scope:payload.scope,
            consentGrantId:grantId,oauthPgRevision:payload.oauth_pg_revision
          });
          return {
            active: true,
            sub: payload.sub,
            scope: payload.scope,
            client_id: payload.client_id,
            canonical_account_id: payload.canonical_account_id,
            consent_grant_id:grantId,
            ...(pgEpoch.enabled()?{oauth_pg_revision:payload.oauth_pg_revision}:{}),
            cnf: payload.cnf,
            exp: payload.exp
          };
        } catch (_error) {
          return { active: false };
        }
      }
    }
  },

  methods: {
    async handleAuthorizationCode(ctx, input, dpopJkt) {
      if (!input.code || !input.code_verifier || !input.redirect_uri) {
        throw new MoleculerError('Missing authorization_code parameters', 400, 'INVALID_GRANT');
      }

      const record = await ctx.call('oauth-code-store.consumeCode', { code: input.code });
      if (record.clientId !== input.client_id) {
        throw new MoleculerError('client_id mismatch for code', 400, 'INVALID_GRANT');
      }
      if (record.redirectUri !== input.redirect_uri) {
        throw new MoleculerError('redirect_uri mismatch for code', 400, 'INVALID_GRANT');
      }
      if (record.dpopJkt !== dpopJkt) {
        throw new MoleculerError('DPoP binding mismatch for authorization code', 401, 'INVALID_DPOP_PROOF');
      }
      if (record.codeChallengeMethod !== 'S256') {
        throw new MoleculerError('Unsupported code challenge method', 400, 'PKCE_VERIFICATION_FAILED');
      }

      const verifierHash = base64UrlSha256(input.code_verifier);
      if (verifierHash !== record.codeChallenge) {
        throw new MoleculerError('PKCE verification failed', 400, 'PKCE_VERIFICATION_FAILED');
      }

      const oauthPgRevision=await pgEpoch.current(ctx,record);
      // A code without the exact PG revision predates (or bypasses) the
      // recovery fence. Redeeming it cannot mint a new signed credential.
      if(oauthPgRevision!==null&&record.oauthPgRevision!==oauthPgRevision){
        throw new MoleculerError('Authorization code epoch stale',400,'INVALID_GRANT');
      }
      const token = await this.issueAccessToken({
        sub: record.did,
        oauthPgRevision,
        canonicalAccountId: record.canonicalAccountId,
        clientId: record.clientId,
        scope: record.scope,
        consentGrantId:record.consentGrantId,
        dpopJkt
      }, ctx);

      const refresh = await ctx.call('oauth-refresh-session.issueRefreshToken', {
        did: record.did,
        canonicalAccountId: record.canonicalAccountId,
        clientId: record.clientId,
        scope: record.scope,
        consentGrantId:record.consentGrantId,
        ...(oauthPgRevision!==null?{oauthPgRevision}:{}),
        dpopJkt
      });

      return {
        access_token: token,
        token_type: 'DPoP',
        expires_in: this.settings.accessTtlSec,
        refresh_token: refresh.refreshToken,
        scope: record.scope,
        sub: record.did
      };
    },

    async handleRefreshToken(ctx, input, dpopJkt) {
      if (!input.refresh_token) {
        throw new MoleculerError('Missing refresh_token', 400, 'INVALID_GRANT');
      }

      const rotated = await ctx.call('oauth-refresh-session.rotateRefreshToken', {
        refreshToken: input.refresh_token,
        dpopJkt
      });

      if (rotated.clientId !== input.client_id) {
        throw new MoleculerError('refresh token client mismatch', 400, 'INVALID_GRANT');
      }

      const token = await this.issueAccessToken({
        sub: rotated.did,
        oauthPgRevision:rotated.oauthPgRevision,
        canonicalAccountId: rotated.canonicalAccountId,
        clientId: rotated.clientId,
        scope: rotated.scope,
        consentGrantId:rotated.consentGrantId,
        dpopJkt
      }, ctx);

      return {
        access_token: token,
        token_type: 'DPoP',
        expires_in: this.settings.accessTtlSec,
        refresh_token: rotated.refreshToken,
        scope: rotated.scope,
        sub: rotated.did
      };
    },

    async issueAccessToken(session, ctx) {
      await requireCurrentConsent(ctx,session);
      const epoch=await pgEpoch.current(ctx,session);
      if(epoch!==null&&session.oauthPgRevision!==undefined&&
         session.oauthPgRevision!==epoch){
        throw new MoleculerError('PostgreSQL OAuth epoch changed',400,'INVALID_GRANT');
      }
      const { privateJwk } = await ctx.call('jwk.get');
      const privateKey = await importJWK(privateJwk, String(privateJwk.alg || 'ES256'));
      const now = nowEpochSec();

      return await new SignJWT({
        scope: session.scope,
        client_id: session.clientId,
        canonical_account_id: session.canonicalAccountId,
        consent_grant_id: session.consentGrantId,
        ...(epoch!==null?{oauth_pg_revision:epoch}:{}),
        cnf: { jkt: session.dpopJkt }
      })
        .setProtectedHeader({ alg: String(privateJwk.alg || 'ES256'), typ: 'at+jwt' })
        .setIssuer(this.settings.issuer)
        .setAudience(this.settings.audience)
        .setSubject(session.sub)
        .setJti(crypto.randomUUID())
        .setIssuedAt(now)
        .setExpirationTime(now + this.settings.accessTtlSec)
        .sign(privateKey);
    }
  }
};
