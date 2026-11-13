const path = require('path');
const crypto = require('node:crypto');
const Redis = require('ioredis');
const { delay } = require('@semapps/ldp');
const { Errors: E } = require('moleculer-web');
const RedisAdapter = require('../../config/oidc-adapter');
const baseConfig = require('../../config/oidc');
const fetch = require('node-fetch');
const CONFIG = require('../../config/config');
const { verifySolidDpop } = require('../../utils/solid-dpop-verifier');
const { allowedOrigin } = require('../../config/oidc-cors-policy');

const validatedRequests = new WeakMap();

module.exports = {
  name: 'solid-oidc',
  settings: {
    baseUrl: CONFIG.BASE_URL,
    frontendUrl: CONFIG.FRONTEND_URL,
    redisUrl: CONFIG.REDIS_OIDC_PROVIDER_URL,
    cookieSecret: CONFIG.COOKIE_SECRET
  },
  dependencies: ['jwk', 'api'],
  stopped() {
    // The OIDC adapter and the replay check share this connection. Close it
    // when Moleculer stops the service; otherwise restarts leak Redis sockets.
    const client = this.dpopRedis;
    this.dpopRedis = null;
    if (client) client.disconnect();
  },
  async started() {
    // Dynamically import Provider since it's an ESM module
    const { default: Provider } = await import('oidc-provider');

    const { privateJwk } = await this.broker.call('jwk.get');

    const config = baseConfig(this.settings, privateJwk);

    const redisClient = new Redis(this.settings.redisUrl, { keyPrefix: 'oidc:' });
    config.adapter = name => new RedisAdapter(name, redisClient);
    this.dpopRedis = redisClient;

    try {
      // Permit a browser origin only if that resolved OAuth client's
      // registered redirect URIs contain the exact origin. Never let one
      // client authorize another site's origin.
      config.clientBasedCORS = (_ctx, origin, client) =>
        allowedOrigin(origin, client, {
          allowLocalhost: process.env.NODE_ENV !== 'production'
        });

      this.oidc = new Provider(this.settings.baseUrl, config);

      // Allow provider to interpret reverse proxy headers.
      this.oidc.proxy = true;

      await this.broker.call('api.addRoute', {
        route: {
          name: 'oidc-config',
          path: '/.well-known/openid-configuration',
          aliases: {
            'GET /': 'solid-oidc.proxyConfig'
          }
        }
      });

      const { pathname: basePath } = new URL(this.settings.baseUrl);

      await this.broker.call('api.addRoute', {
        route: {
          name: 'oidc-login-completed',
          path: path.join(basePath, '/.oidc/login-completed'),
          authentication: true,
          bodyParsers: {
            json: true
          },
          aliases: {
            'POST /': 'solid-oidc.loginCompleted'
          }
        }
      });

      // The OIDC provider route must be added after all other routes, otherwise it gets overwritten
      // TODO find out why ! Probably due to the fact it is only a middleware (adding dummy aliases doesn't help)
      await delay(10000);

      await this.broker.call('api.addRoute', {
        route: {
          name: 'solid-oidc',
          path: path.join(basePath, '/.oidc/auth'),
          use: [this.oidc.callback()]
        }
      });
    } catch (error) {
      // A failed OIDC route registration must not leave an orphan Redis
      // socket or provider reference across service restart attempts.
      this.oidc = null;
      if (this.dpopRedis === redisClient) this.dpopRedis = null;
      redisClient.disconnect();
      throw error;
    }
  },
  actions: {
    // See https://moleculer.services/docs/0.13/moleculer-web.html#Authentication
    async authenticate(ctx) {
      const { route, req, res } = ctx.params;
      // Extract token from authorization header (do not take the Bearer part)
      const token = req.headers.authorization && req.headers.authorization.split(' ')[1];
      if (token) {
        const payload = await ctx.call('jwk.verifyToken', { token });
        if (payload) {
          if (process.env.APODS_SOLID_OIDC_DPOP_ENFORCE_ENABLED === 'true') {
            try {
              await this.verifyDpopRequest(req, token, payload);
            } catch (_error) {
              ctx.meta.webId = 'anon';
              return Promise.reject(new E.UnAuthorizedError(E.ERR_INVALID_TOKEN));
            }
          }
          ctx.meta.tokenPayload = payload;
          ctx.meta.webId = payload.azp; // Use the WebID of the application requesting access
          ctx.meta.impersonatedUser = payload.webid; // Used by some services which need to know the real user (Attention: webid with a i)
          return Promise.resolve(payload);
        }
        // Invalid token
        ctx.meta.webId = 'anon';
        return Promise.reject(new E.UnAuthorizedError(E.ERR_INVALID_TOKEN));
      }
      // No token
      ctx.meta.webId = 'anon';
      return Promise.resolve(null);
    },
    // See https://moleculer.services/docs/0.13/moleculer-web.html#Authorization
    async authorize(ctx) {
      const { route, req, res } = ctx.params;
      // Extract token from authorization header (do not take the Bearer part)
      const token = req.headers.authorization && req.headers.authorization.split(' ')[1];
      if (token) {
        const payload = await ctx.call('jwk.verifyToken', { token });
        if (payload) {
          if (process.env.APODS_SOLID_OIDC_DPOP_ENFORCE_ENABLED === 'true') {
            try {
              await this.verifyDpopRequest(req, token, payload);
            } catch (_error) {
              ctx.meta.webId = 'anon';
              return Promise.reject(new E.UnAuthorizedError(E.ERR_INVALID_TOKEN));
            }
          }
          ctx.meta.tokenPayload = payload;
          ctx.meta.webId = payload.azp; // Use the WebID of the application requesting access
          ctx.meta.impersonatedUser = payload.webid; // Used by some services which need to know the real user (Attention: webid with a i)
          return Promise.resolve(payload);
        }
        ctx.meta.webId = 'anon';
        return Promise.reject(new E.UnAuthorizedError(E.ERR_INVALID_TOKEN));
      }
      ctx.meta.webId = 'anon';
      return Promise.reject(new E.UnAuthorizedError(E.ERR_NO_TOKEN));
    },
    async proxyConfig() {
      const res = await fetch(`${this.settings.baseUrl}.oidc/auth/.well-known/openid-configuration`);
      if (res.ok) {
        return await res.json();
      } else {
        throw new Error('OIDC server not loaded');
      }
    },
    // See https://github.com/panva/node-oidc-provider/blob/main/docs/README.md#user-flows
    async loginCompleted(ctx) {
      const { interactionId } = ctx.params;
      const webId = ctx.meta.webId;

      await this.interactionFinished(interactionId, {
        login: { accountId: webId, amr: ['pwd'], remember: true }
      });
    }
  },
  methods: {
    async verifyDpopRequest(req, token, payload) {
      if (!req || typeof req !== 'object' || typeof req.method !== 'string' ||
          !req.headers || typeof req.headers.dpop !== 'string' ||
          !this.dpopRedis) throw new Error('DPoP request proof is required');

      // A proxy must supply a relative request target. Never let an
      // attacker-supplied absolute or scheme-relative URL choose the DPoP
      // audience through req.originalUrl.
      const requestPath = req.originalUrl || req.url;
      if (typeof requestPath !== 'string' ||
          requestPath.length > 4096 || !requestPath.startsWith('/') ||
          requestPath.startsWith('//') || requestPath.includes('\\')) {
        throw new Error('Invalid DPoP request target');
      }
      const base = new URL(this.settings.baseUrl);
      const targetUrl = new URL(requestPath, base);
      if (base.protocol !== 'https:' || targetUrl.origin !== base.origin) {
        throw new Error('Invalid external DPoP origin');
      }
      const target = targetUrl.toString();
      // The same request may go through both middleware functions.
      // Don't treat its second authorization check as a replay.
      const fingerprint = crypto.createHash('sha256')
        .update(token).update('\0')
        .update(req.headers.dpop).update('\0')
        .update(req.method).update('\0')
        .update(target).digest('hex');
      if (validatedRequests.get(req) === fingerprint) return;

      await verifySolidDpop({
        proof: req.headers.dpop, idToken: token, verifiedToken: payload,
        method: req.method, targetUrl: target,
        expectedIssuer: this.settings.baseUrl,
        reserveReplay: async (key, ttl) => {
          // Share the OIDC provider's Redis connection and use an atomic
          // SET NX so every Moleculer replica sees the same replay ledger.
          const result = await this.dpopRedis.set(
            'atproto:dpop:replay:' + key, '1', 'EX', ttl, 'NX'
          );
          return result === 'OK';
        }
      });
      // Keep only a fixed-size fingerprint on the short-lived request.
      // Raw bearer tokens and signed proofs must not remain in a cache.
      validatedRequests.set(req, fingerprint);
    },
    async interactionFinished(interactionId, result) {
      const interaction = await this.oidc.Interaction.find(interactionId);
      if (interaction) {
        interaction.result = result;
        await interaction.save(interaction.exp - Math.floor(Date.now() / 1000));
      } else {
        throw new Error(`No interaction found with ID ${interactionId}. It may have expired.`);
      }
    }
  }
};
