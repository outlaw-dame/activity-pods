const fs = require('fs');
const path = require('path');
const ApiGatewayService = require('moleculer-web');
const { Errors: E } = require('moleculer-web');
const WebSocketMixin = require('../mixins/websocket');
const CONFIG = require('../config/config');

module.exports = {
  mixins: [ApiGatewayService, WebSocketMixin],
  settings: {
    // Preserve the production default while allowing isolated benchmark runs
    // that intentionally wait for full signup bootstrap to extend the gateway
    // deadline beyond the benchmark client's non-replayable request timeout.
    httpServerTimeout: Number(process.env.APODS_HTTP_SERVER_TIMEOUT_MS || 300000),
    baseUrl: CONFIG.BASE_URL,
    port: CONFIG.PORT,
    cors: {
      origin: '*',
      methods: ['GET', 'PUT', 'PATCH', 'POST', 'DELETE', 'HEAD', 'OPTIONS'],
      exposedHeaders: '*'
    },
    routes: [
      {
        name: 'favicon',
        path: '/favicon.ico',
        aliases: {
          'GET /': 'api.favicon'
        }
      },
      {
        name: 'redirectToFront',
        path: '/',
        aliases: {
          'GET /': 'api.redirectToFront'
        }
      }
    ]
  },
  actions: {
    favicon(ctx) {
      ctx.meta.$responseType = 'image/x-icon';
      return fs.readFileSync(path.resolve(__dirname, '../static/favicon.ico'));
    },
    redirectToFront(ctx) {
      ctx.meta.$statusCode = 302;
      ctx.meta.$location = CONFIG.FRONTEND_URL;
    }
  },
  methods: {
    async authenticate(ctx, route, req, res) {
      // Keep the HTTP-signature principal separate from Moleculer's shared
      // webId metadata. Downstream action middleware may make system-authority
      // child calls before the inbox actor check runs.
      delete ctx.meta.httpSignatureActorUri;
      if (req.headers.signature || (typeof req.headers.authorization === 'string' && req.headers.authorization.startsWith('Signature '))) {
        if (!req.headers.signature && typeof req.headers.authorization === 'string') {
          req.headers.signature = req.headers.authorization.startsWith('Signature ')
            ? req.headers.authorization.slice(10)
            : req.headers.authorization;
        }
        const { isValid, actorUri } = await ctx.call('signature.verifyHttpSignature', {
          path: req.originalUrl,
          method: req.method,
          headers: req.headers
        });
        if (isValid) {
          ctx.meta.webId = actorUri;
          ctx.meta.httpSignatureActorUri = actorUri;
          return null;
        }
        ctx.meta.webId = 'anon';
        throw new E.UnAuthorizedError(E.ERR_INVALID_TOKEN);
      }
      const token = req.headers.authorization?.split(' ')[1];
      if (token) {
        const payload = await ctx.call('auth.jwt.decodeToken', { token });
        if (payload?.azp) {
          // This is a OIDC provider-generated ID token
          return ctx.call('solid-oidc.authenticate', { route, req, res });
        }
        // Otherwise it is a custom JWT token (used by ActivityPods frontend)
        return ctx.call('auth.authenticate', { route, req, res });
      }

      ctx.meta.webId = 'anon';
      return null;
    },
    async authorize(ctx, route, req, res) {
      delete ctx.meta.httpSignatureActorUri;
      if (req.headers.signature || (typeof req.headers.authorization === 'string' && req.headers.authorization.startsWith('Signature '))) {
        if (!req.headers.signature && typeof req.headers.authorization === 'string') {
          req.headers.signature = req.headers.authorization.startsWith('Signature ')
            ? req.headers.authorization.slice(10)
            : req.headers.authorization;
        }
        const { isValid, actorUri } = await ctx.call('signature.verifyHttpSignature', {
          path: req.originalUrl,
          method: req.method,
          headers: req.headers
        });
        if (isValid) {
          ctx.meta.webId = actorUri;
          ctx.meta.httpSignatureActorUri = actorUri;
          return null;
        }
        ctx.meta.webId = 'anon';
        throw new E.UnAuthorizedError(E.ERR_INVALID_TOKEN);
      }
      const token = req.headers.authorization?.split(' ')[1];
      if (token) {
        const payload = await ctx.call('auth.jwt.decodeToken', { token });
        if (payload?.azp) {
          // This is a OIDC provider-generated ID token
          return ctx.call('solid-oidc.authorize', { route, req, res });
        }
        // Otherwise it is a custom JWT token (used by ActivityPods frontend) or a VC capability
        return ctx.call('auth.authorize', { route, req, res });
      }
      ctx.meta.webId = 'anon';
      throw new E.UnAuthorizedError(E.ERR_NO_TOKEN);
    },
    // Overwrite optimization method to put catchAll routes at the end
    // See https://github.com/moleculerjs/moleculer-web/issues/335
    optimizeRouteOrder() {
      this.routes.sort(a => (a.opts.catchAll ? 1 : -1));
      this.aliases.sort(a => (a.route.opts.catchAll ? 1 : -1));
    }
  }
};
