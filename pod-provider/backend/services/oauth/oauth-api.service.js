const { MoleculerError } = require('moleculer').Errors;
const { sanitizeErrorMessage, parseBoolean } = require('../../utils/oauth-security');
const CONFIG = require('../../config/config');
const crypto = require('crypto');

const baseUrl = process.env.SEMAPPS_HOME_URL || CONFIG.BASE_URL || '';

module.exports = {
  name: 'oauth-api',
  dependencies: [
    'api',
    'auth.jwt',
    'oauth-authorization-server-metadata',
    'oauth-protected-resource-metadata',
    'oauth-client-metadata',
    'oauth-dpop-nonce',
    'oauth-par',
    'oauth-authorization',
    'oauth-consent-challenge',
    'oauth-token',
    'oauth-refresh-session',
    'oauth-session-registry'
  ],

  settings: {
    auth: {
      internalBearerToken: process.env.ACTIVITYPODS_TOKEN || ''
    },
    issuer: process.env.OAUTH_ISSUER || baseUrl,
    csrfCookieName: process.env.OAUTH_CSRF_COOKIE_NAME || 'oauth_csrf',
    sessionCookieName: process.env.OAUTH_SESSION_COOKIE_NAME || 'oauth_session',
    sessionTtlSec: Math.max(300, Math.min(Number(process.env.OAUTH_SESSION_TTL_SECONDS) || 3600, 86400)),
    sessionSecret: String(
      process.env.OAUTH_SESSION_SECRET || process.env.ACTIVITYPODS_TOKEN || 'dev-oauth-session-secret'
    ),
    allowInternalAuthorizeFallback: parseBoolean(
      process.env.OAUTH_ALLOW_INTERNAL_AUTHORIZE_FALLBACK,
      process.env.NODE_ENV !== 'production'
    )
  },

  created() {
    // A predictable fallback would let an attacker forge an OAuth browser
    // session for any WebID if the provider was started without a secret.
    // Existing strong ACTIVITYPODS_TOKEN secrets remain compatible.
    const secret = String(this.settings.sessionSecret || '');
    if (process.env.NODE_ENV === 'production' &&
        (secret === 'dev-oauth-session-secret' ||
         Buffer.byteLength(secret, 'utf8') < 32)) {
      throw new Error('OAuth browser sessions require a private 32-byte signing secret');
    }
  },

  async started() {
    await this.broker.call('api.addRoute', {
      route: {
        name: 'oauth-well-known',
        path: '/.well-known',
        authorization: false,
        authentication: false,
        onBeforeCall: (ctx, route, req) => {
          ctx.meta.$headers = req.headers;
          ctx.meta.$query = req.query;
          ctx.meta.$remoteIp = req.headers['x-forwarded-for'] || req.socket?.remoteAddress || req.connection?.remoteAddress || '';
        },
        aliases: {
          'GET /oauth-authorization-server': 'oauth-api.getAuthorizationServerMetadata',
          'GET /oauth-protected-resource': 'oauth-api.getProtectedResourceMetadata'
        }
      },
      toBottom: false
    });

    await this.broker.call('api.addRoute', {
      route: {
        name: 'oauth-public',
        path: '/oauth',
        authorization: false,
        authentication: false,
        bodyParsers: {
          json: { strict: false },
          urlencoded: { extended: false }
        },
        onBeforeCall: (ctx, route, req) => {
          ctx.meta.$headers = req.headers;
          ctx.meta.$query = req.query;
          ctx.meta.$remoteIp = req.headers['x-forwarded-for'] || req.socket?.remoteAddress || req.connection?.remoteAddress || '';
        },
        aliases: {
          'POST /par': 'oauth-api.createPar',
          'GET /authorize': 'oauth-api.getAuthorize',
          'POST /authorize': 'oauth-api.postAuthorizeUser',
          'POST /session/login': 'oauth-api.loginSession',
          'POST /session/logout': 'oauth-api.logoutSession',
          'POST /token': 'oauth-api.exchangeToken',
          'POST /revoke': 'oauth-api.revoke',
          'GET /client-metadata/:id': 'oauth-api.getClientMetadata',
          'GET /dpop-nonce': 'oauth-api.getDpopNonce'
        }
      },
      toBottom: false
    });

    await this.broker.call('api.addRoute', {
      route: {
        name: 'oauth-internal',
        path: '/api/internal/oauth',
        authorization: false,
        authentication: false,
        bodyParsers: { json: { strict: false } },
        onBeforeCall: (ctx, route, req) => {
          ctx.meta.$headers = req.headers;
          ctx.meta.$remoteIp = req.headers['x-forwarded-for'] || req.socket?.remoteAddress || req.connection?.remoteAddress || '';
        },
        aliases: {
          'POST /authorize': 'oauth-api.postAuthorizeInternal',
          'POST /introspect': 'oauth-api.introspect',
          'POST /revoke-family': 'oauth-api.revokeFamily',
          'GET /health': 'oauth-api.health'
        }
      },
      toBottom: false
    });

    this.logger.info('[OAuthApi] OAuth routes registered');
  },

  actions: {
    async getAuthorizationServerMetadata(ctx) {
      this.noStore(ctx);
      return this.runSafely(() => ctx.call('oauth-authorization-server-metadata.getMetadata'));
    },

    async getProtectedResourceMetadata(ctx) {
      this.noStore(ctx);
      return this.runSafely(() => ctx.call('oauth-protected-resource-metadata.getMetadata'));
    },

    async createPar(ctx) {
      this.noStore(ctx);
      const body = this.body(ctx);
      const proof = this.getDpopHeader(ctx);
      const nonce = this.getDpopNonceHeader(ctx);

      const verified = await this.runSafely(() =>
        ctx.call('oauth-dpop-nonce.verifyProof', {
          proofJwt: proof,
          htm: 'POST',
          htu: this.oauthEndpoint('/oauth/par'),
          audience: this.settings.issuer,
          nonce
        })
      );

      ctx.meta.$statusCode = 201;
      return this.runSafely(() =>
        ctx.call('oauth-par.create', {
          ...body,
          dpop_jkt: verified.jkt
        })
      );
    },

    async getAuthorize(ctx) {
      this.noStore(ctx);
      const query = ctx.meta.$query || {};
      const context = await this.runSafely(() =>
        ctx.call('oauth-authorization.getAuthorizationContext', {
          request_uri: query.request_uri
        })
      );

      const csrfToken = this.randomToken();
      const challenge = await this.runSafely(() =>
        ctx.call('oauth-consent-challenge.mint', {
          requestUri: context.request_uri,
          fingerprint: this.requestFingerprint(ctx),
          csrfToken,
          expiresAt: context.expires_at
        })
      );

      this.setCookie(ctx, this.settings.csrfCookieName, csrfToken);
      const payload = {
        ...context,
        consent_required: true,
        consent_challenge: challenge.challengeId,
        authorize_endpoint: '/oauth/authorize'
      };

      if (this.prefersHtml(ctx)) {
        const candidateSession = this.getSession(ctx);
        const existingSession = candidateSession &&
          await this.isActiveBrowserSession(ctx, candidateSession) ? candidateSession : null;
        this.setHtmlResponse(ctx);
        return this.renderAuthorizePage(payload, {
          csrfCookieName: this.settings.csrfCookieName,
          hasSession: !!existingSession,
          webId: existingSession?.webId || ''
        });
      }

      return payload;
    },

    async postAuthorizeUser(ctx) {
      this.noStore(ctx);
      const body = this.body(ctx);
      const csrfToken = this.getCookie(ctx, this.settings.csrfCookieName);
      if (!csrfToken) {
        throw new MoleculerError('CSRF cookie is required', 403, 'LOGIN_REQUIRED');
      }

      const canonicalAccountId = await this.requireUserWebId(ctx);
      const result = await this.authorizeDecision(ctx, body, csrfToken, canonicalAccountId);
      ctx.meta.$statusCode = 302;
      ctx.meta.$location = result.redirect_uri;
      return { redirect: result.redirect_uri };
    },

    async loginSession(ctx) {
      this.noStore(ctx);
      const body = this.body(ctx);
      const username = String(body.username || '').trim();
      const password = String(body.password || '');
      if (!username || !password) {
        throw new MoleculerError('username and password are required', 400, 'INVALID_REQUEST');
      }

      let account;
      try {
        // auth.account.verify returns the authenticated record, including
        // email-login aliases. A separate findByUsername lookup can select
        // a different account or a tombstone after a concurrent mutation.
        account = await this.runSafely(() =>
          ctx.call('auth.account.verify', { username, password })
        );
      } catch {
        throw new MoleculerError('Invalid credentials', 401, 'LOGIN_REQUIRED');
      }
      const webId = account?.webId;
      if (this.ownerAccountUnsafe(account, webId)) {
        throw new MoleculerError('Invalid credentials', 401, 'LOGIN_REQUIRED');
      }

      // A signed cookie is never usable unless its random id was first
      // durably acknowledged by the shared session authority. Ambiguous
      // Redis writes do not emit a cookie, even if they may leave a TTL key.
      const sessionId = crypto.randomBytes(32).toString('base64url');
      const token = this.buildSessionToken(webId, sessionId);
      let registered;
      try {
        registered = await ctx.call('oauth-session-registry.create', {
          webId, sessionId, ttlSec: this.settings.sessionTtlSec
        });
      } catch {
        throw new MoleculerError('Browser session authority unavailable', 503, 'SESSION_AUTHORITY_UNAVAILABLE');
      }
      if (registered !== true) {
        throw new MoleculerError('Browser session authority unavailable', 503, 'SESSION_AUTHORITY_UNAVAILABLE');
      }
      this.setSessionCookie(ctx, token);
      if (this.prefersHtml(ctx)) {
        const requestUri = encodeURIComponent(String(body.request_uri || ''));
        ctx.meta.$statusCode = 303;
        ctx.meta.$location = `/oauth/authorize?request_uri=${requestUri}&format=html`;
        return { redirect: ctx.meta.$location };
      }

      return {
        ok: true,
        webId,
        expires_in: this.settings.sessionTtlSec
      };
    },

    async logoutSession(ctx) {
      this.noStore(ctx);
      const signed = this.getSession(ctx);
      if (signed) {
        let result;
        try {
          result = await ctx.call('oauth-session-registry.revoke', {
            webId: signed.webId, sessionId: signed.sessionId
          });
        } catch {
          throw new MoleculerError('Browser session revocation unavailable', 503, 'SESSION_AUTHORITY_UNAVAILABLE');
        }
        if (!result || typeof result.revoked !== 'boolean') {
          throw new MoleculerError('Browser session revocation unavailable', 503, 'SESSION_AUTHORITY_UNAVAILABLE');
        }
      }
      // Missing, expired or already revoked cookies are harmless; do not
      // claim any active grant was revoked without the Redis acknowledgement.
      this.clearSessionCookie(ctx);
      return { ok: true };
    },

    async postAuthorizeInternal(ctx) {
      this.noStore(ctx);
      if (!this.settings.allowInternalAuthorizeFallback) {
        throw new MoleculerError('Internal authorize fallback is disabled', 403, 'LOGIN_REQUIRED');
      }
      this.requireInternalAuth(ctx);
      const body = this.body(ctx);
      const csrfToken = this.getCookie(ctx, this.settings.csrfCookieName);
      if (!csrfToken) {
        throw new MoleculerError('CSRF cookie is required', 403, 'LOGIN_REQUIRED');
      }

      const canonicalAccountId = this.parseCanonicalAccountId(body.canonicalAccountId);
      const result = await this.authorizeDecision(ctx, body, csrfToken, canonicalAccountId);
      ctx.meta.$statusCode = 302;
      ctx.meta.$location = result.redirect_uri;
      return { redirect: result.redirect_uri };
    },

    async exchangeToken(ctx) {
      this.noStore(ctx);
      const body = this.body(ctx);
      const proof = this.getDpopHeader(ctx);
      const nonce = this.getDpopNonceHeader(ctx);

      return this.runSafely(() =>
        ctx.call('oauth-token.exchange', {
          ...body,
          dpop_proof: proof,
          dpop_nonce: nonce,
          htm: 'POST',
          htu: this.oauthEndpoint('/oauth/token')
        })
      );
    },

    async revoke(ctx) {
      this.noStore(ctx);
      const body = this.body(ctx);
      if (!body.refresh_token) {
        throw new MoleculerError('refresh_token is required', 400, 'INVALID_REQUEST');
      }

      const info = await this.runSafely(() =>
        ctx.call('oauth-refresh-session.introspectRefreshToken', {
          refreshToken: body.refresh_token
        })
      );
      if (info && info.familyId) {
        await this.runSafely(() =>
          ctx.call('oauth-refresh-session.revokeFamily', {
            familyId: info.familyId
          })
        );
      }
      return { revoked: true };
    },

    async getClientMetadata(ctx) {
      this.noStore(ctx);
      const id = decodeURIComponent(String(ctx.params.id || '').trim());
      if (!id) {
        throw new MoleculerError('client metadata id is required', 400, 'INVALID_REQUEST');
      }

      if (id.startsWith('http://') || id.startsWith('https://')) {
        return this.runSafely(() =>
          ctx.call('oauth-client-metadata.resolveClientMetadata', { clientId: id })
        );
      }

      const cached = await this.runSafely(() =>
        ctx.call('oauth-client-metadata.getCachedByHash', { hash: id })
      );
      if (!cached) {
        ctx.meta.$statusCode = 404;
        return { error: 'not_found' };
      }
      return cached;
    },

    async getDpopNonce(ctx) {
      this.noStore(ctx);
      return this.runSafely(() =>
        ctx.call('oauth-dpop-nonce.mintNonce', {
          audience: this.settings.issuer
        })
      );
    },

    async introspect(ctx) {
      this.requireInternalAuth(ctx);
      const body = this.body(ctx);
      return this.runSafely(() =>
        ctx.call('oauth-token.introspectAccessToken', {
          token: String(body.token || '')
        })
      );
    },

    async revokeFamily(ctx) {
      this.requireInternalAuth(ctx);
      const body = this.body(ctx);
      return this.runSafely(() =>
        ctx.call('oauth-refresh-session.revokeFamily', {
          familyId: String(body.familyId || '')
        })
      );
    },

    async health(ctx) {
      this.requireInternalAuth(ctx);
      return {
        ok: true,
        service: 'oauth-api',
        issuer: this.settings.issuer,
        now: new Date().toISOString()
      };
    }
  },

  methods: {
    noStore(ctx) {
      ctx.meta.$responseHeaders = {
        ...(ctx.meta.$responseHeaders || {}),
        'Cache-Control': 'no-store',
        Pragma: 'no-cache',
        'X-Content-Type-Options': 'nosniff'
      };
    },

    oauthEndpoint(pathname) {
      const base = String(this.settings.issuer || '').replace(/\/+$/, '');
      const path = String(pathname || '').startsWith('/') ? String(pathname) : `/${String(pathname || '')}`;
      return `${base}${path}`;
    },

    body(ctx) {
      return (ctx.params && typeof ctx.params === 'object') ? ctx.params : {};
    },

    async runSafely(fn) {
      try {
        return await fn();
      } catch (error) {
        throw this.normalizeError(error);
      }
    },

    normalizeError(error) {
      if (error instanceof MoleculerError) {
        return new MoleculerError(
          sanitizeErrorMessage(error.message),
          error.code,
          error.type,
          error.data
        );
      }
      const status = Number.isFinite(Number(error && error.code)) ? Number(error.code) : 500;
      const type = typeof (error && error.type) === 'string' ? error.type : 'OAUTH_REQUEST_FAILED';
      return new MoleculerError(sanitizeErrorMessage(error && error.message), status, type);
    },

    requireInternalAuth(ctx) {
      const header = ctx.meta?.$headers?.authorization || ctx.meta?.$headers?.Authorization;
      if (!header || !String(header).startsWith('Bearer ')) {
        throw new MoleculerError('Missing bearer token', 401, 'AUTH_FAILED');
      }
      const token = String(header).slice(7);
      if (!this.settings.auth.internalBearerToken || token !== this.settings.auth.internalBearerToken) {
        throw new MoleculerError('Invalid bearer token', 403, 'AUTH_FAILED');
      }
    },

    ownerAccountUnsafe(account, webId) {
      if (!account || typeof account !== 'object' || Array.isArray(account) ||
          typeof webId !== 'string' || account.webId !== webId ||
          webId.length < 8 || webId.length > 2048 ||
          (account.deletedAt !== undefined && account.deletedAt !== null)) {
        return true;
      }
      try {
        const uri = new URL(webId);
        return uri.protocol !== 'https:' || !uri.hostname ||
          !!uri.username || !!uri.password || !!uri.search || uri.href !== webId;
      } catch {
        return true;
      }
    },

    async isActiveBrowserSession(ctx, signedSession) {
      if (!signedSession) return false;
      try {
        return await ctx.call('oauth-session-registry.verify', {
          webId: signedSession.webId, sessionId: signedSession.sessionId
        }) === true;
      } catch {
        // Missing Redis or a stale replica is DENY, never a positive cache.
        return false;
      }
    },

    async requireUserWebId(ctx) {
      const fromBearer = await this.tryUserBearerWebId(ctx);
      const session = fromBearer ? null : this.getSession(ctx);
      const webId = fromBearer || session?.webId;
      if (!webId || (session && !await this.isActiveBrowserSession(ctx, session))) {
        throw new MoleculerError('Login is required to approve authorization', 401, 'LOGIN_REQUIRED');
      }
      // A previously authenticated HMAC cookie or verified JWT is not
      // evidence that an account still exists. SemApps auth.account's
      // findByWebId can return a tombstoned record. Never authorize it.
      let account;
      try {
        account = await ctx.call('auth.account.findByWebId', { webId });
      } catch {
        throw new MoleculerError('Owner account is unavailable', 401, 'LOGIN_REQUIRED');
      }
      if (this.ownerAccountUnsafe(account, webId)) {
        throw new MoleculerError('Owner account is unavailable', 401, 'LOGIN_REQUIRED');
      }
      return webId;
    },

    async tryUserBearerWebId(ctx) {
      const lower = ctx.meta?.$headers?.authorization;
      const upper = ctx.meta?.$headers?.Authorization;
      if (lower === undefined && upper === undefined) {
        return null;
      }
      // A supplied but invalid Authorization header must never fall back
      // to a valid cookie. Reject conflicting duplicate header values.
      const invalid = () => {
        throw new MoleculerError('A valid server-signed user token is required', 401, 'LOGIN_REQUIRED');
      };
      if (lower !== undefined && upper !== undefined && lower !== upper) {
        return invalid();
      }
      const header = lower === undefined ? upper : lower;
      if (typeof header !== 'string' || header.length > 8192) {
        return invalid();
      }
      const match = /^Bearer ([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)$/iu.exec(header);
      if (!match) {
        return invalid();
      }
      let payload;
      try {
        // SemApps auth.jwt.decodeToken is deliberately UNVERIFIED.
        // Only verifyServerSignedToken checks RS256 and expiry.
        payload = await ctx.call('auth.jwt.verifyServerSignedToken', { token: match[1] });
      } catch {
        return invalid();
      }
      // Upstream SemApps generateServerSignedToken currently adds iat
      // but does NOT set exp. Never let an indefinitely valid historical
      // signed JWT authorize a fresh Paper app consent years later.
      const now = Math.floor(Date.now() / 1000);
      if (!payload || typeof payload !== 'object' || Array.isArray(payload) ||
          typeof payload.webId !== 'string' ||
          payload.webId.length < 8 || payload.webId.length > 2048 ||
          !Number.isSafeInteger(payload.iat) ||
          payload.iat > now + 60 || payload.iat <= now - 3600) {
        return invalid();
      }
      let uri;
      try {
        uri = new URL(payload.webId);
      } catch {
        return invalid();
      }
      if (uri.protocol !== 'https:' || !uri.hostname || uri.username ||
          uri.password || uri.search || uri.href !== payload.webId) {
        return invalid();
      }
      return payload.webId;
    },

    prefersHtml(ctx) {
      const queryFormat = String(ctx.meta?.$query?.format || '').toLowerCase();
      if (queryFormat === 'html') return true;
      const accept = String(ctx.meta?.$headers?.accept || ctx.meta?.$headers?.Accept || '').toLowerCase();
      return accept.includes('text/html');
    },

    setHtmlResponse(ctx) {
      ctx.meta.$responseHeaders = {
        ...(ctx.meta.$responseHeaders || {}),
        'Content-Type': 'text/html; charset=utf-8'
      };
    },

    renderAuthorizePage(context, state) {
      const requestUri = this.escapeHtml(String(context.request_uri || ''));
      const challenge = this.escapeHtml(String(context.consent_challenge || ''));
      const clientId = this.escapeHtml(String(context.client_id || ''));
      const scope = this.escapeHtml(String(context.scope || ''));
      const loginHint = this.escapeHtml(String(context.login_hint || ''));
      const webId = this.escapeHtml(String(state.webId || ''));

      return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Authorize Client</title>
  <style>
    :root { color-scheme: light; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; margin: 0; background: #f6f8fb; color: #1a1f36; }
    .wrap { max-width: 720px; margin: 40px auto; padding: 0 16px; }
    .card { background: #fff; border: 1px solid #dbe2ef; border-radius: 14px; padding: 20px; box-shadow: 0 6px 24px rgba(27, 39, 51, 0.08); }
    h1 { margin: 0 0 10px; font-size: 24px; }
    p { margin: 8px 0; line-height: 1.5; }
    code { background: #f1f5ff; padding: 2px 6px; border-radius: 6px; }
    input[type='text'], input[type='password'] { width: 100%; padding: 10px; border: 1px solid #c9d3e7; border-radius: 8px; margin-top: 6px; }
    .row { display: flex; gap: 12px; flex-wrap: wrap; margin-top: 12px; }
    button { border: 0; border-radius: 8px; padding: 10px 14px; cursor: pointer; font-weight: 600; }
    .ok { background: #0f766e; color: #fff; }
    .deny { background: #b91c1c; color: #fff; }
    .alt { background: #1d4ed8; color: #fff; }
    .muted { color: #445; font-size: 14px; }
  </style>
</head>
<body>
  <div class="wrap">
    <div class="card">
      <h1>Authorize Application</h1>
      <p>Client: <code>${clientId}</code></p>
      <p>Requested scope: <code>${scope || 'atproto'}</code></p>
      <p class="muted">Login hint: ${loginHint || 'none'}</p>
      ${state.hasSession ? `<p class="muted">Signed in as <code>${webId}</code></p>` : `
      <form method="post" action="/oauth/session/login">
        <input type="hidden" name="request_uri" value="${requestUri}" />
        <input type="hidden" name="consent_challenge" value="${challenge}" />
        <label>Username<input type="text" name="username" required /></label>
        <label>Password<input type="password" name="password" required /></label>
        <div class="row"><button class="alt" type="submit">Sign In</button></div>
      </form>`}
      <hr style="border:0;border-top:1px solid #e5ebf5;margin:16px 0;" />
      <form method="post" action="/oauth/authorize">
        <input type="hidden" name="request_uri" value="${requestUri}" />
        <input type="hidden" name="consent_challenge" value="${challenge}" />
        <div class="row">
          <button class="ok" type="submit" name="decision" value="approve">Approve</button>
          <button class="deny" type="submit" name="decision" value="deny">Deny</button>
        </div>
      </form>
    </div>
  </div>
</body>
</html>`;
    },

    escapeHtml(value) {
      return String(value)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
    },

    signSessionPayload(payload) {
      return crypto
        .createHmac('sha256', this.settings.sessionSecret)
        .update(payload, 'utf8')
        .digest('base64url');
    },

    buildSessionToken(webId, sessionId) {
      // Deliberately do not mint a legacy stateless cookie. Every new token
      // contains a CSPRNG nonce registered before the cookie is returned.
      if (typeof sessionId !== 'string' || !/^[A-Za-z0-9_-]{43}$/u.test(sessionId)) {
        throw new Error('Browser session id missing or malformed');
      }
      const iat = Math.floor(Date.now() / 1000);
      const exp = iat + this.settings.sessionTtlSec;
      const payload = Buffer.from(JSON.stringify({ webId, iat, exp, sessionId }), 'utf8').toString('base64url');
      const sig = this.signSessionPayload(payload);
      return `${payload}.${sig}`;
    },

    getSession(ctx) {
      const raw = this.getCookie(ctx, this.settings.sessionCookieName);
      // Only the exact two-segment HMAC token format is valid. The SHA-256
      // base64url MAC has exactly 43 ASCII characters. A malformed or
      // wrong-length signature must be denied before timingSafeEqual (which
      // otherwise throws for unequal buffer lengths).
      if (typeof raw !== 'string' || raw.length > 4096) return null;
      const segments = raw.split('.');
      if (segments.length !== 2) return null;
      const [payload, sig] = segments;
      if (!payload || !/^[A-Za-z0-9_-]{43}$/u.test(sig)) return null;
      const expected = this.signSessionPayload(payload);
      if (!crypto.timingSafeEqual(
        Buffer.from(sig, 'ascii'), Buffer.from(expected, 'ascii')
      )) return null;
      let decoded;
      try {
        decoded = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
      } catch {
        return null;
      }
      const exp = decoded?.exp, iat = decoded?.iat;
      const webId = decoded?.webId, sessionId = decoded?.sessionId;
      const now = Math.floor(Date.now() / 1000);
      if (!Number.isSafeInteger(exp) || !Number.isSafeInteger(iat) ||
          iat > now + 60 || iat < now - 86400 ||
          exp <= now || exp <= iat || exp > iat + this.settings.sessionTtlSec ||
          typeof webId !== 'string' || webId.length < 8 || webId.length > 2048 ||
          typeof sessionId !== 'string' || !/^[A-Za-z0-9_-]{43}$/u.test(sessionId)) {
        return null;
      }
      return { webId, exp, sessionId };
    },

    setSessionCookie(ctx, token) {
      const secure = this.settings.issuer.startsWith('https://');
      const parts = [
        `${this.settings.sessionCookieName}=${encodeURIComponent(token)}`,
        'Path=/oauth',
        'HttpOnly',
        'SameSite=Lax',
        `Max-Age=${this.settings.sessionTtlSec}`
      ];
      if (secure) parts.push('Secure');
      this.appendSetCookie(ctx, parts.join('; '));
    },

    clearSessionCookie(ctx) {
      const secure = this.settings.issuer.startsWith('https://');
      const parts = [
        `${this.settings.sessionCookieName}=`,
        'Path=/oauth',
        'HttpOnly',
        'SameSite=Lax',
        'Max-Age=0'
      ];
      if (secure) parts.push('Secure');
      this.appendSetCookie(ctx, parts.join('; '));
    },

    appendSetCookie(ctx, cookie) {
      const existing = ctx.meta?.$responseHeaders?.['Set-Cookie'];
      if (!existing) {
        ctx.meta.$responseHeaders = {
          ...(ctx.meta.$responseHeaders || {}),
          'Set-Cookie': cookie
        };
        return;
      }

      const values = Array.isArray(existing) ? existing.slice() : [existing];
      values.push(cookie);
      ctx.meta.$responseHeaders = {
        ...(ctx.meta.$responseHeaders || {}),
        'Set-Cookie': values
      };
    },

    parseCanonicalAccountId(value) {
      const canonicalAccountId = String(value || '').trim();
      if (!canonicalAccountId) {
        throw new MoleculerError('canonicalAccountId is required for internal authorization', 400, 'INVALID_REQUEST');
      }
      if (!canonicalAccountId.startsWith('http://') && !canonicalAccountId.startsWith('https://')) {
        throw new MoleculerError('canonicalAccountId must be an absolute URL', 400, 'INVALID_REQUEST');
      }
      return canonicalAccountId;
    },

    async authorizeDecision(ctx, body, csrfToken, canonicalAccountId) {
      const headers = ctx.meta?.$headers || {};
      // A browser approval carries its exact live nonce to the atomic
      // consent grant write, serializing logout against owner approval.
      // Explicitly verified provider bearers have no browser session.
      const ownerSessionId = headers.authorization === undefined &&
        headers.Authorization === undefined ? this.getSession(ctx)?.sessionId : undefined;
      return this.runSafely(() =>
        ctx.call('oauth-authorization.authorize', {
          request_uri: body.request_uri,
          decision: body.decision,
          consentChallenge: body.consent_challenge,
          requestFingerprint: this.requestFingerprint(ctx),
          csrfToken,
          canonicalAccountId,
          ownerSessionId
        })
      );
    },

    getDpopHeader(ctx) {
      const header = ctx.meta?.$headers?.dpop || ctx.meta?.$headers?.DPoP;
      if (!header || typeof header !== 'string') {
        throw new MoleculerError('DPoP proof header is required', 401, 'DPOP_PROOF_REQUIRED');
      }
      return String(header).trim();
    },

    getDpopNonceHeader(ctx) {
      const header = ctx.meta?.$headers?.['dpop-nonce'] || ctx.meta?.$headers?.['DPoP-Nonce'];
      return header ? String(header).trim() : undefined;
    },

    parseCookies(ctx) {
      const cookieHeader = ctx.meta?.$headers?.cookie || ctx.meta?.$headers?.Cookie;
      const cookies = Object.create(null);
      if (!cookieHeader || typeof cookieHeader !== 'string') return cookies;
      for (const part of cookieHeader.split(';')) {
        const [rawKey, ...rest] = part.split('=');
        const key = String(rawKey || '').trim();
        if (!key || key.length > 128) continue;
        const encoded = rest.join('=').trim();
        if (encoded.length > 4096) continue;
        try {
          cookies[key] = decodeURIComponent(encoded);
        } catch {
          // An untrusted malformed percent escape must not turn every OAuth
          // route into HTTP 500 or invalidate other well-formed cookies.
        }
      }
      return cookies;
    },

    getCookie(ctx, name) {
      return this.parseCookies(ctx)[name];
    },

    setCookie(ctx, name, value) {
      const secure = this.settings.issuer.startsWith('https://');
      const parts = [
        `${name}=${encodeURIComponent(String(value))}`,
        'Path=/oauth/authorize',
        'HttpOnly',
        'SameSite=Lax'
      ];
      if (secure) {
        parts.push('Secure');
      }
      this.appendSetCookie(ctx, parts.join('; '));
    },

    requestFingerprint(ctx) {
      const ip = String(ctx.meta?.$remoteIp || '').split(',')[0].trim();
      const userAgent = String(ctx.meta?.$headers?.['user-agent'] || ctx.meta?.$headers?.['User-Agent'] || '');
      return crypto.createHash('sha256').update(`${ip}|${userAgent}`, 'utf8').digest('hex');
    },

    randomToken() {
      return crypto.randomBytes(24).toString('base64url');
    }
  }
};