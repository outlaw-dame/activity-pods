'use strict';

const { Errors: { MoleculerError } } = require('moleculer');
const unifiedAccountApi = require('../services/unified-account-api.service');
const { createProviderEnrollmentHandoff } = require('./provider-enrollment-handoff');
const { createProviderBrowserEnrollment } = require('./provider-browser-enrollment');

/**
 * Explicit local-runtime factory, never autoloaded. The same process's trusted
 * signup coordinator owns issue(); only view and consent get HTTP aliases.
 * loadRequirements must resolve and hash the approved app's permission semantics,
 * not trust a browser manifest, dc:modified label or a digest of identifiers alone.
 */
function makeBrowserEnrollmentService({ broker, handoffPool, lifecycle, ...options } = {}) {
  if (!broker || typeof broker.call !== 'function') throw new Error('Enrollment broker required');
  const enrollment = createProviderBrowserEnrollment({
    ...options,
    registerApp: async ({ webId, username, appUri, acceptedAccessNeeds, acceptedSpecialRights }) => {
      const account = await broker.call('auth.account.findByWebId', { webId },
        { meta: {}, timeout: 5000, retries: 0 });
      if (!account || account.webId !== webId || account.username !== username ||
          typeof account.signupReservationId !== 'string' ||
          !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(account.signupReservationId)) {
        throw new Error('Pending owner account mismatch');
      }
      // Caller-selected WebID, dataset, app and acceptAllRequirements never
      // enter this call. The owner comes exclusively from the durable journal.
      return broker.call('auth-agent.registerApp',
        { appUri, acceptedAccessNeeds, acceptedSpecialRights },
        { meta: { webId, dataset: username }, timeout: 30000, retries: 0 });
    }
  });
  function responseHeaders(ctx) {
    ctx.meta.$responseHeaders = { ...ctx.meta.$responseHeaders,
      'Cache-Control': 'no-store', 'Pragma': 'no-cache', 'Vary': 'Origin' };
  }
  async function run(ctx, operation, params) {
    responseHeaders(ctx);
    try {
      return await enrollment[operation]({ ...params,
        cookie: ctx.meta.enrollmentCookie, origin: ctx.meta.enrollmentOrigin });
    } catch (error) {
      const type = typeof error.code === 'string' && /^ENROLLMENT_[A-Z_]+$/u.test(error.code)
        ? error.code : 'ENROLLMENT_UNAVAILABLE';
      throw new MoleculerError('Enrollment is unavailable or requires reconciliation',
        type === 'ENROLLMENT_ALREADY_CLAIMED' ? 409 : 403, type, { retryable: false });
    }
  }
  const schema = {
    name: 'signup-enrollment',
    dependencies: ['api', 'auth.account', 'auth-agent'],
    async started() {
      enrollment.assertEnabled();
      await this.broker.call('api.addRoute', { route: {
        name: 'signup-enrollment', path: '/api/signup-enrollment',
        authentication: false, authorization: false, mappingPolicy: 'restrict',
        whitelist: ['signup-enrollment.view', 'signup-enrollment.consent'],
        bodyParsers: { json: { strict: true, limit: '16kb' } },
        cors: { origin: options.browserOrigin, credentials: true, methods: ['GET', 'POST', 'OPTIONS'] },
        onBeforeCall(ctx, route, req) {
          ctx.meta.enrollmentCookie = req.headers.cookie;
          ctx.meta.enrollmentOrigin = req.headers.origin;
        },
        aliases: { 'GET /': 'signup-enrollment.view', 'POST /consent': 'signup-enrollment.consent' }
      }, toBottom: false });
    },
    actions: {
      view: {
        bulkhead: { enabled: true, concurrency: 8, maxQueueSize: 16 },
        handler(ctx) { return run(ctx, 'view', {}); }
      },
      consent: {
        bulkhead: { enabled: true, concurrency: 4, maxQueueSize: 8 },
        params: {
          $$strict: true,
          csrfToken: { type: 'string', length: 43 },
          approve: 'boolean',
          selected: { type: 'array', items: { type: 'string', max: 2048 }, max: 128, optional: true }
        },
        handler(ctx) { return run(ctx, 'consent', ctx.params); }
      }
    }
  };
  // Keep issuance outside the HTTP/service action namespace. The coordinator
  // must bind the existing canonical operation before using this local method.
  const beginEnrollment = handoffPool && lifecycle
    ? createProviderEnrollmentHandoff({ ...options, broker, handoffPool, lifecycle, issue: enrollment.issue })
    : undefined;
  const signupApi = beginEnrollment ? {
    ...unifiedAccountApi,
    methods: {
      ...unifiedAccountApi.methods,
      beginDisposableEnrollment: beginEnrollment
    }
  } : undefined;
  return Object.freeze({ schema, issue: enrollment.issue, signupApi });
}

module.exports = { makeBrowserEnrollmentService };
