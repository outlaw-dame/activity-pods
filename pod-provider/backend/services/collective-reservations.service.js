'use strict';

/*
 * Internal G1 collective reservation service. The settings Fuseki dataset is
 * authoritative; Redis, the sidecar, legacy Group Pods, and account records are
 * NOT identity authorities.
 *
 * Deliberate safety boundary: NO public HTTP route, NO automatic Group
 * activation, NO keys or DIDs issued, and NO caller-controlled system bypass.
 * A separate trusted provider-issued HMAC operation grant is required for
 * EVERY access. The issuer must enforce SAI/user consent before signing; this
 * service does not issue grants itself. Disabled unless explicitly configured.
 */
const crypto = require('node:crypto');
const { CONSENT_BRIDGE_RELEASED } = require('./utils/collective-release-gate');
const { consentSubject } = require('./collective-consent-fence.service');
const { MoleculerError } = require('moleculer').Errors;
const { parseApprovedApps, assertLiveCollectiveConsent } = require('./utils/collective-access-policy');
const { reserveFingerprint } = require('./utils/collective-grant-claims');
const { leaseReference } = require('./utils/collective-worker-lease');

const NS = 'http://activitypods.org/ns/core#';
const TYPE = 'CollectiveReservationV1';
const PREFIX = 'urn:apods:collective:';
const STAGES = Object.freeze(['reserved', 'ap-key-pending', 'did-pending']);
const GRANT_PURPOSE = 'provider.collective.reservation.v1';
const WORKER_PURPOSE = 'provider.collective.worker.advance.v1';

function problem(code, status = 403) {
  return new MoleculerError(code, status, code);
}

function exactHttps(value, { allowFragment = false } = {}) {
  if (typeof value !== 'string' || value.length > 2048 || /[\u0000-\u0020\u007f\\]/u.test(value)) {
    throw problem('COLLECTIVE_INVALID_URI', 400);
  }
  let parsed;
  try { parsed = new URL(value); } catch { throw problem('COLLECTIVE_INVALID_URI', 400); }
  // Solid WebIDs can contain #me, but an application actor URI used as an
  // app-scoped grant identifier must remain an exact, fragment-free URI.
  if (parsed.protocol !== 'https:' || parsed.username || parsed.password ||
      parsed.href !== value || parsed.search || (!allowFragment && parsed.hash)) {
    throw problem('COLLECTIVE_INVALID_URI', 400);
  }
  return parsed;
}

function requireString(value, pattern, code) {
  if (typeof value !== 'string' || !pattern.test(value)) throw problem(code, 400);
  return value;
}

function hmac(key, text) {
  return crypto.createHmac('sha256', key).update(text).digest('hex');
}

function safeCompare(a, b) {
  // HMAC-SHA256 hex digests are exactly 64 ASCII hex digits. Comparing only JS
  // string lengths lets Unicode strings become unequal byte lengths and makes
  // timingSafeEqual throw instead of returning an authorization denial.
  if (typeof a !== 'string' || typeof b !== 'string' ||
      !/^[0-9a-f]{64}$/u.test(a) || !/^[0-9a-f]{64}$/u.test(b)) return false;
  return crypto.timingSafeEqual(Buffer.from(a, 'ascii'), Buffer.from(b, 'ascii'));
}

function sparqlString(value) {
  return JSON.stringify(value);
}

function unpack(row, name) {
  const x = row?.[name];
  return typeof x === 'string' ? x : (typeof x?.value === 'string' ? x.value : null);
}

/**
 * Trusted authorization issuer must emit:
 * {purpose, principal, app, operation, requestHash, issuedAt, expiresAt, mac}
 * mac=HMAC-SHA256 of JSON.stringify([purpose,principal,app,operation,
 * requestHash,issuedAt,expiresAt]) with PROVIDER_COLLECTIVES_GRANT_SECRET.
 * No untrusted service is allowed to mint the grant.
 */
function assertGrant(grant, secret, principal, app, operation, requestHash, now = Date.now()) {
  if (!secret || Buffer.byteLength(secret) < 32) throw problem('COLLECTIVE_DISABLED', 503);
  if (!grant || grant.purpose !== GRANT_PURPOSE || grant.principal !== principal ||
      grant.app !== app || grant.operation !== operation || grant.requestHash !== requestHash ||
      !Number.isSafeInteger(grant.issuedAt) || !Number.isSafeInteger(grant.expiresAt) ||
      grant.issuedAt > now + 30000 || grant.expiresAt < now ||
      grant.expiresAt - grant.issuedAt > 120000) throw problem('COLLECTIVE_UNAUTHORIZED');
  const fields = [grant.purpose, principal, app, operation, requestHash, grant.issuedAt, grant.expiresAt];
  if (!safeCompare(grant.mac, hmac(secret, JSON.stringify(fields)))) throw problem('COLLECTIVE_UNAUTHORIZED');
}

/**
 * Worker-only transitions are NOT application rights. This credential uses a
 * distinct secret and purpose, so a valid SAI app grant—even if mistaken for
 * an advance operation—cannot move provisioning state.
 */
function assertWorkerGrant(grant, secret, groupId, revision, nextStage, lease, now = Date.now()) {
  if (!secret || Buffer.byteLength(secret) < 32) throw problem('COLLECTIVE_WORKER_DISABLED', 503);
  if (!grant || grant.purpose !== WORKER_PURPOSE || grant.groupId !== groupId ||
      grant.revision !== revision || grant.nextStage !== nextStage ||
      grant.workerId !== lease.workerId || grant.leaseEpoch !== lease.leaseEpoch ||
      grant.leaseHash !== lease.hash ||
      !Number.isSafeInteger(grant.issuedAt) || !Number.isSafeInteger(grant.expiresAt) ||
      grant.issuedAt > now + 30000 || grant.expiresAt < now ||
      grant.expiresAt - grant.issuedAt > 120000) throw problem('COLLECTIVE_WORKER_UNAUTHORIZED');
  const fields = [WORKER_PURPOSE, groupId, revision, nextStage,
    lease.workerId, lease.leaseEpoch, lease.hash, grant.issuedAt, grant.expiresAt];
  if (!safeCompare(grant.mac, hmac(secret, JSON.stringify(fields)))) {
    throw problem('COLLECTIVE_WORKER_UNAUTHORIZED');
  }
}

function validateInput(params, baseUrl, identityKey) {
  const principal = exactHttps(params.principal, { allowFragment: true }).href;
  const app = exactHttps(params.app).href;
  // Provider origin is a bare HTTPS origin; WHATWG serializes it with a
  // trailing slash. Do not apply resource-URL exactness rules to an origin.
  if (typeof baseUrl !== 'string' || baseUrl.length > 256 ||
      /[\u0000-\u0020\u007f\\]/u.test(baseUrl)) {
    throw problem('COLLECTIVE_INVALID_PROVIDER', 503);
  }
  let provider;
  try { provider = new URL(baseUrl); } catch { throw problem('COLLECTIVE_INVALID_PROVIDER', 503); }
  if (provider.protocol !== 'https:' || !provider.hostname ||
      provider.pathname !== '/' || provider.origin !== baseUrl.replace(/\/$/u, '') ||
      provider.username || provider.password || provider.search || provider.hash) {
    throw problem('COLLECTIVE_INVALID_PROVIDER', 503);
  }
  const idempotencyKey = requireString(params.idempotencyKey, /^[a-zA-Z0-9_-]{24,128}$/u, 'COLLECTIVE_INVALID_IDEMPOTENCY');
  const displayName = requireString(params.displayName, /^[^\u0000-\u001f\u007f]{1,160}$/u, 'COLLECTIVE_INVALID_DISPLAY_NAME');
  const requestHash = reserveFingerprint(principal, app, idempotencyKey, displayName);
  const groupId = 'cg_' + hmac(identityKey, JSON.stringify([principal, app, idempotencyKey])).slice(0, 32);
  return { principal, app, displayName, idempotencyKey, requestHash, groupId,
    actorUri: provider.origin + '/groups/' + groupId, uri: PREFIX + groupId };
}

module.exports = {
  name: 'collective-reservations',
  settings: {
    enabled: CONSENT_BRIDGE_RELEASED &&
      process.env.PROVIDER_COLLECTIVES_CONSENT_BRIDGE_ENABLED === 'true' &&
      process.env.PROVIDER_COLLECTIVES_RESERVATIONS_ENABLED === 'true',
    providerOrigin: process.env.SEMAPPS_HOME_URL || '',
    secret: process.env.PROVIDER_COLLECTIVES_GRANT_SECRET || '',
    identityKey: process.env.PROVIDER_COLLECTIVES_ID_KEY || '',
    workerSecret: process.env.PROVIDER_COLLECTIVES_WORKER_SECRET || '',
    approvedApps: parseApprovedApps(process.env.PROVIDER_COLLECTIVES_APPROVED_APPS || ''),
    consentBridgeEnabled: CONSENT_BRIDGE_RELEASED &&
      process.env.PROVIDER_COLLECTIVES_CONSENT_BRIDGE_ENABLED === 'true'
  },
  actions: {
    reserve: {
      params: {
        principal: 'string|min:1', app: 'string|min:1',
        idempotencyKey: 'string|min:24',
        displayName: 'string|min:1',
        grant: { type: 'object', strict: false }
      },
      async handler(ctx) {
        if (!this.settings.enabled) throw problem('COLLECTIVE_DISABLED', 503);
        if (!this.settings.secret || Buffer.byteLength(this.settings.secret) < 32 ||
            !this.settings.identityKey || Buffer.byteLength(this.settings.identityKey) < 32) {
          throw problem('COLLECTIVE_DISABLED', 503);
        }
        const p = validateInput(ctx.params, this.settings.providerOrigin, this.settings.identityKey);
        assertGrant(ctx.params.grant, this.settings.secret, p.principal, p.app, 'reserve', p.requestHash);
        await assertLiveCollectiveConsent(ctx, {
          principal: p.principal, app: p.app, operation: 'reserve',
          approvedApps: this.settings.approvedApps
        });
        // The recorded creator application is provenance, NOT exclusive authority.
        const q = (predicate, value) => '  <' + NS + predicate + '> ' + sparqlString(value) + ' ;\n';
        const ledger = this.settings.consentBridgeEnabled
          ? consentSubject(p.principal, p.app) : null;
        const record = '<' + p.uri + '> a <' + NS + TYPE + '> ;\n' +
          q('canonicalGroupId', p.groupId) +
          q('activityPubActorId', p.actorUri) +
          q('collectiveOwner', p.principal) +
          q('collectiveApp', p.app) +
          q('collectiveRequestHash', p.requestHash) +
          q('collectiveDisplayName', p.displayName) +
          (ledger ? '  <' + NS + 'collectiveConsentRevision> ?consentRevision ;\n' : '') +
          q('collectiveStage', 'reserved') +
          q('collectiveRevision', '1') +
          '  <' + NS + 'collectiveCreatedAt> ' + sparqlString(new Date().toISOString()) + ' .';
        // TDB2/Fuseki dataset transactions serialize concurrent SPARQL writes;
        // no SELECT-then-INSERT race. The deterministic group ID provides
        // request-scoped idempotency independently of individual worker memory.
        await ctx.call('triplestore.update', {
          dataset: 'settings', webId: 'system',
          query: 'INSERT { ' + record + ' } WHERE { ' +
            (ledger ? ledger + ' <' + NS + 'collectiveConsentStatus> "stable" ; ' +
              '<' + NS + 'collectiveConsentRevision> ?consentRevision . ' +
              'FILTER NOT EXISTS { ' + ledger + ' <' + NS +
              'collectivePendingMutation> ?pending . } ' : '') +
            'FILTER NOT EXISTS { <' + p.uri + '> ?existing ?value . } }'
        });
        // This is a containment check, NOT a cross-store atomic fence.
        // If the user revokes SAI while the Fuseki write is in flight, do not
        // return a successful reservation. A private, inactive record can
        // still be left behind; deployment remains disabled until a truly
        // transactionally fenced policy/commit boundary exists.
        await assertLiveCollectiveConsent(ctx, {
          principal: p.principal, app: p.app, operation: 'reserve',
          approvedApps: this.settings.approvedApps
        });
        const stored = await this._load(ctx, p.groupId);
        if (ledger && !stored) throw problem('COLLECTIVE_CONSENT_FENCE_REQUIRED', 503);
        if (!stored || stored.requestHash !== p.requestHash ||
            stored.owner !== p.principal || stored.app !== p.app ||
            stored.actorUri !== p.actorUri) throw problem('COLLECTIVE_RESERVATION_CONFLICT', 409);
        return { canonicalGroupId: p.groupId, actorUri: p.actorUri,
          stage: stored.stage, revision: stored.revision };
      }
    },

    get: {
      params: { canonicalGroupId: 'string|min:12', principal: 'string|min:1',
        app: 'string|min:1', grant: { type: 'object', strict: false } },
      async handler(ctx) {
        if (!this.settings.enabled) throw problem('COLLECTIVE_DISABLED', 503);
        const groupId = requireString(ctx.params.canonicalGroupId, /^cg_[a-f0-9]{32}$/u, 'COLLECTIVE_INVALID_ID');
        const principal = exactHttps(ctx.params.principal, { allowFragment: true }).href;
        const app = exactHttps(ctx.params.app).href;
        assertGrant(ctx.params.grant, this.settings.secret, principal, app, 'read', groupId);
        await assertLiveCollectiveConsent(ctx, {
          principal, app, operation: 'read', approvedApps: this.settings.approvedApps
        });
        const result = await this._load(ctx, groupId);
        if (!result || result.owner !== principal) throw problem('COLLECTIVE_NOT_FOUND', 404);
        return { canonicalGroupId: groupId, actorUri: result.actorUri, stage: result.stage,
          revision: result.revision, displayName: result.displayName };
      }
    },

    advance: {
      params: { canonicalGroupId: 'string|min:12', principal: 'string|min:1',
        app: 'string|min:1', expectedRevision: 'number|integer|min:1',
        nextStage: { type: 'enum', values: STAGES.slice(1) },
        workerId: 'string', leaseEpoch: 'string', leaseToken: 'string',
        workerGrant: { type: 'object', strict: false } },
      async handler(ctx) {
        if (!this.settings.enabled) throw problem('COLLECTIVE_DISABLED', 503);
        const groupId = requireString(ctx.params.canonicalGroupId, /^cg_[a-f0-9]{32}$/u, 'COLLECTIVE_INVALID_ID');
        const principal = exactHttps(ctx.params.principal, { allowFragment: true }).href;
        const app = exactHttps(ctx.params.app).href;
        const next = ctx.params.nextStage, revision = ctx.params.expectedRevision;
        const lease = leaseReference(ctx.params);
        if (!lease) throw problem('COLLECTIVE_WORKER_UNAUTHORIZED');
        assertWorkerGrant(ctx.params.workerGrant, this.settings.workerSecret, groupId, revision, next, lease);
        const now = Date.now();
        const before = await this._load(ctx, groupId);
        if (!before || before.owner !== principal) throw problem('COLLECTIVE_NOT_FOUND', 404);
        if (before.revision !== revision) throw problem('COLLECTIVE_STALE_REVISION', 409);
        // A worker grant authorizes only the worker; it does not supersede the
        // person's SAI consent. Any later consent revision blocks provisioning
        // until a deliberately reviewed recovery path authorizes it.
        if (this.settings.consentBridgeEnabled) {
          if (!before.consentRevision) throw problem('COLLECTIVE_CONSENT_FENCE_REQUIRED', 503);
          await assertLiveCollectiveConsent(ctx, {
            principal, app: before.app, operation: 'reserve',
            approvedApps: this.settings.approvedApps
          });
        }
        if (STAGES.indexOf(next) !== STAGES.indexOf(before.stage) + 1) {
          throw problem('COLLECTIVE_INVALID_TRANSITION', 409);
        }
        // A per-transition nonce prevents a losing same-stage race from
        // incorrectly observing the winner's state and reporting success.
        const transitionId = crypto.randomUUID();
        await ctx.call('triplestore.update', {
          dataset: 'settings', webId: 'system',
          query: 'PREFIX apods: <' + NS + '>\nPREFIX xsd: <http://www.w3.org/2001/XMLSchema#>\n' +
            'DELETE { <' + PREFIX + groupId + '> apods:collectiveStage ' + sparqlString(before.stage) +
            ' ; apods:collectiveRevision ' + sparqlString(String(revision)) +
            ' . <' + PREFIX + groupId + '> apods:collectiveLastTransition ?previousTransition . }\n' +
            'INSERT { <' + PREFIX + groupId + '> apods:collectiveStage ' + sparqlString(next) +
            ' ; apods:collectiveRevision ' + sparqlString(String(revision + 1)) +
            ' ; apods:collectiveLastTransition ' + sparqlString(transitionId) + ' . }\n' +
            'WHERE { <' + PREFIX + groupId + '> apods:collectiveStage ' + sparqlString(before.stage) +
            ' ; apods:collectiveRevision ' + sparqlString(String(revision)) +
            ' ; apods:collectiveLeaseOwner ' + sparqlString(lease.workerId) +
            ' ; apods:collectiveLeaseHash ' + sparqlString(lease.hash) +
            ' ; apods:collectiveLeaseEpoch ' + sparqlString(lease.leaseEpoch) +
            ' ; apods:collectiveLeaseUntil ?heldUntil . ' +
            (this.settings.consentBridgeEnabled ?
              '<' + PREFIX + groupId + '> apods:collectiveConsentRevision ?reservationConsentRevision . ' +
              consentSubject(before.owner, before.app) +
              ' apods:collectiveConsentStatus "stable" ; apods:collectiveConsentRevision ?liveConsentRevision . ' +
              'FILTER(?reservationConsentRevision = ?liveConsentRevision) ' +
              'FILTER NOT EXISTS { ' + consentSubject(before.owner, before.app) +
              ' apods:collectivePendingMutation ?pending . } ' : '') +
            'FILTER(xsd:integer(?heldUntil) > ' + now + ') ' +
            'OPTIONAL { <' + PREFIX + groupId + '> apods:collectiveLastTransition ?previousTransition . } }'
        });
        const after = await this._load(ctx, groupId);
        if (!after || after.stage !== next || after.revision !== revision + 1 || after.lastTransition !== transitionId) {
          throw problem('COLLECTIVE_STALE_REVISION', 409);
        }
        return { canonicalGroupId: groupId, stage: after.stage, revision: after.revision };
      }
    }
  },

  methods: {
    async _load(ctx, groupId) {
      const subject = PREFIX + groupId;
      const rows = await ctx.call('triplestore.query', {
        dataset: 'settings', webId: 'system',
        query: 'PREFIX apods: <' + NS + '>\n' +
          'SELECT ?owner ?app ?requestHash ?actorUri ?displayName ?stage ?revision ?lastTransition ?consentRevision WHERE {\n' +
          '  <' + subject + '> a apods:' + TYPE + ' ;\n' +
          '    apods:collectiveOwner ?owner ; apods:collectiveApp ?app ;\n' +
          '    apods:collectiveRequestHash ?requestHash ;\n' +
          '    apods:activityPubActorId ?actorUri ;\n' +
          '    apods:collectiveDisplayName ?displayName ;\n' +
          '    apods:collectiveStage ?stage ; apods:collectiveRevision ?revision .\n' +
          '  OPTIONAL { <' + subject + '> apods:collectiveLastTransition ?lastTransition . }\n' +
          '  OPTIONAL { <' + subject + '> apods:collectiveConsentRevision ?consentRevision . }\n}\nLIMIT 2'
      });
      if (!Array.isArray(rows) || rows.length === 0) return null;
      if (rows.length !== 1) throw problem('COLLECTIVE_CORRUPT_STATE', 500);
      const row = rows[0], revision = Number(unpack(row, 'revision'));
      const stage = unpack(row, 'stage');
      if (!Number.isSafeInteger(revision) || revision < 1 || !STAGES.includes(stage)) {
        throw problem('COLLECTIVE_CORRUPT_STATE', 500);
      }
      return { owner: unpack(row, 'owner'), app: unpack(row, 'app'),
        requestHash: unpack(row, 'requestHash'), actorUri: unpack(row, 'actorUri'),
        displayName: unpack(row, 'displayName'), lastTransition: unpack(row, 'lastTransition'),
        consentRevision: unpack(row, 'consentRevision'), stage, revision };
    }
  }
};
