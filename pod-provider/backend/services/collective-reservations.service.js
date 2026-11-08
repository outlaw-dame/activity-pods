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
const { MoleculerError } = require('moleculer').Errors;

const NS = 'http://activitypods.org/ns/core#';
const TYPE = 'CollectiveReservationV1';
const PREFIX = 'urn:apods:collective:';
const STAGES = Object.freeze(['reserved', 'ap-key-pending', 'did-pending']);
const GRANT_PURPOSE = 'provider.collective.reservation.v1';

function problem(code, status = 403) {
  return new MoleculerError(code, status, code);
}

function exactHttps(value) {
  if (typeof value !== 'string' || value.length > 2048 || /[\u0000-\u0020\u007f\\]/u.test(value)) {
    throw problem('COLLECTIVE_INVALID_URI', 400);
  }
  let parsed;
  try { parsed = new URL(value); } catch { throw problem('COLLECTIVE_INVALID_URI', 400); }
  if (parsed.protocol !== 'https:' || parsed.username || parsed.password ||
      parsed.href !== value || parsed.search || parsed.hash) throw problem('COLLECTIVE_INVALID_URI', 400);
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
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length || a.length > 256) return false;
  return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
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

function validateInput(params, baseUrl, identityKey) {
  const principal = exactHttps(params.principal).href;
  const app = exactHttps(params.app).href;
  const provider = exactHttps(baseUrl);
  if (provider.origin !== baseUrl) throw problem('COLLECTIVE_INVALID_PROVIDER', 503);
  const idempotencyKey = requireString(params.idempotencyKey, /^[a-zA-Z0-9_-]{24,128}$/u, 'COLLECTIVE_INVALID_IDEMPOTENCY');
  const displayName = requireString(params.displayName, /^[^\u0000-\u001f\u007f]{1,160}$/u, 'COLLECTIVE_INVALID_DISPLAY_NAME');
  const canonical = JSON.stringify([principal, app, idempotencyKey, displayName]);
  const requestHash = crypto.createHash('sha256').update(canonical).digest('hex');
  const groupId = 'cg_' + hmac(identityKey, JSON.stringify([principal, app, idempotencyKey])).slice(0, 32);
  return { principal, app, displayName, idempotencyKey, requestHash, groupId,
    actorUri: baseUrl + '/groups/' + groupId, uri: PREFIX + groupId };
}

module.exports = {
  name: 'collective-reservations',
  settings: {
    enabled: process.env.PROVIDER_COLLECTIVES_RESERVATIONS_ENABLED === 'true',
    providerOrigin: process.env.SEMAPPS_HOME_URL || '',
    secret: process.env.PROVIDER_COLLECTIVES_GRANT_SECRET || '',
    identityKey: process.env.PROVIDER_COLLECTIVES_ID_KEY || ''
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
        // The recorded creator application is provenance, NOT exclusive authority.
        const q = (predicate, value) => '  <' + NS + predicate + '> ' + sparqlString(value) + ' ;\n';
        const record = '<' + p.uri + '> a <' + NS + TYPE + '> ;\n' +
          q('canonicalGroupId', p.groupId) +
          q('activityPubActorId', p.actorUri) +
          q('collectiveOwner', p.principal) +
          q('collectiveApp', p.app) +
          q('collectiveRequestHash', p.requestHash) +
          q('collectiveDisplayName', p.displayName) +
          q('collectiveStage', 'reserved') +
          q('collectiveRevision', '1') +
          '  <' + NS + 'collectiveCreatedAt> ' + sparqlString(new Date().toISOString()) + ' .';
        // TDB2/Fuseki dataset transactions serialize concurrent SPARQL writes;
        // no SELECT-then-INSERT race. The deterministic group ID provides
        // request-scoped idempotency independently of individual worker memory.
        await ctx.call('triplestore.update', {
          dataset: 'settings', webId: 'system',
          query: 'INSERT { ' + record + ' } WHERE { FILTER NOT EXISTS { <' + p.uri + '> ?existing ?value . } }'
        });
        const stored = await this._load(ctx, p.groupId);
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
        const principal = exactHttps(ctx.params.principal).href;
        const app = exactHttps(ctx.params.app).href;
        assertGrant(ctx.params.grant, this.settings.secret, principal, app, 'read', groupId);
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
        grant: { type: 'object', strict: false } },
      async handler(ctx) {
        if (!this.settings.enabled) throw problem('COLLECTIVE_DISABLED', 503);
        const groupId = requireString(ctx.params.canonicalGroupId, /^cg_[a-f0-9]{32}$/u, 'COLLECTIVE_INVALID_ID');
        const principal = exactHttps(ctx.params.principal).href;
        const app = exactHttps(ctx.params.app).href;
        const next = ctx.params.nextStage, revision = ctx.params.expectedRevision;
        const payloadHash = crypto.createHash('sha256').update(JSON.stringify([groupId, revision, next])).digest('hex');
        assertGrant(ctx.params.grant, this.settings.secret, principal, app, 'advance', payloadHash);
        const before = await this._load(ctx, groupId);
        if (!before || before.owner !== principal) throw problem('COLLECTIVE_NOT_FOUND', 404);
        if (before.revision !== revision) throw problem('COLLECTIVE_STALE_REVISION', 409);
        if (STAGES.indexOf(next) !== STAGES.indexOf(before.stage) + 1) {
          throw problem('COLLECTIVE_INVALID_TRANSITION', 409);
        }
        // A per-transition nonce prevents a losing same-stage race from
        // incorrectly observing the winner's state and reporting success.
        const transitionId = crypto.randomUUID();
        await ctx.call('triplestore.update', {
          dataset: 'settings', webId: 'system',
          query: 'PREFIX apods: <' + NS + '>\n' +
            'DELETE { <' + PREFIX + groupId + '> apods:collectiveStage ' + sparqlString(before.stage) +
            ' ; apods:collectiveRevision ' + sparqlString(String(revision)) +
            ' . <' + PREFIX + groupId + '> apods:collectiveLastTransition ?previousTransition . }\n' +
            'INSERT { <' + PREFIX + groupId + '> apods:collectiveStage ' + sparqlString(next) +
            ' ; apods:collectiveRevision ' + sparqlString(String(revision + 1)) +
            ' ; apods:collectiveLastTransition ' + sparqlString(transitionId) + ' . }\n' +
            'WHERE { <' + PREFIX + groupId + '> apods:collectiveStage ' + sparqlString(before.stage) +
            ' ; apods:collectiveRevision ' + sparqlString(String(revision)) +
            ' . OPTIONAL { <' + PREFIX + groupId + '> apods:collectiveLastTransition ?previousTransition . } }'
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
          'SELECT ?owner ?app ?requestHash ?actorUri ?displayName ?stage ?revision ?lastTransition WHERE {\n' +
          '  <' + subject + '> a apods:' + TYPE + ' ;\n' +
          '    apods:collectiveOwner ?owner ; apods:collectiveApp ?app ;\n' +
          '    apods:collectiveRequestHash ?requestHash ;\n' +
          '    apods:activityPubActorId ?actorUri ;\n' +
          '    apods:collectiveDisplayName ?displayName ;\n' +
          '    apods:collectiveStage ?stage ; apods:collectiveRevision ?revision .\n' +
          '  OPTIONAL { <' + subject + '> apods:collectiveLastTransition ?lastTransition . }\n}\nLIMIT 2'
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
        displayName: unpack(row, 'displayName'), lastTransition: unpack(row, 'lastTransition'), stage, revision };
    }
  }
};
