'use strict';

/**
 * Provider-authoritative provisioning work lease.
 *
 * This module DOES NOT invoke external key/DID issuers or advance the Group
 * lifecycle. It fences an exclusive provisioning attempt in durable TDB2 RDF,
 * with short leases, atomic compare/replace, renewal and safe expiry recovery.
 *
 * No HTTP route, disabled by default. A future isolated provider worker issuer
 * MUST sign lease requests and must never expose its signing key to applications.
 */
const crypto = require('node:crypto');
const { CONSENT_BRIDGE_RELEASED } = require('./utils/collective-release-gate');
const { MoleculerError } = require('moleculer').Errors;
const { WORKER_ID_PATTERN, hashLeaseToken } = require('./utils/collective-worker-lease');

const NS = 'http://activitypods.org/ns/core#';
const PREFIX = 'urn:apods:collective:';
const PURPOSE = 'provider.collective.worker.lease.v1';
const ID = /^cg_[a-f0-9]{32}$/u;
const HASH = /^[a-f0-9]{64}$/u;
const LEASE_TTL_MS = 30000;

function fail(code, status = 403) {
  throw new MoleculerError(code, status, code);
}
function mac(secret, fields) {
  return crypto.createHmac('sha256', secret).update(JSON.stringify(fields)).digest('hex');
}
function literal(value) {
  return JSON.stringify(String(value));
}
function unpack(row, field) {
  const x = row?.[field];
  return typeof x === 'string' ? x : typeof x?.value === 'string' ? x.value : null;
}
function validateInputs({ canonicalGroupId, workerId }, secret) {
  if (!secret || Buffer.byteLength(secret) < 32) fail('COLLECTIVE_WORKER_LEASE_DISABLED', 503);
  if (typeof canonicalGroupId !== 'string' || !ID.test(canonicalGroupId)) fail('COLLECTIVE_INVALID_ID', 400);
  if (typeof workerId !== 'string' || !WORKER_ID_PATTERN.test(workerId)) fail('COLLECTIVE_INVALID_WORKER', 400);
}
function assertGrant(grant, secret, action, groupId, workerId, tokenHash = '', now = Date.now()) {
  if (!grant || grant.purpose !== PURPOSE || grant.operation !== action ||
      grant.groupId !== groupId || grant.workerId !== workerId ||
      grant.tokenHash !== tokenHash ||
      !Number.isSafeInteger(grant.issuedAt) || !Number.isSafeInteger(grant.expiresAt) ||
      grant.issuedAt > now + 10000 || grant.expiresAt < now ||
      grant.expiresAt - grant.issuedAt > 60000 || !HASH.test(grant.mac || '')) {
    fail('COLLECTIVE_WORKER_UNAUTHORIZED');
  }
  const fields = [PURPOSE, action, groupId, workerId, tokenHash, grant.issuedAt, grant.expiresAt];
  const expected = mac(secret, fields);
  if (!crypto.timingSafeEqual(Buffer.from(grant.mac, 'ascii'), Buffer.from(expected, 'ascii'))) {
    fail('COLLECTIVE_WORKER_UNAUTHORIZED');
  }
}
function requireTokenHash(token) {
  const hash = hashLeaseToken(token);
  if (!hash) fail('COLLECTIVE_INVALID_LEASE_TOKEN', 400);
  return hash;
}
function subject(id) { return '<' + PREFIX + id + '>'; }

module.exports = {
  name: 'collective-provisioning-leases',
  settings: {
    enabled: CONSENT_BRIDGE_RELEASED && process.env.PROVIDER_COLLECTIVES_RESERVATIONS_ENABLED === 'true' &&
      process.env.PROVIDER_COLLECTIVES_WORKER_LEASES_ENABLED === 'true',
    secret: process.env.PROVIDER_COLLECTIVES_WORKER_SECRET || '',
    ttlMs: LEASE_TTL_MS
  },
  actions: {
    claim: {
      params: { canonicalGroupId: 'string', workerId: 'string',
        workerGrant: { type: 'object', strict: false } },
      async handler(ctx) {
        if (!this.settings.enabled) fail('COLLECTIVE_WORKER_LEASE_DISABLED', 503);
        const { canonicalGroupId: id, workerId } = ctx.params;
        validateInputs(ctx.params, this.settings.secret);
        assertGrant(ctx.params.workerGrant, this.settings.secret, 'claim', id, workerId);
        const token = crypto.randomBytes(32).toString('base64url');
        const tokenHash = requireTokenHash(token);
        const epoch = crypto.randomUUID();
        const now = Date.now();
        const until = now + this.settings.ttlMs;
        const s = subject(id);
        const query = 'PREFIX apods: <' + NS + '>\nPREFIX xsd: <http://www.w3.org/2001/XMLSchema#>\n' +
          'DELETE { ' + s + ' apods:collectiveLeaseOwner ?oldOwner ; ' +
          'apods:collectiveLeaseHash ?oldHash ; apods:collectiveLeaseUntil ?oldUntil ; ' +
          'apods:collectiveLeaseEpoch ?oldEpoch . }\n' +
          'INSERT { ' + s + ' apods:collectiveLeaseOwner ' + literal(workerId) + ' ; ' +
          'apods:collectiveLeaseHash ' + literal(tokenHash) + ' ; ' +
          'apods:collectiveLeaseUntil ' + literal(until) + ' ; ' +
          'apods:collectiveLeaseEpoch ' + literal(epoch) + ' . }\n' +
          'WHERE { ' + s + ' a apods:CollectiveReservationV1 ; apods:collectiveStage ?stage . ' +
          'FILTER(?stage IN ("reserved", "ap-key-pending", "did-pending")) ' +
          'OPTIONAL { ' + s + ' apods:collectiveLeaseOwner ?oldOwner . } ' +
          'OPTIONAL { ' + s + ' apods:collectiveLeaseHash ?oldHash . } ' +
          'OPTIONAL { ' + s + ' apods:collectiveLeaseUntil ?oldUntil . } ' +
          'OPTIONAL { ' + s + ' apods:collectiveLeaseEpoch ?oldEpoch . } ' +
          'FILTER((!BOUND(?oldOwner) && !BOUND(?oldHash) && !BOUND(?oldUntil) && !BOUND(?oldEpoch)) || ' +
          '(BOUND(?oldOwner) && BOUND(?oldHash) && BOUND(?oldUntil) && BOUND(?oldEpoch) && ' +
          'xsd:integer(?oldUntil) < ' + now + ')) }';
        await ctx.call('triplestore.update', { dataset: 'settings', webId: 'system', query });
        const after = await this._load(ctx, id);
        if (!after || after.owner !== workerId || after.hash !== tokenHash ||
            after.epoch !== epoch || after.until !== until) fail('COLLECTIVE_LEASE_UNAVAILABLE', 409);
        return { canonicalGroupId: id, workerId, leaseToken: token, epoch, expiresAt: until };
      }
    },

    renew: {
      params: { canonicalGroupId: 'string', workerId: 'string', leaseToken: 'string',
        workerGrant: { type: 'object', strict: false } },
      async handler(ctx) {
        if (!this.settings.enabled) fail('COLLECTIVE_WORKER_LEASE_DISABLED', 503);
        const { canonicalGroupId: id, workerId, leaseToken } = ctx.params;
        validateInputs(ctx.params, this.settings.secret);
        const tokenHash = requireTokenHash(leaseToken);
        assertGrant(ctx.params.workerGrant, this.settings.secret, 'renew', id, workerId, tokenHash);
        const before = await this._load(ctx, id);
        const now = Date.now();
        if (!before || before.owner !== workerId || before.hash !== tokenHash ||
            before.until <= now || !before.epoch) fail('COLLECTIVE_LEASE_UNAVAILABLE', 409);
        const until = now + this.settings.ttlMs;
        const s = subject(id);
        const query = 'PREFIX apods: <' + NS + '>\nPREFIX xsd: <http://www.w3.org/2001/XMLSchema#>\n' +
          'DELETE { ' + s + ' apods:collectiveLeaseUntil ' + literal(before.until) + ' . }\n' +
          'INSERT { ' + s + ' apods:collectiveLeaseUntil ' + literal(until) + ' . }\n' +
          'WHERE { ' + s + ' apods:collectiveLeaseOwner ' + literal(workerId) +
          ' ; apods:collectiveLeaseHash ' + literal(tokenHash) +
          ' ; apods:collectiveLeaseEpoch ' + literal(before.epoch) +
          ' ; apods:collectiveLeaseUntil ' + literal(before.until) + ' . ' +
          'FILTER(xsd:integer(' + literal(before.until) + ') > ' + now + ' && ' +
          until + ' > ' + before.until + ') }';
        await ctx.call('triplestore.update', { dataset: 'settings', webId: 'system', query });
        const after = await this._load(ctx, id);
        if (!after || after.owner !== workerId || after.hash !== tokenHash ||
            after.epoch !== before.epoch || after.until !== until) fail('COLLECTIVE_LEASE_UNAVAILABLE', 409);
        return { canonicalGroupId: id, workerId, epoch: after.epoch, expiresAt: until };
      }
    },

    release: {
      params: { canonicalGroupId: 'string', workerId: 'string', leaseToken: 'string',
        workerGrant: { type: 'object', strict: false } },
      async handler(ctx) {
        if (!this.settings.enabled) fail('COLLECTIVE_WORKER_LEASE_DISABLED', 503);
        const { canonicalGroupId: id, workerId, leaseToken } = ctx.params;
        validateInputs(ctx.params, this.settings.secret);
        const tokenHash = requireTokenHash(leaseToken);
        assertGrant(ctx.params.workerGrant, this.settings.secret, 'release', id, workerId, tokenHash);
        const before = await this._load(ctx, id);
        if (!before || before.owner !== workerId || before.hash !== tokenHash) {
          fail('COLLECTIVE_LEASE_UNAVAILABLE', 409);
        }
        const s = subject(id);
        const query = 'PREFIX apods: <' + NS + '>\nDELETE { ' + s +
          ' apods:collectiveLeaseOwner ' + literal(workerId) +
          ' ; apods:collectiveLeaseHash ' + literal(tokenHash) +
          ' ; apods:collectiveLeaseUntil ' + literal(before.until) +
          ' ; apods:collectiveLeaseEpoch ' + literal(before.epoch) + ' . }\n' +
          'WHERE { ' + s + ' apods:collectiveLeaseOwner ' + literal(workerId) +
          ' ; apods:collectiveLeaseHash ' + literal(tokenHash) +
          ' ; apods:collectiveLeaseUntil ' + literal(before.until) +
          ' ; apods:collectiveLeaseEpoch ' + literal(before.epoch) + ' . }';
        await ctx.call('triplestore.update', { dataset: 'settings', webId: 'system', query });
        const after = await this._load(ctx, id);
        if (after?.hash === tokenHash) fail('COLLECTIVE_LEASE_UNAVAILABLE', 409);
        return { released: true };
      }
    }
  },

  methods: {
    async _load(ctx, id) {
      const s = subject(id);
      const rows = await ctx.call('triplestore.query', {
        dataset: 'settings', webId: 'system',
        query: 'PREFIX apods: <' + NS + '>\n' +
          'SELECT ?owner ?hash ?until ?epoch WHERE { ' + s +
          ' a apods:CollectiveReservationV1 . OPTIONAL { ' + s +
          ' apods:collectiveLeaseOwner ?owner ; apods:collectiveLeaseHash ?hash ; ' +
          'apods:collectiveLeaseUntil ?until ; apods:collectiveLeaseEpoch ?epoch . } }\nLIMIT 2'
      });
      if (!Array.isArray(rows) || !rows.length) return null;
      if (rows.length !== 1) fail('COLLECTIVE_CORRUPT_LEASE', 500);
      const row = rows[0];
      const owner = unpack(row, 'owner');
      const hash = unpack(row, 'hash');
      const untilRaw = unpack(row, 'until');
      const epoch = unpack(row, 'epoch');
      if (!owner && !hash && !untilRaw && !epoch) return {};
      const until = Number(untilRaw);
      if (!owner || !hash || !HASH.test(hash) || !epoch ||
          !Number.isSafeInteger(until) || until < 1) fail('COLLECTIVE_CORRUPT_LEASE', 500);
      return { owner, hash, until, epoch };
    }
  }
};
