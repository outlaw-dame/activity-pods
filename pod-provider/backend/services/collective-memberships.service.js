'use strict';

/**
 * Provider-owned G2 membership control-plane service.
 * No HTTP route, application-supplied owner identity, Group Pod, new login,
 * sender key, federation issuer or public Group activation.
 *
 * Signer is NOT implemented here: a future existing Solid-OIDC/SAI gateway
 * must verify the user and approved app BEFORE issuing an operation-bound
 * HMAC. Until that gateway and the live Group actor are reviewed, the
 * immutable G1 release fuse keeps ALL actions disabled in production.
 */
const crypto = require('node:crypto');
const { MoleculerError } = require('moleculer').Errors;
const { CONSENT_BRIDGE_RELEASED } = require('./utils/collective-release-gate');
const { parseApprovedApps } = require('./utils/collective-access-policy');
const rdf = require('../utils/collective-membership-rdf');

const PURPOSE = 'provider.collective.membership.v1';
const NS = 'http://activitypods.org/ns/core#';

function deny(code, status = 403) { throw new MoleculerError(code, status, code); }
function hash(value) { return crypto.createHash('sha256').update(JSON.stringify(value)).digest('hex'); }
function getValue(row, field) {
  const data = row?.[field];
  return typeof data === 'string' ? data : data?.value;
}
function canonicalRequest(operation, params) {
  const { groupId, owner, app } = params;
  rdf.validateId(groupId);
  rdf.validateActor(owner);
  rdf.validateActor(app);
  switch (operation) {
    case 'initialize':
      return hash([operation, groupId, owner, app]);
    case 'change':
      rdf.validateActor(params.member);
      if (!rdf.ROLES.has(params.role) || !rdf.STATUSES.has(params.status)) deny('GROUP_MEMBER_INVALID_INPUT', 400);
      if (!Number.isSafeInteger(params.expectedEpoch) || params.expectedEpoch < 1) {
        deny('GROUP_MEMBERSHIP_INVALID_EPOCH', 400);
      }
      return hash([operation, groupId, owner, app, params.member,
        params.role, params.status, params.expectedEpoch]);
    case 'list':
      if (params.cursor != null) rdf.validateActor(params.cursor);
      if (!Number.isSafeInteger(params.limit) || params.limit < 1 ||
          params.limit > rdf.MAX_LIMIT) deny('GROUP_MEMBERSHIP_INVALID_LIMIT', 400);
      return hash([operation, groupId, owner, app, params.cursor ?? null, params.limit]);
    default:
      deny('GROUP_MEMBERSHIP_INVALID_OPERATION', 400);
  }
}
function authenticate(settings, params, operation) {
  if (!settings?.enabled) deny('GROUP_MEMBERSHIP_DISABLED', 503);
  if (typeof settings.secret !== 'string' || Buffer.byteLength(settings.secret) < 32) {
    deny('GROUP_MEMBERSHIP_DISABLED', 503);
  }
  const requestHash = canonicalRequest(operation, params);
  if (!settings.approvedApps.includes(params.app)) deny('GROUP_APP_NOT_APPROVED');
  const grant = params.grant;
  const now = Date.now();
  if (!grant || grant.purpose !== PURPOSE || grant.operation !== operation ||
      grant.owner !== params.owner || grant.app !== params.app ||
      grant.groupId !== params.groupId || grant.requestHash !== requestHash ||
      !Number.isSafeInteger(grant.issuedAt) || !Number.isSafeInteger(grant.expiresAt) ||
      grant.issuedAt > now + 10000 || grant.expiresAt < now ||
      grant.expiresAt - grant.issuedAt > 60000 ||
      typeof grant.mac !== 'string' || !/^[0-9a-f]{64}$/u.test(grant.mac)) {
    deny('GROUP_MEMBERSHIP_UNAUTHORIZED');
  }
  const material = JSON.stringify([PURPOSE, operation, params.groupId,
    params.owner, params.app, requestHash, grant.issuedAt, grant.expiresAt]);
  const expected = crypto.createHmac('sha256', settings.secret).update(material).digest('hex');
  if (!crypto.timingSafeEqual(Buffer.from(grant.mac, 'ascii'), Buffer.from(expected, 'ascii'))) {
    deny('GROUP_MEMBERSHIP_UNAUTHORIZED');
  }
}
async function query(ctx, sparql) {
  return ctx.call('triplestore.query', { dataset: 'settings', webId: 'system', query: sparql });
}
async function update(ctx, sparql) {
  return ctx.call('triplestore.update', { dataset: 'settings', webId: 'system', query: sparql });
}
async function currentEpoch(ctx, groupId, owner) {
  const rows = await query(ctx, rdf.readEpochQuery({ groupId, owner }));
  if (!Array.isArray(rows) || rows.length !== 1 ||
      !/^[1-9][0-9]*$/u.test(String(getValue(rows[0], 'epoch')))) {
    deny('GROUP_MEMBERSHIP_EPOCH_UNVERIFIED', 503);
  }
  const value = Number(getValue(rows[0], 'epoch'));
  if (!Number.isSafeInteger(value)) deny('GROUP_MEMBERSHIP_EPOCH_UNVERIFIED', 503);
  return value;
}

module.exports = {
  name: 'collective-memberships',
  settings: {
    // The only route to enablement is a separate reviewed code release,
    // after a real Solid-OIDC/SAI owner credential issuer is in place.
    enabled: CONSENT_BRIDGE_RELEASED &&
      process.env.PROVIDER_COLLECTIVES_MEMBERSHIPS_ENABLED === 'true',
    secret: process.env.PROVIDER_COLLECTIVES_MEMBERSHIP_SECRET || '',
    approvedApps: parseApprovedApps(process.env.PROVIDER_COLLECTIVES_APPROVED_APPS || '')
  },
  actions: {
    initialize: {
      params: { groupId: 'string', owner: 'string', app: 'string',
        grant: { type: 'object', strict: false } },
      async handler(ctx) {
        authenticate(this.settings, ctx.params, 'initialize');
        await update(ctx, rdf.initializeQuery(ctx.params));
        const epoch = await currentEpoch(ctx, ctx.params.groupId, ctx.params.owner);
        if (epoch !== 1) deny('GROUP_MEMBERSHIP_INIT_CONFLICT', 409);
        return { groupId: ctx.params.groupId, membershipRevision: 1 };
      }
    },
    change: {
      params: { groupId: 'string', owner: 'string', app: 'string', member: 'string',
        role: 'string', status: 'string', expectedEpoch: 'number|integer|min:1',
        grant: { type: 'object', strict: false } },
      async handler(ctx) {
        authenticate(this.settings, ctx.params, 'change');
        const receipt = crypto.randomUUID();
        await update(ctx, rdf.mutateQuery({ ...ctx.params, receipt }));
        const rows = await query(ctx, rdf.readMutationQuery(ctx.params));
        if (!Array.isArray(rows) || rows.length !== 1 ||
            Number(getValue(rows[0], 'epoch')) !== ctx.params.expectedEpoch + 1 ||
            getValue(rows[0], 'role') !== ctx.params.role ||
            getValue(rows[0], 'status') !== ctx.params.status ||
            getValue(rows[0], 'receipt') !== receipt) {
          deny('GROUP_MEMBERSHIP_STALE_EPOCH', 409);
        }
        return {
          groupId: ctx.params.groupId, membershipRevision: ctx.params.expectedEpoch + 1,
          member: ctx.params.member, role: ctx.params.role, status: ctx.params.status
        };
      }
    },
    list: {
      params: {
        groupId: 'string', owner: 'string', app: 'string',
        cursor: { type: 'string', optional: true },
        limit: 'number|integer|min:1|max:1000',
        grant: { type: 'object', strict: false }
      },
      async handler(ctx) {
        authenticate(this.settings, ctx.params, 'list');
        const rows = await query(ctx, rdf.listQuery(ctx.params));
        if (!Array.isArray(rows) || rows.length < 1 || rows.length > ctx.params.limit + 1) {
          deny('GROUP_MEMBERSHIP_SNAPSHOT_UNVERIFIED', 503);
        }
        const revision = Number(getValue(rows[0], 'epoch'));
        if (!Number.isSafeInteger(revision) || revision < 1 ||
            rows.some(row => Number(getValue(row, 'epoch')) !== revision)) {
          deny('GROUP_MEMBERSHIP_SNAPSHOT_UNVERIFIED', 503);
        }
        const limited = rows.slice(0, ctx.params.limit);
        const actorUris = limited.map(row => rdf.validateActor(getValue(row, 'actor')));
        if (new Set(actorUris).size !== actorUris.length ||
            actorUris.some((uri, i) => i > 0 && uri <= actorUris[i - 1])) {
          deny('GROUP_MEMBERSHIP_SNAPSHOT_UNVERIFIED', 503);
        }
        return {
          groupActorUri: null, // Not issued while the G1 actor fuse remains closed.
          groupId: ctx.params.groupId,
          membershipRevision: revision,
          members: limited.map((row, index) => ({
            actorUri: actorUris[index], role: getValue(row, 'role')
          })),
          hasMore: rows.length > ctx.params.limit,
          nextCursor: rows.length > ctx.params.limit ? actorUris[actorUris.length - 1] : null
        };
      }
    }
  },
  _test: { canonicalRequest, authenticate, currentEpoch, PURPOSE, NS }
};
