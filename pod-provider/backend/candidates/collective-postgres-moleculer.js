'use strict';

/**
 * Isolated Moleculer service adapter for the PostgreSQL Group authority
 * candidate. NOT autoloaded: lives outside backend/services. It cannot be
 * enabled with environment variables or registered in production without a
 * separate reviewed release and live Solid-OIDC/SAI cutover.
 *
 * The caller supplies one bounded node-postgres-compatible Pool per Moleculer
 * process. Do not open a pool per Group, action, or user. The injected pool is
 * NOT owned by this service and is never terminated here.
 *
 * This is the same transaction model proved in the disposable Python
 * prototype; production migration must remove the duplicate prototype.
 */
const { MoleculerError } = require('moleculer').Errors;
const rdf = require('../utils/collective-membership-rdf');

const SCHEMA = 'paper_groups_candidate';
const LIMIT = 100;
function fail(code, status = 403) {
  throw new MoleculerError(code, status, code);
}
function assertInput(params, operation) {
  rdf.validateId(params.groupId);
  rdf.validateActor(params.owner);
  rdf.validateActor(params.app);
  if (operation === 'change') {
    rdf.validateActor(params.member);
    if (params.member === params.owner || params.role === 'owner' ||
        !rdf.ROLES.has(params.role) || !rdf.STATUSES.has(params.status) ||
        !Number.isSafeInteger(params.expectedRevision) || params.expectedRevision < 1 ||
        typeof params.operationId !== 'string' ||
        !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu.test(params.operationId)) {
      fail('GROUP_POSTGRES_INVALID_INPUT', 400);
    }
  }
  if (operation === 'list') {
    if (!Number.isSafeInteger(params.limit) || params.limit < 1 || params.limit > LIMIT) {
      fail('GROUP_POSTGRES_INVALID_PAGE', 400);
    }
    if (params.cursor != null) {
      rdf.validateActor(params.cursor);
      if (!Number.isSafeInteger(params.expectedRevision) ||
          params.expectedRevision < 1) fail('GROUP_POSTGRES_STALE_PAGE', 409);
    }
  }
}
async function transaction(pool, fn) {
  const client = await pool.connect();
  let inTransaction = false;
  let connectionBroken = false;
  try {
    await client.query('BEGIN');
    inTransaction = true;
    await client.query("SET LOCAL lock_timeout = '2500ms'");
    await client.query("SET LOCAL statement_timeout = '8000ms'");
    await client.query("SET LOCAL idle_in_transaction_session_timeout = '5000ms'");
    const result = await fn(client);
    await client.query('COMMIT');
    inTransaction = false;
    return result;
  } catch (error) {
    if (inTransaction) {
      try { await client.query('ROLLBACK'); }
      catch (_) { connectionBroken = true; /* preserve original error */ }
    }
    throw error;
  } finally {
    // Failed rollback leaves unknown transaction state. A poisoned
    // connection must never be returned to the shared pool.
    client.release(connectionBroken);
  }
}
async function authority(client, { owner, app, groupId }, groupMode) {
  // Consistent lock order across identity, consent, Group, including the
  // revocation callback that will own consent FOR UPDATE at cutover.
  const identity = await client.query(
    'SELECT enabled FROM ' + SCHEMA + '.identities WHERE webid=$1 FOR SHARE', [owner]
  );
  if (identity.rowCount !== 1 || identity.rows[0].enabled !== true) {
    fail('GROUP_POSTGRES_AUTHORITY_DENIED');
  }
  const consent = await client.query(
    'SELECT granted,revision FROM ' + SCHEMA +
    '.consent WHERE owner_webid=$1 AND app_uri=$2 FOR SHARE', [owner, app]
  );
  if (consent.rowCount !== 1 || consent.rows[0].granted !== true) {
    fail('GROUP_POSTGRES_AUTHORITY_DENIED');
  }
  const group = await client.query(
    'SELECT revision,state FROM ' + SCHEMA +
    '.groups WHERE group_id=$1 AND owner_webid=$2 AND app_uri=$3 FOR ' +
    (groupMode === 'write' ? 'UPDATE' : 'SHARE'),
    [groupId, owner, app]
  );
  if (group.rowCount !== 1 || group.rows[0].state === 'suspended') {
    fail('GROUP_POSTGRES_AUTHORITY_DENIED');
  }
  const revision = Number(group.rows[0].revision);
  const consentRevision = Number(consent.rows[0].revision);
  if (!Number.isSafeInteger(revision) || revision < 1 ||
      !Number.isSafeInteger(consentRevision) || consentRevision < 1) {
    fail('GROUP_POSTGRES_EPOCH_UNVERIFIED', 503);
  }
  return { revision, consentRevision };
}
function createCandidateService({ pool, fixtureOnly = false } = {}) {
  if (!pool || typeof pool.connect !== 'function') {
    throw new TypeError('GROUP_POSTGRES_POOL_REQUIRED');
  }
  return {
    name: 'collective-postgres-candidate',
    settings: { enabled: false },
    actions: {
      list: {
        params: {
          groupId: 'string', owner: 'string', app: 'string',
          cursor: { type: 'string', optional: true },
          expectedRevision: { type: 'number', integer: true, optional: true },
          limit: { type: 'number', integer: true, min: 1, max: LIMIT }
        },
        async handler(ctx) {
          if (!fixtureOnly || this.settings.enabled !== true) {
            fail('GROUP_POSTGRES_NOT_RELEASED', 503);
          }
          const p = ctx.params;
          assertInput(p, 'list');
          return transaction(pool, async client => {
            const current = await authority(client, p, 'read');
            if (p.expectedRevision !== undefined &&
                current.revision !== p.expectedRevision) {
              fail('GROUP_POSTGRES_STALE_PAGE', 409);
            }
            const result = await client.query(
              'SELECT actor_uri,role FROM ' + SCHEMA + '.members ' +
              'WHERE group_id=$1 AND status=\'active\' AND ' +
              'actor_uri COLLATE "C" > $2 COLLATE "C" ' +
              'ORDER BY actor_uri COLLATE "C" LIMIT $3',
              [p.groupId, p.cursor || '', p.limit + 1]
            );
            const rows = result.rows.slice(0, p.limit);
            const more = result.rows.length > p.limit;
            return {
              membershipRevision: current.revision,
              members: rows.map(r => ({ actorUri: r.actor_uri, role: r.role })),
              hasMore: more,
              nextCursor: more ? rows[rows.length - 1].actor_uri : null
            };
          });
        }
      },
      change: {
        params: {
          groupId: 'string', owner: 'string', app: 'string',
          member: 'string', role: 'string', status: 'string',
          expectedRevision: { type: 'number', integer: true, min: 1 },
          operationId: 'string'
        },
        async handler(ctx) {
          if (!fixtureOnly || this.settings.enabled !== true) {
            fail('GROUP_POSTGRES_NOT_RELEASED', 503);
          }
          const p = ctx.params;
          assertInput(p, 'change');
          return transaction(pool, async client => {
            const auth = await authority(client, p, 'write');
            const replay = await client.query(
              'SELECT revision,actor_uri,role,status FROM ' + SCHEMA +
              '.transitions WHERE group_id=$1 AND operation_id=$2::uuid',
              [p.groupId, p.operationId]
            );
            if (replay.rowCount) {
              const record = replay.rows[0];
              if (record.actor_uri !== p.member || record.role !== p.role ||
                  record.status !== p.status) {
                fail('GROUP_POSTGRES_OPERATION_CONFLICT', 409);
              }
              return { membershipRevision: Number(record.revision), replay: true };
            }
            if (auth.revision !== p.expectedRevision) fail('GROUP_POSTGRES_STALE_REVISION', 409);
            const revision = auth.revision + 1;
            if (!Number.isSafeInteger(revision)) fail('GROUP_POSTGRES_EPOCH_OVERFLOW', 409);
            await client.query(
              'INSERT INTO ' + SCHEMA +
              '.members (group_id,actor_uri,role,status,change_revision) ' +
              'VALUES ($1,$2,$3,$4,$5) ON CONFLICT (group_id,actor_uri) DO UPDATE ' +
              'SET role=EXCLUDED.role,status=EXCLUDED.status,change_revision=EXCLUDED.change_revision',
              [p.groupId, p.member, p.role, p.status, revision]
            );
            const changed = await client.query(
              'UPDATE ' + SCHEMA + '.groups SET revision=$1 ' +
              'WHERE group_id=$2 AND revision=$3 RETURNING revision',
              [revision, p.groupId, auth.revision]
            );
            if (changed.rowCount !== 1) fail('GROUP_POSTGRES_STALE_REVISION', 409);
            await client.query(
              'INSERT INTO ' + SCHEMA +
              '.transitions (group_id,revision,actor_uri,status,role,operation_id,consent_revision) ' +
              'VALUES ($1,$2,$3,$4,$5,$6::uuid,$7)',
              [p.groupId, revision, p.member, p.status, p.role,
                p.operationId, auth.consentRevision]
            );
            return { membershipRevision: revision, replay: false };
          });
        }
      }
    }
  };
}
module.exports = Object.freeze({ createCandidateService, transaction, authority, LIMIT });
