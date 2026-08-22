'use strict';

const crypto = require('crypto');
const Redis = require('ioredis');
const { MoleculerError } = require('moleculer').Errors;

const ACTION = 'signing.provisionAtprotoIdentity';
const KEY_PREFIX = 'activitypods:atproto:provision:v1:';
const DEFAULT_TTL_MS = 10 * 60 * 1000;
const MIN_TTL_MS = 30 * 1000;
const MAX_TTL_MS = 30 * 60 * 1000;

function resolveRedisUrl() {
  return (
    process.env.SEMAPPS_QUEUE_SERVICE_URL ||
    process.env.SEMAPPS_REDIS_CACHE_URL ||
    'redis://127.0.0.1:6379/1'
  );
}

function resolveTtlMs() {
  const value = Number(process.env.ATPROTO_PROVISION_RESERVATION_TTL_MS || DEFAULT_TTL_MS);
  if (!Number.isFinite(value)) return DEFAULT_TTL_MS;
  return Math.max(MIN_TTL_MS, Math.min(MAX_TTL_MS, Math.floor(value)));
}

function reservationKey(canonicalAccountId) {
  const digest = crypto.createHash('sha256').update(String(canonicalAccountId), 'utf8').digest('hex');
  return `${KEY_PREFIX}${digest}`;
}

module.exports = function AtprotoProvisioningReservationMiddleware(options = {}) {
  const redisUrl = options.redisUrl || resolveRedisUrl();
  const ttlMs = Number.isInteger(options.ttlMs) ? options.ttlMs : resolveTtlMs();
  let redis;

  async function ensureRedis() {
    if (!redis) {
      redis = new Redis(redisUrl, {
        lazyConnect: true,
        maxRetriesPerRequest: 1,
        enableReadyCheck: true
      });
    }
    if (redis.status === 'wait') await redis.connect();
    return redis;
  }

  async function acquire(canonicalAccountId) {
    const client = await ensureRedis();
    const key = reservationKey(canonicalAccountId);
    const token = crypto.randomBytes(32).toString('base64url');
    let result;
    try {
      result = await client.set(key, token, 'PX', ttlMs, 'NX');
    } catch (error) {
      throw new MoleculerError(
        'ATProto provisioning reservation authority unavailable',
        503,
        'PROVISIONING_RESERVATION_UNAVAILABLE',
        { message: error?.message }
      );
    }
    if (result !== 'OK') {
      throw new MoleculerError(
        'ATProto identity provisioning is already in progress for this account',
        409,
        'IDENTITY_PROVISIONING_IN_PROGRESS',
        { canonicalAccountId }
      );
    }
    return { key, token };
  }

  async function release(reservation) {
    if (!reservation || !redis) return;
    const script = `
      if redis.call('GET', KEYS[1]) == ARGV[1] then
        return redis.call('DEL', KEYS[1])
      end
      return 0
    `;
    try {
      await redis.eval(script, 1, reservation.key, reservation.token);
    } catch {
      // Never replace the authoritative provisioning result with a release
      // error. The lease expires automatically; compare-and-delete prevents
      // this caller from releasing a newer owner's reservation.
    }
  }

  return {
    name: 'AtprotoProvisioningReservation',

    async stopped() {
      if (redis && redis.status !== 'end') {
        await redis.quit().catch(() => redis.disconnect());
      }
    },

    localAction(next, action) {
      if (action.name !== ACTION) return next;

      return async function atprotoProvisioningReservedAction(ctx) {
        const canonicalAccountId = ctx.params?.canonicalAccountId;
        if (typeof canonicalAccountId !== 'string' || canonicalAccountId.length === 0) {
          return next(ctx);
        }

        // This SET NX reservation happens before the signing action performs
        // its existence check or generates either private key. Because every
        // replica uses the same Redis authority, concurrent requests for one
        // canonical account cannot both reach key generation.
        const reservation = await acquire(canonicalAccountId);
        try {
          return await next(ctx);
        } finally {
          await release(reservation);
        }
      };
    }
  };
};

module.exports.reservationKey = reservationKey;
module.exports.resolveTtlMs = resolveTtlMs;
