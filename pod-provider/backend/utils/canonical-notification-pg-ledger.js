'use strict';

/**
 * Durable canonical notifications: one PostgreSQL record per (intent, local
 * recipient), plus a leased work row for the ActivityPub inbox projection.
 * No per-account scan, per-recipient connection, process-local idempotency,
 * network I/O inside transactions or unbounded retry loop.
 */
const crypto = require('node:crypto');

const SCHEMA = 'paper_notification_ledger';
const MAX_RECIPIENTS = 64;
const MAX_TOTAL_BYTES = 196608;
const MAX_ATTEMPTS = 8;
const LEASE_SECONDS = 20;
const safeUri = value => {
  if (typeof value !== 'string' || value.length < 1 || value.length > 2048 ||
      /[\u0000-\u0020\u007f]/u.test(value)) throw invalid('PG_NOTIFY_INPUT_INVALID');
  let u;
  try { u = new URL(value); } catch { throw invalid('PG_NOTIFY_INPUT_INVALID'); }
  if (u.protocol !== 'https:' || u.href !== value || u.username || u.password ||
      u.hash || u.search) throw invalid('PG_NOTIFY_INPUT_INVALID');
  return value;
};
function invalid(code) {
  const e = new Error('Canonical notification request rejected');
  e.code = code;
  return e;
}
function sha(value) { return crypto.createHash('sha256').update(value).digest(); }
function str(value, max) {
  return typeof value === 'string' && value.length > 0 &&
    value.length <= max && !/[\u0000-\u001f\u007f]/u.test(value);
}
function validateBatch({ intentId, kind, protocol, recipients }) {
  if (!str(intentId, 512) || !str(kind, 64) ||
      !['activitypub', 'atproto'].includes(protocol) ||
      !Array.isArray(recipients) || recipients.length > MAX_RECIPIENTS) {
    throw invalid('PG_NOTIFY_INPUT_INVALID');
  }
  const entries = recipients.map(entry => {
    if (!entry || typeof entry !== 'object' || Array.isArray(entry)) throw invalid('PG_NOTIFY_INPUT_INVALID');
    const recipient = safeUri(entry.recipient);
    const activity = entry.activity;
    if (!activity || typeof activity !== 'object' || Array.isArray(activity) ||
        activity.actor !== entry.actorUri) throw invalid('PG_NOTIFY_INPUT_INVALID');
    safeUri(entry.actorUri);
    let data;
    try { data = JSON.stringify({ actorUri: entry.actorUri, activity }); }
    catch { throw invalid('PG_NOTIFY_INPUT_INVALID'); }
    if (!data || Buffer.byteLength(data, 'utf8') > 65536) throw invalid('PG_NOTIFY_PAYLOAD_LIMIT');
    return { recipient, data, key: sha(recipient) };
  });
  entries.sort((a,b) => Buffer.compare(a.key,b.key));
  if (entries.some((item,i) => i > 0 && item.recipient === entries[i-1].recipient)) {
    throw invalid('PG_NOTIFY_DUPLICATE_RECIPIENT');
  }
  const canonical = JSON.stringify([intentId,kind,protocol,entries.map(x=>[x.recipient,x.data])]);
  if (Buffer.byteLength(canonical,'utf8') > MAX_TOTAL_BYTES) throw invalid('PG_NOTIFY_PAYLOAD_LIMIT');
  return { intentId, kind, protocol, entries, intentKey: sha(intentId), fingerprint: sha(canonical) };
}
async function tx(pool, fn) {
  const client = await pool.connect();
  let open = false;
  let poisoned = false;
  try {
    await client.query('BEGIN');
    open = true;
    await client.query("SET LOCAL statement_timeout = '6500ms'");
    await client.query("SET LOCAL lock_timeout = '2500ms'");
    await client.query("SET LOCAL idle_in_transaction_session_timeout = '5000ms'");
    const value = await fn(client);
    await client.query('COMMIT');
    open = false;
    return value;
  } catch (err) {
    if (open) {
      try { await client.query('ROLLBACK'); }
      catch { poisoned = true; }
    }
    throw err;
  } finally {
    client.release(poisoned);
  }
}
function claimToken(value) {
  if (typeof value !== 'string' || !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu.test(value)) {
    throw invalid('PG_NOTIFY_CLAIM_INVALID');
  }
  return value;
}
function key(value) {
  if (typeof value !== 'string' || !/^[a-f0-9]{64}$/u.test(value)) throw invalid('PG_NOTIFY_KEY_INVALID');
  return Buffer.from(value, 'hex');
}
function createCanonicalNotificationLedger({ pool } = {}) {
  if (!pool?.query || typeof pool.connect !== 'function') throw invalid('PG_NOTIFY_POOL_REQUIRED');
  return Object.freeze({
    async verifySchema() {
      const rows = await pool.query(
        "SELECT to_regclass('paper_notification_ledger.intents') AS intents, " +
        "to_regclass('paper_notification_ledger.deliveries') AS deliveries, " +
        "to_regclass('paper_notification_ledger.quarantine') AS quarantine"
      );
      if (!rows.rows[0]?.intents || !rows.rows[0]?.deliveries || !rows.rows[0]?.quarantine) {
        throw invalid('PG_NOTIFY_SCHEMA_MISSING');
      }
    },
    async enqueue(request) {
      const p = validateBatch(request);
      return tx(pool, async client => {
        const fresh = await client.query(
          'INSERT INTO '+SCHEMA+'.intents (intent_key,intent_id,payload_sha256,notification_kind,source_protocol,recipient_count) ' +
          'VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (intent_key) DO NOTHING RETURNING intent_key',
          [p.intentKey,p.intentId,p.fingerprint,p.kind,p.protocol,p.entries.length]
        );
        const actual = await client.query(
          'SELECT intent_id,payload_sha256,recipient_count FROM '+SCHEMA+'.intents WHERE intent_key=$1 FOR UPDATE',
          [p.intentKey]
        );
        if (actual.rowCount !== 1 ||
            actual.rows[0].intent_id !== p.intentId ||
            actual.rows[0].recipient_count !== p.entries.length ||
            !Buffer.from(actual.rows[0].payload_sha256).equals(p.fingerprint)) {
          throw invalid('PG_NOTIFY_INTENT_CONFLICT');
        }
        if (fresh.rowCount === 1) {
          for (const item of p.entries) {
            await client.query(
              'INSERT INTO '+SCHEMA+'.deliveries (intent_key,recipient_key,recipient_webid,activity_json) '+
              'VALUES ($1,$2,$3,$4::jsonb)',
              [p.intentKey,item.key,item.recipient,item.data]
            );
          }
        }
        return Object.freeze({
          accepted: true, duplicate: fresh.rowCount === 0,
          recipients: p.entries.length
        });
      });
    },
    async claim({ limit = 8, workerToken = crypto.randomUUID() } = {}) {
      if (!Number.isSafeInteger(limit) || limit < 1 || limit > 16) throw invalid('PG_NOTIFY_BATCH_INVALID');
      claimToken(workerToken);
      const results = await pool.query(
        'WITH due AS (SELECT intent_key,recipient_key FROM '+SCHEMA+'.deliveries ' +
        "WHERE (state='pending' AND next_attempt_at <= clock_timestamp()) OR " +
        "(state='leased' AND lease_until <= clock_timestamp()) " +
        'ORDER BY next_attempt_at,created_at,intent_key,recipient_key ' +
        'FOR UPDATE SKIP LOCKED LIMIT $1) ' +
        'UPDATE '+SCHEMA+'.deliveries d ' +
        "SET state='leased',lease_token=$2::uuid,lease_until=clock_timestamp()+make_interval(secs=>$3) " +
        'FROM due WHERE d.intent_key=due.intent_key AND d.recipient_key=due.recipient_key ' +
        'RETURNING encode(d.intent_key,\'hex\') AS intent_key, ' +
        'encode(d.recipient_key,\'hex\') AS recipient_key, d.recipient_webid, d.activity_json, d.attempts',
        [limit,workerToken,LEASE_SECONDS]
      );
      return results.rows.map(r => Object.freeze({ ...r, workerToken }));
    },
    async finish({ intentKey, recipientKey, workerToken }) {
      claimToken(workerToken);
      const result = await pool.query(
        'UPDATE '+SCHEMA+'.deliveries ' +
        "SET state='delivered',delivered_at=clock_timestamp(),lease_token=NULL,lease_until=NULL " +
        "WHERE intent_key=$1 AND recipient_key=$2 AND state='leased' " +
        'AND lease_token=$3::uuid AND lease_until > clock_timestamp() RETURNING 1',
        [key(intentKey),key(recipientKey),workerToken]
      );
      if (result.rowCount !== 1) throw invalid('PG_NOTIFY_STALE_LEASE');
      return { delivered: true };
    },
    async fail({ intentKey, recipientKey, workerToken, reasonCode = 'DELIVERY_FAILED' }) {
      claimToken(workerToken);
      if (!/^[A-Z][A-Z0-9_]{0,63}$/u.test(reasonCode)) throw invalid('PG_NOTIFY_REASON_INVALID');
      return tx(pool, async client => {
        const row = await client.query(
          'SELECT attempts FROM '+SCHEMA+'.deliveries ' +
          "WHERE intent_key=$1 AND recipient_key=$2 AND state='leased' " +
          'AND lease_token=$3::uuid AND lease_until > clock_timestamp() FOR UPDATE',
          [key(intentKey),key(recipientKey),workerToken]
        );
        if (row.rowCount !== 1) throw invalid('PG_NOTIFY_STALE_LEASE');
        const count = Number(row.rows[0].attempts)+1;
        if (!Number.isSafeInteger(count) || count > MAX_ATTEMPTS) throw invalid('PG_NOTIFY_ATTEMPTS_INVALID');
        const dead = count >= MAX_ATTEMPTS;
        // Full jitter, capped at one minute. No retry sleeps inside this
        // transaction; the next worker claim checks a indexed due timestamp.
        const delay = Math.floor(Math.random()*Math.min(60000,500*2**(count-1)));
        await client.query(
          'UPDATE '+SCHEMA+'.deliveries SET attempts=$4, ' +
          "state=$5,lease_token=NULL,lease_until=NULL,next_attempt_at=clock_timestamp()+($6::integer*interval '1 millisecond') " +
          'WHERE intent_key=$1 AND recipient_key=$2 AND lease_token=$3::uuid',
          [key(intentKey),key(recipientKey),workerToken,count,dead?'dead':'pending',delay]
        );
        if (dead) await client.query(
          'INSERT INTO '+SCHEMA+'.quarantine (intent_key,recipient_key,reason_code,attempts) VALUES ($1,$2,$3,$4)',
          [key(intentKey),key(recipientKey),reasonCode,count]
        );
        return { dead, attempts: count, retryDelayMs: dead?null:delay };
      });
    }
  });
}
module.exports = { MAX_RECIPIENTS, MAX_TOTAL_BYTES, LEASE_SECONDS, MAX_ATTEMPTS, validateBatch, createCanonicalNotificationLedger };
