'use strict';

const crypto = require('node:crypto');
const { createCanonicalNotificationLedger } = require('../utils/canonical-notification-pg-ledger');
const { assertNotificationPgCanRun } = require('../utils/notification-pg-release-gate');

const ENABLED = process.env.APODS_NOTIFICATION_LEDGER_WORKER_ENABLED === 'true';
const CONCURRENCY = 4;
const BATCH = 8;

function isTrustedLocalInbox(baseUrl, uri) {
  try {
    const origin = new URL(baseUrl);
    const u = new URL(uri);
    return u.origin === origin.origin && u.href === uri &&
      !u.username && !u.password && !u.search && !u.hash &&
      u.pathname.endsWith('/inbox') && u.protocol === origin.protocol;
  } catch { return false; }
}

module.exports = {
  name: 'internal-notification-delivery-worker',
  dependencies: ENABLED ? ['activitypub.actor', 'activitypub.inbox'] : [],
  settings: {
    enabled: ENABLED,
    baseUrl: process.env.SEMAPPS_HOME_URL || ''
  },
  created() {
    this.notificationWorker = {
      timer: null, active: null, stopping: false, pool: null, ledger: null
    };
  },
  async started() {
    assertNotificationPgCanRun();
    if (!this.settings.enabled) return;
    if (!isTrustedLocalInbox(this.settings.baseUrl, this.settings.baseUrl.replace(/\/+$/u, '') + '/_proof/inbox')) {
      throw new Error('Notification delivery worker needs a canonical local provider origin');
    }
    const url = process.env.APODS_NOTIFICATION_PG_URL;
    if (!url) throw new Error('Missing dedicated PostgreSQL notification DSN');
    const { Pool } = require('pg');
    const pool = new Pool({
      connectionString: url, max: 2, connectionTimeoutMillis: 3000,
      idleTimeoutMillis: 10000, query_timeout: 6500, allowExitOnIdle: true
    });
    const ledger = createCanonicalNotificationLedger({ pool });
    try { await ledger.verifySchema(); }
    catch (e) { await pool.end(); throw e; }
    Object.assign(this.notificationWorker, { pool, ledger });
    this.scheduleNextNotificationPoll(0);
  },
  async stopped() {
    const s = this.notificationWorker;
    s.stopping = true;
    if (s.timer) clearTimeout(s.timer);
    if (s.active) await s.active.catch(() => {});
    if (s.pool) await s.pool.end();
    s.pool = null;
    s.ledger = null;
  },
  methods: {
    scheduleNextNotificationPoll(delayMs) {
      const s = this.notificationWorker;
      if (s.stopping || !s.ledger) return;
      s.timer = setTimeout(() => {
        s.timer = null;
        // Prevent overlap; fixed upper work bound per poll. Idle workers
        // sleep ~2 seconds and spread load with jitter across replicas.
        s.active = this.pollCanonicalNotifications().catch(error => {
          this.logger.error('[CanonicalNotificationWorker] Batch failed', {
            code: error?.code || 'PG_NOTIFY_BATCH_FAILURE'
          });
        }).finally(() => {
          s.active = null;
          this.scheduleNextNotificationPoll(1750 + Math.floor(Math.random()*500));
        });
      }, delayMs);
      s.timer.unref?.();
    },
    async pollCanonicalNotifications() {
      const s = this.notificationWorker;
      const token = crypto.randomUUID();
      const jobs = await s.ledger.claim({limit:BATCH,workerToken:token});
      let next = 0;
      const runner = async () => {
        while (next < jobs.length && !s.stopping) {
          const item = jobs[next++];
          try {
            const actor = await this.broker.call('activitypub.actor.get',
              { actorUri: item.recipient_webid, webId: 'system' }, {timeout:5000});
            const inbox = actor?.inbox;
            if (!isTrustedLocalInbox(this.settings.baseUrl,inbox)) {
              throw Object.assign(new Error('Invalid local inbox'), {code:'LOCAL_INBOX_INVALID'});
            }
            const body = item.activity_json;
            if (!body?.activity || typeof body.actorUri !== 'string' ||
                body.activity.actor !== body.actorUri) {
              throw Object.assign(new Error('Corrupt notification event'), {code:'EVENT_SHAPE_INVALID'});
            }
            await this.broker.call('activitypub.inbox.post',
              {...body.activity,collectionUri:inbox},
              {meta:{webId:body.actorUri,skipSignatureValidation:true},timeout:5000});
            await s.ledger.finish({
              intentKey:item.intent_key,recipientKey:item.recipient_key,workerToken:token
            });
          } catch (error) {
            try {
              await s.ledger.fail({
                intentKey:item.intent_key,recipientKey:item.recipient_key,
                workerToken:token,
                reasonCode:/^[A-Z][A-Z0-9_]{0,63}$/u.test(error?.code||'')
                  ?error.code:'DELIVERY_FAILED'
              });
            } catch (markError) {
              // The lease expires and remains claimable. Never acknowledge
              // and discard a record when failure persistence did not commit.
              this.logger.error('[CanonicalNotificationWorker] Failed to record retry', {
                code:markError?.code||'PG_NOTIFY_FAILURE_RECORD'
              });
            }
          }
        }
      };
      await Promise.all(Array.from({length:Math.min(CONCURRENCY,jobs.length)},()=>runner()));
      return jobs.length;
    }
  }
};
