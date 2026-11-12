'use strict';

// Source-controlled guard. A green PG test is not proof of production
// WebSocket delivery durability. A release review must explicitly promote
// this constant after the real DB/Pod outage and replay acceptance gates.
const NOTIFICATION_PG_CUTOVER_RELEASED = false;

function assertNotificationPgCanRun(env = process.env) {
  const requested = env.APODS_NOTIFICATION_LEDGER_ENABLED === 'true' ||
    env.APODS_NOTIFICATION_LEDGER_WORKER_ENABLED === 'true';
  const disposableTest = env.NODE_ENV === 'test' &&
    env.APODS_NOTIFICATION_PG_DISPOSABLE === 'confirmed';
  if (requested && !NOTIFICATION_PG_CUTOVER_RELEASED && !disposableTest) {
    throw new Error('Canonical notification PG cutover not released: live delivery/idempotency acceptance outstanding');
  }
}
module.exports = { assertNotificationPgCanRun };
