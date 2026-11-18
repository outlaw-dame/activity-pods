'use strict';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;

function createProviderEnrollmentHandoff({
  broker, handoffPool, lifecycle, issue, providerId, appClientId, returnUri
}) {
  const gate = () => {
    if (process.env.NODE_ENV !== 'test' ||
        process.env.PAPER_ACCOUNTS_DISPOSABLE !== 'confirmed' ||
        process.env.PAPER_BROWSER_ENROLLMENT_DISPOSABLE !== 'confirmed') {
      throw new Error('Enrollment handoff is unavailable');
    }
  };
  gate();
  return async ({ reservationId, appClientId: client, redirectUri, username, webId, setCookie }) => {
    gate();
    if (!UUID.test(reservationId || '') || client !== appClientId || redirectUri !== returnUri ||
        !/^[a-z][a-z0-9_-]{1,31}$/u.test(username || '') ||
        webId !== providerId + '/users/' + username || typeof setCookie !== 'function') {
      throw new Error('Enrollment scope mismatch');
    }
    const options = { meta: {}, timeout: 5000, retries: 0 };
    const [account, binding] = await Promise.all([
      broker.call('auth.account.findByWebId', { webId }, options),
      broker.call('identitybindings.getByCanonicalAccountId', { canonicalAccountId: webId }, options)
    ]);
    if (account?.webId !== webId || account.username !== username ||
        account.signupReservationId !== reservationId ||
        binding?.webId !== webId || binding.activityPubActorId !== webId ||
        binding.atprotoSource === 'external' || binding.atprotoManaged !== true ||
        !binding.atSigningKeyRef || !binding.atRotationKeyRef ||
        !binding.repoRootCid || !binding.repoRev || binding.repoInitialized !== true) {
      throw new Error('Protected provider identity mismatch');
    }
    const result = await handoffPool.query({
      text: 'SELECT * FROM paper_account_reservation_proof.enrollment_handoff($1,$2,$3,$4,$5)',
      values: [reservationId, providerId, appClientId, username, webId],
      query_timeout: 5000
    });
    if (result.rowCount !== 1) throw new Error('Canonical enrollment scope unavailable');
    const row = result.rows[0];
    const bound = await lifecycle.change({
      providerId, accountId: row.account_id, operationId: row.operation_id,
      expectedGeneration: 1, kind: 'bind_unified_identity', webId, activityPubActorId: webId,
      atprotoDid: binding.atprotoDid, atprotoHandle: binding.atprotoHandle,
      atprotoPdsUrl: binding.atprotoPdsUrl, repoInitialized: true
    });
    if (bound.generation !== 2 || bound.replay !== false) {
      throw new Error('Canonical enrollment binding requires reconciliation');
    }
    return issue({ operationId: row.operation_id, idempotencyHmac: row.idempotency_hmac,
      requestHmac: row.request_hmac, setCookie });
  };
}

module.exports = { createProviderEnrollmentHandoff };
