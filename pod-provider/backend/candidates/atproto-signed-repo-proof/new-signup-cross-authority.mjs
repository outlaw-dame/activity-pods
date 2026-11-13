/**
 * Non-activated, read-only unified NEW-account release evidence.
 *
 * One signup operation remains owned by the PR #138 PostgreSQL account
 * candidate; this verifier only correlates it with the existing signed
 * repository, real CAR readback, protected Solid binding and durable PG->RDF
 * projection fence. It never mints a DID, signs a commit, changes a username,
 * completes an operation or opens an HTTP/Moleculer action.
 *
 * These reads are not an atomic transaction across PostgreSQL and Jena.
 * Therefore a successful result is evidence_only, NEVER a production release.
 */
const DID = /^did:plc:[a-z2-7]{24}$/u;
const CID = /^bafyre[a-z2-7]{53}$/u;
const TID = /^[234567abcdefghij][234567abcdefghijklmnopqrstuvwxyz]{12}$/u;

function deny(code) {
  const error = new Error('Unified new-signup proof is incomplete or unavailable');
  error.code = code;
  throw error;
}

const accountFingerprint = a => JSON.stringify([
  a.account_id, a.provider_id, a.username_key, a.webid,
  a.activitypub_actor_uri, a.atproto_did, a.atproto_handle,
  a.atproto_pds_url, a.atproto_repo_initialized, a.state,
  a.generation
]);

export function createNewSignupCrossAuthority({
  accountAuthority, repositoryAuthority, projectionAuthority,
  solidCall, fixtureOnly = false
} = {}) {
  // The actual production account signup remains disabled until a distinct,
  // reviewed provider-owned writer and XRPC/consent gate is activated.
  const unavailable = () => deny('UNIFIED_SIGNUP_CROSS_AUTHORITY_NOT_RELEASED');
  if (fixtureOnly !== true || process.env.NODE_ENV === 'production' ||
      process.env.PAPER_ACCOUNTS_DISPOSABLE !== 'confirmed' ||
      process.env.ATPROTO_REPO_PROOF_DISPOSABLE !== 'confirmed') {
    return Object.freeze({ verify: unavailable });
  }
  if (!accountAuthority ||
      ['readSignup','read','verifySignupSolidReadiness'].some(x =>
        typeof accountAuthority[x] !== 'function') ||
      typeof repositoryAuthority?.verifyReady !== 'function' ||
      typeof projectionAuthority?.readiness !== 'function' ||
      typeof solidCall !== 'function') {
    deny('UNIFIED_SIGNUP_CROSS_AUTHORITY_CONFIGURATION_INVALID');
  }

  async function verify(scope) {
    // The caller has already verified the external app and produced HMAC
    // digests. Never accept a public idempotency key or user-supplied actor.
    const operation = await accountAuthority.readSignup(scope);
    if (!operation || operation.replay !== true ||
        operation.state !== 'reconciliation_required' ||
        !Number.isSafeInteger(operation.generation) ||
        operation.generation < 2) {
      deny('UNIFIED_SIGNUP_OPERATION_NOT_FENCED');
    }
    const before = await accountAuthority.read({
      providerId: scope.providerId, accountId: operation.accountId
    });
    if (!before || before.state !== 'provisioning' ||
        before.webid !== before.activitypub_actor_uri ||
        !DID.test(before.atproto_did || '') ||
        before.atproto_repo_initialized !== true ||
        typeof before.atproto_handle !== 'string' ||
        typeof before.atproto_pds_url !== 'string') {
      deny('UNIFIED_SIGNUP_ACCOUNT_IDENTITY_INCOMPLETE');
    }
    // The Solid read executes only the three indexed SemApps/Jena lookups
    // and rejects a different managed DID, AP actor or missing bootstrap.
    const solid = await accountAuthority.verifySignupSolidReadiness({
      ...scope, call: solidCall
    });
    if (solid?.complete !== true || solid.accountId !== operation.accountId ||
        solid.operationId !== operation.operationId ||
        solid.generation !== before.generation ||
        solid.webId !== before.webid || solid.did !== before.atproto_did) {
      deny('UNIFIED_SIGNUP_SOLID_EVIDENCE_MISMATCH');
    }

    // The PostgreSQL account projection must also agree with the protected
    // current handle and PDS URL. Solid bootstrap verification deliberately
    // does not validate these fields, and neither may be trusted in isolation.
    const binding = await solidCall('identitybindings.getByCanonicalAccountId', {
      canonicalAccountId: before.webid
    });
    if (!binding || binding.canonicalAccountId !== before.webid ||
        binding.atprotoHandle !== before.atproto_handle ||
        binding.atprotoPdsUrl !== before.atproto_pds_url ||
        binding.webId !== before.webid ||
        binding.activityPubActorId !== before.webid ||
        binding.atprotoDid !== before.atproto_did ||
        binding.atprotoSource !== 'local' ||
        binding.atprotoManaged !== true) {
      deny('UNIFIED_SIGNUP_ACCOUNT_RDF_PROJECTION_MISMATCH');
    }

    // The repository bridge verifies the real signed v3 CAR from its
    // PostgreSQL head and checks current PLC DID, signing key, handle,
    // PDS origin and the protected RDF identity projection.
    const repo = await repositoryAuthority.verifyReady({
      canonicalAccountId: before.webid,
      did: before.atproto_did,
      handle: before.atproto_handle
    });
    if (repo?.verified !== true || repo.accountId !== before.webid ||
        repo.did !== before.atproto_did ||
        !CID.test(repo.commitCid || '') || !CID.test(repo.rootCid || '') ||
        !TID.test(repo.rev || '') ||
        !['pending','delivered'].includes(repo.outboxStatus)) {
      deny('UNIFIED_SIGNUP_SIGNED_REPOSITORY_MISMATCH');
    }

    // Require applied PG recovery intent, current monotone Jena fence
    // and current provider/SAI permission. A Boolean in RDF alone is
    // NEVER enough to report successful repository readiness.
    const projected = await projectionAuthority.readiness({
      accountId: before.webid, did: before.atproto_did
    });
    if (projected?.ready !== true ||
        projected.accountId !== repo.accountId ||
        projected.did !== repo.did || projected.headCid !== repo.commitCid ||
        projected.rootCid !== repo.rootCid || projected.rev !== repo.rev ||
        projected.outboxStatus !== repo.outboxStatus ||
        typeof projected.fence !== 'string' ||
        !/^[1-9][0-9]{0,18}$/u.test(projected.fence)) {
      deny('UNIFIED_SIGNUP_PROJECTION_MISMATCH');
    }

    // No PG transaction/connection is held across OIDC, PLC/DNS or RDF I/O.
    // Re-read both authority records to reject concurrent changes. A future
    // activation still needs a provider-owned atomic completion CAS.
    const [afterOperation, after] = await Promise.all([
      accountAuthority.readSignup(scope),
      accountAuthority.read({
        providerId: scope.providerId, accountId: operation.accountId
      })
    ]);
    if (!after || !afterOperation ||
        afterOperation.operationId !== operation.operationId ||
        afterOperation.accountId !== operation.accountId ||
        afterOperation.generation !== operation.generation ||
        afterOperation.state !== operation.state ||
        accountFingerprint(after) !== accountFingerprint(before)) {
      deny('UNIFIED_SIGNUP_CONCURRENT_AUTHORITY_CHANGE');
    }
    return Object.freeze({
      evidence: 'signed_repo_solid_projection_v1',
      accountId: operation.accountId, webId: before.webid,
      did: repo.did, commitCid: repo.commitCid, rootCid: repo.rootCid,
      rev: repo.rev, projectionFence: projected.fence,
      outboxStatus: repo.outboxStatus,
      signupGeneration: operation.generation,
      accountGeneration: before.generation,
      status: 'evidence_only',
      productionReady: false
    });
  }
  return Object.freeze({ verify });
}
