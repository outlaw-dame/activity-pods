/**
 * Issues a provider operation ticket only for an active PostgreSQL recovery
 * lease and a current, independently verified SAI permission.
 *
 * This belongs in trusted provider orchestration, not a public API or a
 * generic Moleculer action. The database lease is the source of the epoch;
 * neither an HTTP request nor an inherited broker context can select it.
 */
const TABLE = 'paper_atproto_repo_proof.rdf_projection_jobs';
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const DID = /^did:plc:[a-z2-7]{24}$/u;
const CID = /^bafyre[a-z2-7]{53}$/u;
const REV = /^[234567abcdefghij][234567abcdefghijklmnopqrstuvwxyz]{12}$/u;
const EPOCH = /^[1-9][0-9]{0,18}$/u;

function rejected(reason) {
  const e = new Error('The repository recovery claim cannot issue an operation ticket');
  e.code = reason;
  throw e;
}
function webId(value) {
  if (typeof value !== 'string' || value.length > 2048) rejected('PG_TICKET_SCOPE_INVALID');
  let u;
  try { u = new URL(value); } catch { rejected('PG_TICKET_SCOPE_INVALID'); }
  if (u.protocol !== 'https:' || u.href !== value || u.username || u.password ||
      u.search || u.hash) rejected('PG_TICKET_SCOPE_INVALID');
}
function leaseState(row, claim) {
  if (!row || row.account_id !== claim.accountId || row.did !== claim.did ||
      String(row.lease_owner).toLowerCase() !== claim.leaseOwner.toLowerCase() ||
      String(row.lease_epoch) !== String(claim.leaseEpoch) ||
      row.lease_live !== true || row.state !== 'leased' ||
      !CID.test(row.head_cid) || !CID.test(row.root_cid) ||
      !REV.test(row.rev) || Number(row.generation) !== 1) {
    rejected('PG_TICKET_LEASE_STALE');
  }
  return row;
}

export function createPgLeaseTicketIssuer({
  pool, tickets, verifySignedHead, verifyCurrentSaiConsent,
  verifyCanonicalPgConsent,
  fixtureOnly = false
} = {}) {
  if (process.env.NODE_ENV === 'production' ||
      process.env.ATPROTO_REPO_PROOF_DISPOSABLE !== 'confirmed' ||
      fixtureOnly !== true) {
    return Object.freeze({
      issueForLease: async () => rejected('PG_TICKET_NOT_RELEASED')
    });
  }
  if (!pool?.query || typeof tickets?.issue !== 'function' ||
      typeof verifySignedHead !== 'function' ||
      typeof verifyCurrentSaiConsent !== 'function') {
    rejected('PG_TICKET_CONFIG_INVALID');
  }
  const canonicalMode = process.env.APODS_ATPROTO_CANONICAL_PG_AUTHORITY_ENABLED === 'true';
  // In the canonical mode, even an authenticated Jena grant is not
  // sufficient authority: a privileged SPARQL writer could forge that RDF.
  if (canonicalMode && typeof verifyCanonicalPgConsent !== 'function') {
    rejected('PG_TICKET_CANONICAL_AUTHORITY_REQUIRED');
  }
  const getLease = async claim => {
    const r = await pool.query(
      'SELECT account_id, did, head_cid, root_cid, rev, generation, state, ' +
      'lease_owner, lease_epoch::text AS lease_epoch, ' +
      '(lease_until > clock_timestamp()) AS lease_live ' +
      'FROM ' + TABLE +
      " WHERE account_id=$1 AND did=$2 AND lease_owner=$3::uuid AND state='leased'",
      [claim.accountId, claim.did, claim.leaseOwner]
    );
    if (r.rowCount !== 1) rejected('PG_TICKET_LEASE_STALE');
    return leaseState(r.rows[0], claim);
  };

  async function issueForLease({
    claim, appUri, grantUri, consentRevision
  } = {}) {
    if (!claim || typeof claim !== 'object' ||
        !UUID.test(claim.leaseOwner || '') || !DID.test(claim.did || '') ||
        !EPOCH.test(String(claim.leaseEpoch || '')) ||
        typeof consentRevision !== 'string' || !EPOCH.test(consentRevision) ||
        BigInt(consentRevision) > 9223372036854775807n ||
        BigInt(String(claim.leaseEpoch)) > 9223372036854775807n) {
      rejected('PG_TICKET_SCOPE_INVALID');
    }
    webId(claim.accountId);
    webId(appUri);
    webId(grantUri);

    const lease = await getLease(claim);
    const proof = await verifySignedHead({
      accountId: claim.accountId, did: claim.did
    });
    if (proof?.verified !== true || proof.accountId !== claim.accountId ||
        proof.did !== claim.did || proof.commitCid !== lease.head_cid ||
        proof.rootCid !== lease.root_cid || proof.rev !== lease.rev ||
        !['pending', 'delivered'].includes(proof.outboxStatus)) {
      rejected('PG_TICKET_SIGNED_HEAD_CHANGED');
    }
    const granted = await verifyCurrentSaiConsent({
      accountId: claim.accountId,
      appUri, grantUri, consentRevision
    });
    if (granted !== true) rejected('PG_TICKET_SAI_NOT_CURRENT');
    if (canonicalMode) {
      const current = await verifyCanonicalPgConsent({
        accountId: claim.accountId, did: claim.did,
        appUri, grantUri, consentRevision
      });
      if (current !== true) rejected('PG_TICKET_CANONICAL_PERMISSION_DENIED');
    }

    // Neither a CPU-heavy signature check nor a Moleculer/Jena call runs
    // while holding a database connection or transaction open.
    await getLease(claim);
    const scope = {
      accountId: claim.accountId, did: claim.did,
      appUri, grantUri, epoch: consentRevision,
      projectionFence: String(lease.lease_epoch),
      operation: 'project', rootCid: lease.root_cid, rev: lease.rev
    };
    return Object.freeze({
      ticket: tickets.issue(scope),
      scope: Object.freeze(scope),
      headCid: lease.head_cid
    });
  }

  return Object.freeze({ issueForLease });
}
