/**
 * NON-ACTIVATED candidate adapter to the REAL ActivityPods per-WebID
 * ControlledContainerMixin and per-username Jena/TDB2 dataset.
 *
 * No public API, no registered Moleculer service and no background scanner.
 * Only disposable, provider-owned integration tests may instantiate this.
 * Every relevant call is indexed or an exact resource read; no Pod/account
 * enumeration, no unbounded fan-out, no DB connections held across I/O.
 */
import crypto from 'node:crypto';
import { buildFencedRepoProjectionSparql } from './fuseki-fence.mjs';
import {
  safeIri, consentSubject, readConsentQuery, bootstrapConsentQuery,
  beginRevocationQuery, parseConsentRows
} from './pod-consent-fence.mjs';

const APODS = 'http://activitypods.org/ns/core#';
const INTEROP = 'http://www.w3.org/ns/solid/interop#';
const ACL_WRITE = new Set(['acl:Write', 'http://www.w3.org/ns/auth/acl#Write']);
const USERNAME = /^[a-z0-9][a-z0-9_-]{0,62}$/u;
const DID = /^did:plc:[a-z2-7]{24}$/u;
const CID = /^bafyre[a-z2-7]{53}$/u;
const TID = /^[234567abcdefghij][234567abcdefghijklmnopqrstuvwxyz]{12}$/u;
const FENCE = /^[1-9][0-9]{0,18}$/u;
const MAX = 9223372036854775807n;

function deny(code, text) {
  const e = new Error(text);
  e.code = code;
  throw e;
}
function canonicalUrl(value, { fragment = false } = {}) {
  safeIri(value, { httpsOnly: true });
  const u = new URL(value);
  if ((!fragment && u.hash) || u.search || u.username || u.password || u.href !== value) {
    deny('POD_PROJECTION_LOCATION_INVALID', 'Noncanonical user-controlled URI');
  }
  return value;
}
function contained(child, parent) {
  const root = parent.endsWith('/') ? parent : parent + '/';
  return child.startsWith(root) && child.length > root.length;
}
function property(resource, field) {
  const compact = 'interop:' + field;
  const raw = resource?.[compact] ?? resource?.[INTEROP + field];
  return raw;
}
function scalar(raw) {
  if (Array.isArray(raw)) {
    if (raw.length !== 1) return null;
    return scalar(raw[0]);
  }
  if (typeof raw === 'string') return raw;
  if (raw && typeof raw === 'object') {
    return scalar(raw['@id'] ?? raw['@value'] ?? raw.value);
  }
  return null;
}
function containsExactly(values, requested) {
  const entries = Array.isArray(values) ? values : [values];
  return entries.length > 0 && entries.length <= 32 &&
    entries.some(x => scalar(x) === requested);
}
function scope({ accountId, did, appUri, grantUri, epoch, operation }) {
  canonicalUrl(accountId);
  canonicalUrl(appUri);
  canonicalUrl(grantUri);
  if (!DID.test(did || '') || typeof epoch !== 'string' ||
      !FENCE.test(epoch) || BigInt(epoch) > MAX ||
      !['bootstrap', 'project', 'revoke'].includes(operation)) {
    deny('POD_PROJECTION_SCOPE_INVALID', 'Invalid protected repository scope');
  }
  return Object.freeze({ accountId, did, appUri, grantUri, epoch, operation });
}
function checkBinding(binding, location, did) {
  if (!binding || binding.id !== location.resourceUri ||
      binding.canonicalAccountId !== location.accountId ||
      binding.webId !== location.accountId ||
      binding.activityPubActorId !== location.accountId ||
      binding.atprotoDid !== did || binding.atprotoManaged !== true ||
      binding.atprotoSource !== 'local' || binding.status !== 'active') {
    deny('POD_PROJECTION_IDENTITY_DRIFT', 'Canonical LDP identity association differs');
  }
}
function checkProjected(binding, expected, epoch) {
  checkBinding(binding, expected.location, expected.did);
  if (binding.repoInitialized !== true ||
      binding.repoRootCid !== expected.rootCid ||
      binding.repoRev !== expected.rev ||
      binding.repoProjectionFence !== epoch) {
    deny('POD_PROJECTION_READBACK_MISMATCH', 'Protected LDP read-back does not match CAS');
  }
}
function grantResource(result, resourceUri) {
  if (!result || (result.id || result['@id']) !== resourceUri) {
    deny('POD_PROJECTION_SAI_INVALID', 'SAI grant resource was not the exact requested record');
  }
  return result;
}

/**
 * The issuer of 'operationTickets' stays in trusted provider code. 'call'
 * invokes actual ActivityPods Moleculer actions with fresh, independently
 * verified credentials, rather than trusting inherited ctx.meta.
 *
 * The expectedRepoShapeTree must be an explicitly configured, installed
 * per-app SAI DataGrant shape; it is NOT inferred from arbitrary input.
 * The adapter is deliberately test-only until the real SAI mutation hooks
 * cover every grant replacement/revocation path.
 */
export function createPodActivityPodsProjection({
  call, operationTickets, expectedIssuer, expectedRepoShapeTree,
  graphUri = null, fixtureOnly = false, now = Date.now
} = {}) {
  const enabled = fixtureOnly === true &&
    process.env.ATPROTO_REPO_FUSEKI_PROOF_DISPOSABLE === 'confirmed' &&
    process.env.NODE_ENV !== 'production';
  if (!enabled) {
    const closed = async () => deny('POD_PROJECTION_NOT_RELEASED', 'Per-Pod repository writer is not released');
    return Object.freeze({ locate: closed, bootstrapConsent: closed, project: closed, revoke: closed, check: closed });
  }
  if (typeof call !== 'function' || !operationTickets ||
      typeof operationTickets.verify !== 'function' ||
      typeof expectedIssuer !== 'string' || !expectedIssuer ||
      typeof expectedRepoShapeTree !== 'string') {
    deny('POD_PROJECTION_CONFIG_INVALID', 'Trusted provider/OIDC/SAI configuration required');
  }
  canonicalUrl(expectedIssuer);
  safeIri(expectedRepoShapeTree, { httpsOnly: true });
  if (graphUri !== null) safeIri(graphUri);

  const invoke = (name, params) => call(name, params, { timeout: 5000 });

  async function locate(accountId) {
    canonicalUrl(accountId);
    // The auth account is looked up by its indexed WebID, never via a
    // population scan. Solid storage creates the dataset as username.
    const account = await invoke('auth.account.findByWebId', { webId: accountId });
    if (!account || account.webId !== accountId || !USERNAME.test(account.username || '')) {
      deny('POD_PROJECTION_OWNER_UNKNOWN', 'Unverified canonical Pod dataset owner');
    }
    const dataset = account.username;
    const [storageRoot, containerUri] = await Promise.all([
      invoke('solid-storage.getUrl', { webId: accountId }),
      invoke('identitybindings.getContainerUri', { webId: accountId })
    ]);
    canonicalUrl(storageRoot);
    canonicalUrl(containerUri);
    if (!contained(containerUri, storageRoot) ||
        new URL(storageRoot).origin !== new URL(accountId).origin ||
        new URL(containerUri).origin !== new URL(accountId).origin) {
      deny('POD_PROJECTION_LOCATION_INVALID', 'LDP binding is not contained in the owner Pod');
    }
    const slug = 'atproto-' + crypto.createHash('sha256').update(accountId).digest('hex').slice(0, 24);
    const resourceUri = containerUri.replace(/\/?$/u, '/') + slug;
    if (!contained(resourceUri, containerUri)) {
      deny('POD_PROJECTION_LOCATION_INVALID', 'Canonical protected binding location invalid');
    }
    const exists = await invoke('triplestore.dataset.exist', { dataset });
    if (exists !== true) {
      deny('POD_PROJECTION_DATASET_MISSING', 'Canonical per-Pod dataset does not exist');
    }
    return Object.freeze({ accountId, dataset, storageRoot, containerUri, resourceUri });
  }

  async function oidc(token, accountId, appUri) {
    if (typeof token !== 'string' || token.length > 8192 || !token) {
      deny('POD_PROJECTION_OIDC_INVALID', 'Missing OIDC token');
    }
    // Existing jwk.verifyToken validates JWT cryptographic signature and time
    // but not audience/issuer: enforce them here, together with session
    // freshness. Neither ctx.meta.webId nor ctx.meta.impersonatedUser is proof.
    const verified = await invoke('jwk.verifyToken', { token });
    const time = Math.floor(now() / 1000);
    const audienceOk = verified?.aud === appUri ||
      (Array.isArray(verified?.aud) && verified.aud.length === 1 && verified.aud[0] === appUri);
    if (!verified || verified.iss !== expectedIssuer || !audienceOk ||
        verified.azp !== appUri || verified.webid !== accountId ||
        !Number.isInteger(verified.iat) || !Number.isInteger(verified.exp) ||
        verified.iat > time + 5 || verified.iat < time - 300 ||
        verified.exp <= time || verified.exp > time + 3600) {
      deny('POD_PROJECTION_OIDC_INVALID', 'Solid-OIDC application/subject/audience mismatch');
    }
    return true;
  }

  async function sai(location, appUri, grantUri) {
    const grantContainer = await invoke('access-grants.getContainerUri', { webId: location.accountId });
    canonicalUrl(grantContainer);
    if (!contained(grantUri, grantContainer) ||
        !contained(grantContainer, location.storageRoot)) {
      deny('POD_PROJECTION_SAI_INVALID', 'Grant does not belong to this Pod');
    }
    const grant = grantResource(await invoke('access-grants.get', {
      resourceUri: grantUri, webId: 'system'
    }), grantUri);
    if (scalar(property(grant, 'grantedBy')) !== location.accountId ||
        scalar(property(grant, 'grantee')) !== appUri) {
      deny('POD_PROJECTION_SAI_INVALID', 'AccessGrant owner or application mismatch');
    }
    const data = property(grant, 'hasDataGrant');
    const links = Array.isArray(data) ? data : [data];
    if (links.length !== 1) {
      deny('POD_PROJECTION_SAI_INVALID', 'Require exactly one scoped DataGrant for this operation');
    }
    const dataGrantUri = scalar(links[0]);
    canonicalUrl(dataGrantUri);
    const dataContainer = await invoke('data-grants.getContainerUri', { webId: location.accountId });
    canonicalUrl(dataContainer);
    if (!contained(dataGrantUri, dataContainer) ||
        !contained(dataContainer, location.storageRoot)) {
      deny('POD_PROJECTION_SAI_INVALID', 'DataGrant is not owner-scoped');
    }
    const dataGrant = grantResource(await invoke('data-grants.get', {
      resourceUri: dataGrantUri, webId: 'system'
    }), dataGrantUri);
    if (scalar(property(dataGrant, 'dataOwner')) !== location.accountId ||
        scalar(property(dataGrant, 'grantee')) !== appUri ||
        scalar(property(dataGrant, 'registeredShapeTree')) !== expectedRepoShapeTree ||
        !containsExactly(property(dataGrant, 'accessMode'), 'acl:Write') &&
        !containsExactly(property(dataGrant, 'accessMode'), 'http://www.w3.org/ns/auth/acl#Write')) {
      deny('POD_PROJECTION_SAI_INVALID', 'Missing current SAI scope, owner or write grant');
    }
    return true;
  }

  async function consent(location, appUri, grantUri) {
    const subjectUri = consentSubject(location.accountId, appUri);
    const rows = await invoke('triplestore.query', {
      dataset: location.dataset, webId: 'system',
      query: readConsentQuery({ subjectUri, graphUri })
    });
    return { ...parseConsentRows(rows, { grantUri }), subjectUri };
  }
  function authorize(ticket, s) {
    operationTickets.verify(ticket, s);
  }
  async function binding(location, did) {
    const value = await invoke('identitybindings.getByCanonicalAccountId', {
      canonicalAccountId: location.accountId
    });
    checkBinding(value, location, did);
    return value;
  }
  async function bootstrapConsent({ accountId, did, appUri, grantUri, epoch, ticket, oidcToken }) {
    const s = scope({ accountId, did, appUri, grantUri, epoch, operation: 'bootstrap' });
    if (epoch !== '1') deny('POD_CONSENT_INVALID', 'Consent bootstrap requires epoch 1');
    authorize(ticket, s);
    const location = await locate(accountId);
    await oidc(oidcToken, accountId, appUri);
    await sai(location, appUri, grantUri);
    await binding(location, did);
    const subjectUri = consentSubject(accountId, appUri);
    await invoke('triplestore.update', {
      dataset: location.dataset, webId: 'system',
      query: bootstrapConsentQuery({ subjectUri, grantUri, graphUri })
    });
    const readback = await consent(location, appUri, grantUri);
    if (readback.status !== 'active' || readback.revision !== '1') {
      deny('POD_CONSENT_CONFLICT', 'Consent bootstrap was rejected or has been revoked');
    }
    await sai(location, appUri, grantUri);
    return Object.freeze({ accountId, status: 'active', epoch: '1' });
  }
  async function project({
    accountId, did, appUri, grantUri, epoch, ticket, oidcToken, rootCid, rev
  }) {
    const s = scope({ accountId, did, appUri, grantUri, epoch, operation: 'project' });
    if (!CID.test(rootCid || '') || !TID.test(rev || '')) {
      deny('POD_PROJECTION_SCOPE_INVALID', 'Invalid signed repository root/revision');
    }
    authorize(ticket, s);
    const location = await locate(accountId);
    await oidc(oidcToken, accountId, appUri);
    await sai(location, appUri, grantUri);
    await binding(location, did);
    const prior = await consent(location, appUri, grantUri);
    if (prior.status !== 'active' || prior.revision !== epoch) {
      deny('POD_CONSENT_NOT_ACTIVE', 'Grant is revoked or revision changed');
    }
    await invoke('triplestore.update', {
      dataset: location.dataset, webId: 'system',
      query: buildFencedRepoProjectionSparql({
        resourceUri: location.resourceUri, graphUri,
        accountId, did, rootCid, rev, fence: epoch,
        consentFence: { subjectUri: prior.subjectUri, grantUri, revision: epoch }
      })
    });
    // Never trust Fuseki HTTP 2xx as CAS success: LDP read-back must match,
    // the durable consent must still be active and the SAI grant still exist.
    checkProjected(await binding(location, did), { location, did, rootCid, rev }, epoch);
    const after = await consent(location, appUri, grantUri);
    if (after.status !== 'active' || after.revision !== epoch) {
      deny('POD_CONSENT_NOT_ACTIVE', 'Revoked SAI grant after RDF write');
    }
    await sai(location, appUri, grantUri);
    await oidc(oidcToken, accountId, appUri);
    return Object.freeze({ projected: true, accountId, did, rootCid, rev, epoch });
  }
  async function revoke({ accountId, did, appUri, grantUri, epoch, ticket }) {
    const s = scope({ accountId, did, appUri, grantUri, epoch, operation: 'revoke' });
    authorize(ticket, s);
    const location = await locate(accountId);
    // Revocation must NEVER depend on an active/valid user token or an already
    // removed SAI record. This is intended for the trusted SAI *pre-delete*
    // lifecycle hook; a failure must block that mutation rather than regrant.
    const before = await consent(location, appUri, grantUri);
    if (before.status !== 'active' || before.revision !== epoch) {
      deny('POD_CONSENT_NOT_ACTIVE', 'Consent already blocked or concurrently revised');
    }
    await invoke('triplestore.update', {
      dataset: location.dataset, webId: 'system',
      query: beginRevocationQuery({
        subjectUri: before.subjectUri, grantUri, revision: epoch, graphUri
      })
    });
    const after = await consent(location, appUri, grantUri);
    if (after.status !== 'blocked' || after.revision !== String(BigInt(epoch) + 1n)) {
      deny('POD_CONSENT_REVOKE_UNVERIFIED', 'Revocation fence did not persist');
    }
    return Object.freeze({ revoked: true, accountId, epoch: after.revision });
  }
  async function check({ accountId, did, appUri, grantUri, epoch, oidcToken, rootCid, rev }) {
    scope({ accountId, did, appUri, grantUri, epoch, operation: 'project' });
    const location = await locate(accountId);
    await oidc(oidcToken, accountId, appUri);
    await sai(location, appUri, grantUri);
    checkProjected(await binding(location, did), { location, did, rootCid, rev }, epoch);
    const active = await consent(location, appUri, grantUri);
    if (active.status !== 'active' || active.revision !== epoch) {
      deny('POD_CONSENT_NOT_ACTIVE', 'Revoked grant cannot imply repository readiness');
    }
    return Object.freeze({ ready: true, accountId, did, epoch });
  }
  return Object.freeze({ locate, bootstrapConsent, project, revoke, check });
}
