'use strict';

const { MoleculerError } = require('moleculer').Errors;
const { hasAuthorizedOwnerParentForBroker } = require('./atproto-sai-owner-context');
const {
  buildCanonicalPodAccountLookup, parseCanonicalPodAccount
} = require('../../candidates/atproto-signed-repo-proof/pod-account-lookup.cjs');
const {
  safeIri, safeEpoch, consentSubject, readConsentQuery,
  beginRevocationQuery, parseConsentRows
} = require('../../candidates/atproto-signed-repo-proof/pod-consent-fence.cjs');

const INTEROP = 'http://www.w3.org/ns/solid/interop#';
const ALLOWED_KINDS = new Set([
  'access-authorizations', 'data-authorizations', 'access-grants', 'data-grants'
]);

function deny(type, cause) {
  throw new MoleculerError(
    'The ATProto consent change could not be safely recorded',
    503, type,
    cause ? { reason: cause } : undefined
  );
}

function scalar(value) {
  if (Array.isArray(value)) return value.length === 1 ? scalar(value[0]) : null;
  if (typeof value === 'string') return value;
  if (value && typeof value === 'object') return scalar(value['@id'] ?? value['@value'] ?? value.value);
  return null;
}

function claim(resource, property) {
  if (!resource || typeof resource !== 'object') return null;
  const aliases = ['interop:' + property, INTEROP + property];
  const present = aliases.filter(key => Object.prototype.hasOwnProperty.call(resource, key));
  if (present.length !== 1) return null;
  return scalar(resource[present[0]]);
}

// The approved-app configuration is small and rarely changes. Avoid parsing
// it and allocating a new Set for every SAI grant action. Hold only the most
// recent value so configuration reloads cannot accumulate cache entries.
let cachedApprovedApps = null;
function approvedApps() {
  const raw = process.env.APODS_ATPROTO_SAI_FENCED_APPS || '';
  if (cachedApprovedApps?.raw === raw) return cachedApprovedApps.apps;
  if (raw.length > 8192) deny('ATPROTO_SAI_FENCE_CONFIG_INVALID');
  const apps = raw.split(',').map(app => app.trim()).filter(Boolean);
  if (!apps.length || apps.length > 32 || new Set(apps).size !== apps.length) {
    deny('ATPROTO_SAI_FENCE_CONFIG_INVALID');
  }
  for (const app of apps) {
    try {
      safeIri(app, { httpsOnly: true });
      const uri = new URL(app);
      if (uri.search || uri.hash || uri.href !== app) throw Error('Invalid app');
    } catch {
      deny('ATPROTO_SAI_FENCE_CONFIG_INVALID');
    }
  }
  const verified = new Set(apps);
  cachedApprovedApps = { raw, apps: verified };
  return verified;
}

// ActivityPods stores LDP resources outside the container URI when
// resourcesWithContainerPath is false. Verify the authoritative ldp:contains
// triple rather than relying on a URI prefix or listing the whole container.
function resourceMembershipQuery(containerUri, resourceUri) {
  safeIri(containerUri, { httpsOnly: true });
  safeIri(resourceUri, { httpsOnly: true });
  const container = containerUri.replace(/[/]+$/u, '');
  const resource = resourceUri.replace(/[/]+$/u, '');
  return 'ASK WHERE { VALUES ?container { <' + container + '> <' + container +
    '/> } VALUES ?child { <' + resource + '> <' + resource +
    '/> } ?container <http://www.w3.org/ns/ldp#contains> ?child . }';
}

function isOwnedStorageUri(uri, owner) {
  if (typeof uri !== 'string' || uri.length > 4096) return false;
  try {
    const parsed = new URL(uri);
    const storageRoot = owner.replace(/[/]+$/u, '') + '/data/';
    return parsed.href === uri && !parsed.username && !parsed.password &&
      !parsed.search && !parsed.hash && uri.startsWith(storageRoot);
  } catch {
    return false;
  }
}

function bindingIdentity(kind, resource) {
  if (!ALLOWED_KINDS.has(kind)) deny('ATPROTO_SAI_FENCE_KIND_INVALID');
  const ownerKey = kind.startsWith('access-') ? 'grantedBy' : 'dataOwner';
  const owner = claim(resource, ownerKey);
  const app = claim(resource, 'grantee');
  if (!owner || !app) deny('ATPROTO_SAI_FENCE_IDENTITY_INVALID');
  safeIri(owner, { httpsOnly: true });
  safeIri(app, { httpsOnly: true });
  if (new URL(owner).hash || new URL(app).hash || new URL(owner).search ||
      new URL(app).search) deny('ATPROTO_SAI_FENCE_IDENTITY_INVALID');
  return { owner, app };
}

/**
 * Called from the native SAI LDP before-hooks.
 *
 * An existing active repository grant is fenced in its owner's Jena dataset
 * BEFORE any authorization or grant resource is changed. If a hook or the
 * database fails, the native SAI mutation is rejected. A successful fence
 * stays blocked even when a later SAI operation fails; only a new verified
 * consent ceremony may establish a fresh grant revision.
 *
 * The feature is off by default. Every app that can use the managed-repo
 * shape must appear in APODS_ATPROTO_SAI_FENCED_APPS before enabling it.
 */
async function beforeSaiMutation(ctx, kind, resource, operation) {
  if (process.env.APODS_ATPROTO_SAI_NATIVE_FENCE_ENABLED !== 'true') {
    return { checked: false };
  }
  // No broad Solid or provider-wide feature flag is needed for unrelated
  // SAI grants. Parse the small approved-app set before any broker calls.
  const apps = approvedApps();
  const { owner, app } = bindingIdentity(kind, resource);
  if (!apps.has(app)) return { checked: false };
  if (operation !== 'post' && operation !== 'delete') {
    deny('ATPROTO_SAI_FENCE_OPERATION_INVALID');
  }

  // This must happen before writing the consent barrier. Otherwise an
  // unauthorized LDP request could revoke someone else's repository access
  // simply by making the service run its before hook.
  //
  // SAI registration is an owner decision. A client acting through
  // impersonatedUser may use its granted data permissions, but cannot grant
  // or revoke the owner's repository authority.
  // Direct LDP calls must carry the authenticated owner. An app install,
  // upgrade or uninstall may perform nested LDP writes as 'system'; those
  // calls are accepted only while the already-authorized parent SAI action
  // is on the call stack for this exact owner/application pair.
  const directOwner = ctx.meta?.webId === owner && !ctx.meta?.impersonatedUser;
  const ownerAction = directOwner ? false :
    await hasAuthorizedOwnerParentForBroker(ctx, { owner, app });
  if (!directOwner && !ownerAction) {
    throw new MoleculerError(
      'Only the Pod owner can change this repository authorization',
      403, 'ATPROTO_SAI_OWNER_REQUIRED'
    );
  }

  // A slow Jena or Moleculer node must not hold a grant-mutation request
  // through a chain of independent 5-second timeouts. The entire fence has
  // one monotonic 12-second budget; exhausting it denies the SAI change.
  const deadline = process.hrtime.bigint() + 12_000_000_000n;
  const call = (name, params) => {
    const remainingMs = Number((deadline - process.hrtime.bigint()) / 1_000_000n);
    if (remainingMs < 1) deny('ATPROTO_SAI_FENCE_TIMEOUT');
    return ctx.call(name, params, { timeout: Math.min(5000, remainingMs) });
  };

  try {
    const nativeContainer = await call(kind + '.getContainerUri', { webId: owner });
    safeIri(nativeContainer, { httpsOnly: true });
    const target = operation === 'post' ? nativeContainer : ctx.params?.resourceUri;
    if (!isOwnedStorageUri(nativeContainer, owner) ||
        (operation === 'delete' && !isOwnedStorageUri(target, owner))) {
      throw new MoleculerError(
        'The authorization is outside the owner’s Pod storage',
        403, 'ATPROTO_SAI_TARGET_INVALID'
      );
    }
    if (operation === 'post' && ctx.params?.containerUri &&
        ctx.params.containerUri !== nativeContainer) {
      throw new MoleculerError(
        'The authorization must be stored in the owner’s SAI container',
        403, 'ATPROTO_SAI_TARGET_INVALID'
      );
    }
    const rights = await call('webacl.resource.hasRights', {
      resourceUri: target,
      rights: operation === 'post' ? { append: true, write: true } : { write: true },
      webId: owner
    });
    if (operation === 'post' ? rights?.append !== true && rights?.write !== true
        : rights?.write !== true) {
      throw new MoleculerError(
        'The Pod owner lacks permission to change this SAI resource',
        403, 'ATPROTO_SAI_MUTATION_NOT_ALLOWED'
      );
    }

    const accountRows = await call('triplestore.query', {
      dataset: 'settings', webId: 'system',
      query: buildCanonicalPodAccountLookup(owner)
    });
    const account = parseCanonicalPodAccount(accountRows, owner);
    const dataset = account.username;
    if (operation === 'delete') {
      const belongsToContainer = await call('triplestore.query', {
        dataset, webId: 'system',
        query: resourceMembershipQuery(nativeContainer, target)
      });
      if (belongsToContainer !== true) {
        throw new MoleculerError(
          'The authorization is not contained by the owner’s SAI container',
          403, 'ATPROTO_SAI_TARGET_INVALID'
        );
      }
    }
    const subjectUri = consentSubject(owner, app);
    const getRows = () => call('triplestore.query', {
      dataset, webId: 'system',
      query: readConsentQuery({ subjectUri })
    });
    const rows = await getRows();
    // No consent epoch exists yet for the new app/Pod. The eventual native
    // bootstrap must separately verify installed SAI permission.
    if (Array.isArray(rows) && rows.length === 0) return { checked: true, present: false };
    if (!Array.isArray(rows) || rows.length !== 1) {
      deny('ATPROTO_SAI_FENCE_AMBIGUOUS');
    }
    const grantUri = scalar(rows[0]?.grant);
    if (!grantUri) deny('ATPROTO_SAI_FENCE_AMBIGUOUS');
    safeIri(grantUri, { httpsOnly: true });
    const state = parseConsentRows(rows, { grantUri });
    if (state.status === 'blocked') return { checked: true, blocked: true };

    // Only the approved application's existing access grant is a valid
    // consent pointer. Do not trust the mutation's submitted grant URI.
    const grantContainer = await call('access-grants.getContainerUri', { webId: owner });
    safeIri(grantContainer, { httpsOnly: true });
    if (!isOwnedStorageUri(grantContainer, owner) ||
        !isOwnedStorageUri(grantUri, owner)) {
      deny('ATPROTO_SAI_FENCE_GRANT_INVALID');
    }
    const grantIsAttached = await call('triplestore.query', {
      dataset, webId: 'system',
      query: resourceMembershipQuery(grantContainer, grantUri)
    });
    if (grantIsAttached !== true) deny('ATPROTO_SAI_FENCE_GRANT_INVALID');
    safeEpoch(state.revision);
    if (BigInt(state.revision) === 9223372036854775807n) {
      deny('ATPROTO_SAI_FENCE_EPOCH_EXHAUSTED');
    }
    await call('triplestore.update', {
      dataset, webId: 'system',
      query: beginRevocationQuery({
        subjectUri, grantUri, revision: state.revision
      })
    });
    // SPARQL update HTTP success does not mean its WHERE clause matched.
    // A concurrent delete can race this hook; both paths must see blocked
    // consent before any native mutation is allowed to continue.
    const readback = parseConsentRows(await getRows(), { grantUri });
    if (readback.status !== 'blocked' ||
        BigInt(readback.revision) <= BigInt(state.revision)) {
      deny('ATPROTO_SAI_FENCE_NOT_DURABLE');
    }
    return { checked: true, blocked: true };
  } catch (error) {
    if (error instanceof MoleculerError && error.type?.startsWith('ATPROTO_SAI_')) {
      throw error;
    }
    // Never leak sensitive SAI or token contents in the public error.
    deny('ATPROTO_SAI_FENCE_UNAVAILABLE');
  }
}

module.exports = { beforeSaiMutation, bindingIdentity, claim, resourceMembershipQuery, isOwnedStorageUri };
