'use strict';

const { MIME_TYPES } = require('@semapps/mime-types');
const { sanitizeSparqlQuery } = require('@semapps/triplestore');
const {
  DELIVERY_PLAN_SCHEMA,
  computeDeliveryPlanIntentId,
  determineActivityVisibility,
  getExplicitConcreteRecipientUris,
  hasSenderFollowersAudience,
  isActorFollowersAddress,
  normalizeDeliveryTargetDomain,
  parseDeliveryEndpointUrl,
  sanitizeDeliveryActivity,
  validateDeliveryPlanV1
} = require('./activitypub-delivery-plan');

const DEFAULT_TARGET_RESOLUTION_CONCURRENCY = 10;
const DEFAULT_LOCAL_TARGET_CACHE_MAX_ENTRIES = 4096;
const DEFAULT_REMOTE_TARGET_CACHE_MAX_ENTRIES = 4096;
const remoteTargetCacheAuthorities = new WeakMap();
const LOCAL_COLLECTION_QUERIES = Object.freeze({
  followers: Object.freeze({
    prefix: 'PREFIX as: <https://www.w3.org/ns/activitystreams#>',
    predicate: 'as:followers'
  }),
  inbox: Object.freeze({
    prefix: 'PREFIX ldp: <http://www.w3.org/ns/ldp#>',
    predicate: 'ldp:inbox'
  }),
  outbox: Object.freeze({
    prefix: 'PREFIX as: <https://www.w3.org/ns/activitystreams#>',
    predicate: 'as:outbox'
  })
});

function normalizeActorUri(value) {
  if (typeof value === 'string' && value.length > 0) return value;
  if (value && typeof value === 'object') return value.id || value['@id'] || null;
  return null;
}

function normalizeAddress(value) {
  if (typeof value === 'string') return value;
  if (value && typeof value === 'object' && !Array.isArray(value)) return value.id || value['@id'] || null;
  return null;
}

function addressValues(value) {
  const values = Array.isArray(value) ? value : [value];
  return values.map(normalizeAddress).filter(item => typeof item === 'string');
}

function isFollowersCollectionUri(value) {
  if (typeof value !== 'string' || value.length === 0) return false;
  try {
    return new URL(value).pathname.replace(/\/+$/u, '').endsWith('/followers');
  } catch {
    return false;
  }
}

function determineVisibility(activity) {
  return determineActivityVisibility(activity);
}

async function mapWithConcurrency(items, concurrency, mapper) {
  const normalizedConcurrency = Math.max(1, Math.floor(concurrency || 1));
  const output = new Array(items.length);
  let nextIndex = 0;

  async function worker() {
    while (true) {
      const index = nextIndex;
      nextIndex += 1;
      if (index >= items.length) return;
      output[index] = await mapper(items[index], index);
    }
  }

  const workerCount = Math.min(normalizedConcurrency, Math.max(items.length, 1));
  await Promise.all(Array.from({ length: workerCount }, () => worker()));
  return output;
}

function createDeliveryIntentId({ activityId, actorUri, localRecipientUris, remoteRecipientUris }) {
  return computeDeliveryPlanIntentId({ activityId, actorUri, localRecipientUris, remoteRecipientUris });
}

async function resolveLocalActorCollectionUri(ctx, { actorUri, dataset, collection }) {
  if (typeof actorUri !== 'string' || actorUri.length === 0) {
    throw new Error(`Local ${collection || 'collection'} resolution requires an actor URI`);
  }
  if (typeof dataset !== 'string' || dataset.length === 0) {
    throw new Error(`Local ${collection || 'collection'} resolution requires a dataset for ${actorUri}`);
  }
  if (!Object.prototype.hasOwnProperty.call(LOCAL_COLLECTION_QUERIES, collection)) {
    throw new Error(`Unsupported local ActivityPub collection predicate ${collection}`);
  }
  const querySpec = LOCAL_COLLECTION_QUERIES[collection];

  const bindingName = `${collection}Uri`;
  const actorIri = sanitizeSparqlQuery`<${actorUri}>`;
  const query = `
    ${querySpec.prefix}
    SELECT DISTINCT ?${bindingName}
    WHERE {
      ${actorIri} ${querySpec.predicate} ?${bindingName} .
    }
    LIMIT 2
  `;
  const rows = await ctx.call('triplestore.query', {
    query,
    accept: MIME_TYPES.SPARQL_JSON,
    dataset,
    webId: 'system'
  });
  const collectionUris = (Array.isArray(rows) ? rows : [])
    .map(row => row?.[bindingName]?.value)
    .filter(value => typeof value === 'string' && value.length > 0);

  if (collectionUris.length !== 1) {
    throw new Error(
      collectionUris.length === 0
        ? `Unable to resolve safe local ${collection} for ${actorUri}`
        : `Unable to resolve unambiguous local ${collection} for ${actorUri}`
    );
  }

  const collectionUri = collectionUris[0];
  if (!parseDeliveryEndpointUrl(collectionUri)) {
    throw new Error(`Unable to resolve safe local ${collection} for ${actorUri}`);
  }
  return collectionUri;
}

async function resolveLocalFollowersUri(ctx, actorUri, dataset) {
  return resolveLocalActorCollectionUri(ctx, { actorUri, dataset, collection: 'followers' });
}

async function resolveLocalInboxUri(ctx, actorUri, dataset) {
  return resolveLocalActorCollectionUri(ctx, { actorUri, dataset, collection: 'inbox' });
}

async function resolveLocalOutboxUri(ctx, actorUri, dataset) {
  return resolveLocalActorCollectionUri(ctx, { actorUri, dataset, collection: 'outbox' });
}

function localDatasetForAccount(actorUri, podProvider, account) {
  if (!account) throw new Error(`Unable to resolve local ActivityPub account for ${actorUri}`);
  const dataset = podProvider ? account.username : account.username || account.dataset;
  if (typeof dataset !== 'string' || dataset.length === 0) {
    throw new Error(`Unable to resolve local dataset for ${actorUri}`);
  }
  return dataset;
}

function normalizeLocalDeliveryTarget(actorUri, dataset, target) {
  if (
    !target ||
    typeof target !== 'object' ||
    Array.isArray(target) ||
    target.actorUri !== actorUri ||
    target.dataset !== dataset
  ) {
    throw new Error(`Cached local delivery target does not match ${actorUri} in dataset ${dataset}`);
  }
  if (typeof target.inboxUri !== 'string' || !parseDeliveryEndpointUrl(target.inboxUri)) {
    throw new Error(`Cached local delivery target has invalid inbox for ${actorUri}`);
  }
  return { actorUri, dataset, inboxUri: target.inboxUri };
}

async function resolveLocalDeliveryTarget(ctx, actorUri, podProvider, preResolvedAccount) {
  const account =
    preResolvedAccount === undefined
      ? await ctx.call('auth.account.findByWebId', { webId: actorUri })
      : preResolvedAccount;
  const dataset = localDatasetForAccount(actorUri, podProvider, account);
  const inboxUri = await resolveLocalInboxUri(ctx, actorUri, dataset);
  return { actorUri, dataset, inboxUri };
}

async function resolveLocalDeliveryTargetWithCache(
  ctx,
  actorUri,
  podProvider,
  preResolvedAccount,
  localDeliveryTargets,
  maxEntries = DEFAULT_LOCAL_TARGET_CACHE_MAX_ENTRIES
) {
  const account =
    preResolvedAccount === undefined
      ? await ctx.call('auth.account.findByWebId', { webId: actorUri })
      : preResolvedAccount;
  const dataset = localDatasetForAccount(actorUri, podProvider, account);

  if (localDeliveryTargets instanceof Map && localDeliveryTargets.has(actorUri)) {
    try {
      return normalizeLocalDeliveryTarget(actorUri, dataset, localDeliveryTargets.get(actorUri));
    } catch {
      localDeliveryTargets.delete(actorUri);
    }
  }

  const inboxUri = await resolveLocalInboxUri(ctx, actorUri, dataset);
  const target = { actorUri, dataset, inboxUri };
  if (localDeliveryTargets instanceof Map) {
    const boundedMaxEntries = Math.max(0, Math.floor(Number(maxEntries) || 0));
    if (localDeliveryTargets.size < boundedMaxEntries) {
      localDeliveryTargets.set(actorUri, Object.freeze({ ...target }));
    }
  }
  return target;
}

function parseRemoteDeliveryUrl(value, actorUri, label) {
  if (typeof value !== 'string' || value.length === 0) {
    throw new Error(`Unable to resolve remote ${label} for ${actorUri}`);
  }
  const parsed = parseDeliveryEndpointUrl(value);
  if (!parsed) {
    throw new Error(`Resolved invalid remote ${label} URL for ${actorUri}`);
  }
  return parsed;
}

function normalizeRemoteDeliveryTarget(actorUri, target) {
  if (!target || typeof target !== 'object' || Array.isArray(target) || target.actorUri !== actorUri) {
    throw new Error(`Cached remote delivery target does not match ${actorUri}`);
  }

  const inbox = parseRemoteDeliveryUrl(target.inboxUrl, actorUri, 'inbox');
  const rawSharedInboxUrl = target.sharedInboxUrl;
  let sharedInboxUrl;
  let deliveryUrl = inbox;
  if (rawSharedInboxUrl !== undefined && rawSharedInboxUrl !== null && rawSharedInboxUrl !== '') {
    const sharedInbox = parseRemoteDeliveryUrl(rawSharedInboxUrl, actorUri, 'shared inbox');
    sharedInboxUrl = sharedInbox.toString();
    deliveryUrl = sharedInbox;
  }

  const targetDomain = normalizeDeliveryTargetDomain(deliveryUrl.hostname);
  if (!targetDomain) {
    throw new Error(`Resolved invalid remote delivery hostname for ${actorUri}`);
  }

  return {
    actorUri,
    inboxUrl: inbox.toString(),
    ...(sharedInboxUrl ? { sharedInboxUrl } : {}),
    targetDomain
  };
}

async function resolveRemoteDeliveryTarget(ctx, actorUri, signingActorUri) {
  if (typeof signingActorUri !== 'string' || signingActorUri.length === 0 || signingActorUri === 'system') {
    throw new Error(`Remote delivery target resolution requires a concrete sender authority for ${actorUri}`);
  }
  const actor = await ctx.call('activitypub.actor.get', { actorUri, webId: signingActorUri });
  return normalizeRemoteDeliveryTarget(actorUri, {
    actorUri,
    inboxUrl: actor && actor.inbox,
    sharedInboxUrl: actor?.endpoints?.sharedInbox
  });
}

async function resolveRemoteDeliveryTargetWithCache(
  ctx,
  actorUri,
  signingActorUri,
  remoteDeliveryTargets,
  maxEntries = DEFAULT_REMOTE_TARGET_CACHE_MAX_ENTRIES
) {
  if (!(remoteDeliveryTargets instanceof Map)) return resolveRemoteDeliveryTarget(ctx, actorUri, signingActorUri);

  const cachedAuthority = remoteTargetCacheAuthorities.get(remoteDeliveryTargets);
  if (cachedAuthority && cachedAuthority !== signingActorUri) {
    throw new Error('Remote delivery target cache cannot be reused across sender authorities');
  }
  if (!cachedAuthority) remoteTargetCacheAuthorities.set(remoteDeliveryTargets, signingActorUri);

  if (remoteDeliveryTargets.has(actorUri)) {
    try {
      return normalizeRemoteDeliveryTarget(actorUri, remoteDeliveryTargets.get(actorUri));
    } catch {
      remoteDeliveryTargets.delete(actorUri);
    }
  }

  const target = await resolveRemoteDeliveryTarget(ctx, actorUri, signingActorUri);
  const boundedMaxEntries = Math.max(0, Math.floor(Number(maxEntries) || 0));
  if (remoteDeliveryTargets.size < boundedMaxEntries) {
    remoteDeliveryTargets.set(actorUri, Object.freeze({ ...target }));
  }
  return target;
}

function assertConcreteRecipientUris(recipientUris, classification, actorUri) {
  const followersCollection = recipientUris.find(uri => isActorFollowersAddress(uri, actorUri));
  if (followersCollection) {
    throw new Error(
      `ActivityPub Delivery Plan received unresolved ${classification} followers collection ${followersCollection}`
    );
  }
}

function assertSourceRecipientCoverage(activity, localRecipientUris, remoteRecipientUris) {
  if (hasSenderFollowersAudience(activity)) {
    throw new Error(
      'ActivityPub Delivery Plan cannot safely infer sender followers from the audience field; authoritative audience expansion is required before external delivery'
    );
  }

  const plannedRecipients = new Set([...localRecipientUris, ...remoteRecipientUris]);
  const omittedRecipient = getExplicitConcreteRecipientUris(activity).find(uri => !plannedRecipients.has(uri));
  if (omittedRecipient) {
    throw new Error(`ActivityPub Delivery Plan omitted explicitly addressed recipient ${omittedRecipient}`);
  }
}

async function buildDeliveryPlanV1(
  ctx,
  {
    activity,
    localRecipientUris = [],
    remoteRecipientUris = [],
    localRecipientAccounts,
    localDeliveryTargets,
    remoteDeliveryTargets,
    podProvider = true,
    concurrency = DEFAULT_TARGET_RESOLUTION_CONCURRENCY
  }
) {
  const actorUri = normalizeActorUri(activity?.actor);
  const activityId = activity?.id || activity?.['@id'];
  if (!actorUri || typeof activityId !== 'string' || activityId.length === 0) {
    throw new Error('ActivityPub Delivery Plan requires concrete actorUri and activityId');
  }

  const uniqueLocalUris = [...new Set(localRecipientUris.filter(value => typeof value === 'string'))];
  const uniqueRemoteUris = [...new Set(remoteRecipientUris.filter(value => typeof value === 'string'))];
  assertConcreteRecipientUris(uniqueLocalUris, 'local', actorUri);
  assertConcreteRecipientUris(uniqueRemoteUris, 'remote', actorUri);

  const localSet = new Set(uniqueLocalUris);
  const overlappingRecipient = uniqueRemoteUris.find(uri => localSet.has(uri));
  if (overlappingRecipient) {
    throw new Error(`ActivityPub Delivery Plan recipient cannot be both local and remote: ${overlappingRecipient}`);
  }
  assertSourceRecipientCoverage(activity, uniqueLocalUris, uniqueRemoteUris);

  const taggedTargets = [
    ...uniqueLocalUris.map(actor => ({ classification: 'local', actor })),
    ...uniqueRemoteUris.map(actor => ({ classification: 'remote', actor }))
  ];
  const resolvedTargets = await mapWithConcurrency(taggedTargets, concurrency, async target => ({
    classification: target.classification,
    value:
      target.classification === 'local'
        ? await resolveLocalDeliveryTargetWithCache(
            ctx,
            target.actor,
            podProvider,
            localRecipientAccounts instanceof Map && localRecipientAccounts.has(target.actor)
              ? localRecipientAccounts.get(target.actor)
              : undefined,
            localDeliveryTargets
          )
        : await resolveRemoteDeliveryTargetWithCache(ctx, target.actor, actorUri, remoteDeliveryTargets)
  }));
  const localRecipients = resolvedTargets
    .filter(target => target.classification === 'local')
    .map(target => target.value);
  const remoteRecipients = resolvedTargets
    .filter(target => target.classification === 'remote')
    .map(target => target.value);

  const visibility = determineVisibility(activity);
  const deliveryActivity = sanitizeDeliveryActivity(activity);
  const plan = {
    schema: DELIVERY_PLAN_SCHEMA,
    intentId: createDeliveryIntentId({
      activityId,
      actorUri,
      localRecipientUris: uniqueLocalUris,
      remoteRecipientUris: uniqueRemoteUris
    }),
    activityId,
    actorUri,
    activity: deliveryActivity,
    localRecipients,
    remoteRecipients,
    meta: {
      visibility,
      isPublicActivity: visibility === 'public' || visibility === 'unlisted'
    }
  };

  if (!validateDeliveryPlanV1(plan)) {
    throw new Error(`Generated invalid ${DELIVERY_PLAN_SCHEMA} payload for ${activityId}`);
  }

  return plan;
}

module.exports = {
  DEFAULT_LOCAL_TARGET_CACHE_MAX_ENTRIES,
  DEFAULT_REMOTE_TARGET_CACHE_MAX_ENTRIES,
  DEFAULT_TARGET_RESOLUTION_CONCURRENCY,
  addressValues,
  assertConcreteRecipientUris,
  assertSourceRecipientCoverage,
  buildDeliveryPlanV1,
  createDeliveryIntentId,
  determineVisibility,
  isFollowersCollectionUri,
  localDatasetForAccount,
  mapWithConcurrency,
  normalizeActorUri,
  normalizeLocalDeliveryTarget,
  normalizeRemoteDeliveryTarget,
  resolveLocalActorCollectionUri,
  resolveLocalDeliveryTarget,
  resolveLocalDeliveryTargetWithCache,
  resolveLocalFollowersUri,
  resolveLocalInboxUri,
  resolveLocalOutboxUri,
  resolveRemoteDeliveryTarget,
  resolveRemoteDeliveryTargetWithCache
};
