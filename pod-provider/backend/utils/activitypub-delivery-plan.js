'use strict';

const crypto = require('crypto');

const DELIVERY_PLAN_SCHEMA = 'ap.delivery-plan.v1';
const DELIVERY_PLAN_FIXTURE_SHA256 = '0d38040d212f781deb71fc8a62c9f4a6bef60ef977414369e9b8a41df0d1b09a';
const DELIVERY_PLAN_JSON_SCHEMA_SHA256 = '36ca416cc862c895ca87ff00a85facdd9ad171d9e214e9d0685e4c46fef5d6af';
const VISIBILITIES = new Set(['public', 'unlisted', 'followers', 'direct']);
const PLAN_KEYS = new Set(['schema', 'intentId', 'activityId', 'actorUri', 'activity', 'localRecipients', 'remoteRecipients', 'meta']);
const LOCAL_TARGET_KEYS = new Set(['actorUri', 'dataset', 'inboxUri']);
const REMOTE_TARGET_KEYS = new Set(['actorUri', 'inboxUrl', 'sharedInboxUrl', 'targetDomain']);
const META_KEYS = new Set(['visibility', 'isPublicActivity', 'isPublicIndexable', 'searchConsent']);
const APDM_INTENT_ID_PATTERN = /^apdm-v1-[a-f0-9]{64}$/u;
const ACTIVITYSTREAMS_NAMESPACE = 'https://www.w3.org/ns/activitystreams#';
const ADDRESSING_TERMS = new Set(['to', 'bto', 'cc', 'bcc', 'audience']);
const PUBLIC_ADDRESSES = new Set([`${ACTIVITYSTREAMS_NAMESPACE}Public`, 'as:Public', 'Public']);
// eslint-disable-next-line no-control-regex -- Deliberately match individual control or ignorable code points at this input boundary.
const UNSAFE_TOKEN_PATTERN = /[\s\u0000-\u001f\u007f]/u;

function isNonEmptyString(value) {
  return typeof value === 'string' && value.length > 0;
}

function isCleanString(value) {
  return isNonEmptyString(value) && !UNSAFE_TOKEN_PATTERN.test(value);
}

function hasOnlyKeys(value, allowed) {
  return Object.keys(value).every(key => allowed.has(key));
}

function assertDenseArray(value, label) {
  for (let index = 0; index < value.length; index += 1) {
    if (!Object.prototype.hasOwnProperty.call(value, index)) {
      throw new TypeError(`Cannot ${label} sparse array`);
    }
  }
}

function parseHttpUrl(value) {
  if (!isCleanString(value)) return null;
  try {
    const parsed = new URL(value);
    if (!['http:', 'https:'].includes(parsed.protocol)) return null;
    if (parsed.username || parsed.password) return null;
    return parsed;
  } catch {
    return null;
  }
}

function parseDeliveryEndpointUrl(value) {
  const parsed = parseHttpUrl(value);
  if (!parsed || value.includes('#')) return null;
  return normalizeDeliveryTargetDomain(parsed.hostname) ? parsed : null;
}

function normalizeDeliveryTargetDomain(value) {
  if (!isCleanString(value)) return null;
  const normalized = value.toLowerCase().replace(/\.+$/u, '');
  return normalized.length > 0 ? normalized : null;
}

function isHttpUrl(value) {
  return Boolean(parseHttpUrl(value));
}

function normalizeId(value) {
  if (typeof value === 'string') return value;
  if (value && typeof value === 'object' && !Array.isArray(value)) return value.id || value['@id'] || null;
  return null;
}

function normalizeAddresses(value) {
  const values = Array.isArray(value) ? value : [value];
  return values.map(normalizeId).filter(item => typeof item === 'string');
}

function resolveAddressingDefinition(definition, prefixes) {
  const raw = typeof definition === 'string'
    ? definition
    : definition && typeof definition === 'object' && !Array.isArray(definition)
      ? definition['@id']
      : null;
  if (typeof raw !== 'string') return null;
  if (raw.startsWith(ACTIVITYSTREAMS_NAMESPACE)) {
    const term = raw.slice(ACTIVITYSTREAMS_NAMESPACE.length);
    return ADDRESSING_TERMS.has(term) ? term : null;
  }
  const separator = raw.indexOf(':');
  if (separator > 0) {
    const prefix = raw.slice(0, separator);
    const suffix = raw.slice(separator + 1);
    if (prefixes.get(prefix) === ACTIVITYSTREAMS_NAMESPACE && ADDRESSING_TERMS.has(suffix)) return suffix;
  }
  return ADDRESSING_TERMS.has(raw) ? raw : null;
}

function buildContextState(context, inherited) {
  const prefixes = new Map(inherited?.prefixes || [['as', ACTIVITYSTREAMS_NAMESPACE]]);
  const aliases = new Map(inherited?.aliases || []);
  const entries = Array.isArray(context) ? context : context === undefined ? [] : [context];

  for (const entry of entries) {
    if (!entry || typeof entry !== 'object' || Array.isArray(entry)) continue;
    for (const [key, definition] of Object.entries(entry)) {
      const raw = typeof definition === 'string'
        ? definition
        : definition && typeof definition === 'object' && !Array.isArray(definition)
          ? definition['@id']
          : null;
      if (raw === ACTIVITYSTREAMS_NAMESPACE) prefixes.set(key, ACTIVITYSTREAMS_NAMESPACE);
    }
    for (const [key, definition] of Object.entries(entry)) {
      const term = resolveAddressingDefinition(definition, prefixes);
      if (term) aliases.set(key, term);
    }
  }
  return { prefixes, aliases };
}

function canonicalAddressingTerm(key, state) {
  if (ADDRESSING_TERMS.has(key)) return key;
  if (key.startsWith(ACTIVITYSTREAMS_NAMESPACE)) {
    const term = key.slice(ACTIVITYSTREAMS_NAMESPACE.length);
    return ADDRESSING_TERMS.has(term) ? term : null;
  }
  const separator = key.indexOf(':');
  if (separator > 0) {
    const prefix = key.slice(0, separator);
    const suffix = key.slice(separator + 1);
    if (state.prefixes.get(prefix) === ACTIVITYSTREAMS_NAMESPACE && ADDRESSING_TERMS.has(suffix)) return suffix;
  }
  return state.aliases.get(key) || null;
}

function addressingValues(activity, term) {
  if (!activity || typeof activity !== 'object' || Array.isArray(activity)) return [];
  const state = buildContextState(activity['@context']);
  const values = [];
  for (const [key, value] of Object.entries(activity)) {
    if (canonicalAddressingTerm(key, state) === term) values.push(...normalizeAddresses(value));
  }
  return values;
}

function isActorFollowersAddress(value, actorUri) {
  if (typeof value !== 'string' || typeof actorUri !== 'string') return false;
  try {
    const address = new URL(value);
    const actor = new URL(actorUri);
    if (actor.search || actor.hash || address.search || address.hash) return false;
    if (address.origin !== actor.origin) return false;
    const actorPath = actor.pathname.replace(/\/+$/u, '');
    const addressPath = address.pathname.replace(/\/+$/u, '');
    return addressPath === `${actorPath}/followers`;
  } catch {
    return false;
  }
}

function determineActivityVisibility(activity) {
  const to = addressingValues(activity, 'to');
  const cc = addressingValues(activity, 'cc');
  if (to.some(value => PUBLIC_ADDRESSES.has(value))) return 'public';
  if (cc.some(value => PUBLIC_ADDRESSES.has(value))) return 'unlisted';
  const actorUri = normalizeId(activity?.actor);
  if (actorUri && to.some(value => isActorFollowersAddress(value, actorUri))) return 'followers';
  return 'direct';
}

function hasSenderFollowersAudience(activity) {
  const actorUri = normalizeId(activity?.actor);
  return Boolean(actorUri && addressingValues(activity, 'audience').some(value => isActorFollowersAddress(value, actorUri)));
}

function getExplicitConcreteRecipientUris(activity) {
  const actorUri = normalizeId(activity?.actor);
  const addresses = [...ADDRESSING_TERMS].flatMap(term => addressingValues(activity, term));
  return [...new Set(addresses.filter(value => {
    if (PUBLIC_ADDRESSES.has(value)) return false;
    if (actorUri && isActorFollowersAddress(value, actorUri)) return false;
    return true;
  }))];
}

function containsBlindAudienceFields(value, seen = new WeakSet(), inheritedContext) {
  if (!value || typeof value !== 'object') return false;
  if (seen.has(value)) return false;
  seen.add(value);
  if (Array.isArray(value)) return value.some(item => containsBlindAudienceFields(item, seen, inheritedContext));
  const state = buildContextState(value['@context'], inheritedContext);
  if (Object.keys(value).some(key => {
    const term = canonicalAddressingTerm(key, state);
    return term === 'bto' || term === 'bcc';
  })) return true;
  return Object.values(value).some(item => containsBlindAudienceFields(item, seen, state));
}

function sanitizeDeliveryActivity(value, seen = new WeakSet(), inheritedContext) {
  if (value === null) return null;
  if (Array.isArray(value)) {
    assertDenseArray(value, 'sanitize');
    if (seen.has(value)) throw new TypeError('Cannot sanitize cyclic ActivityPub delivery payload');
    seen.add(value);
    const output = value.map(item => sanitizeDeliveryActivity(item, seen, inheritedContext));
    seen.delete(value);
    return output;
  }

  switch (typeof value) {
    case 'string':
    case 'boolean':
      return value;
    case 'number':
      if (!Number.isFinite(value)) throw new TypeError('Cannot sanitize non-finite ActivityPub delivery value');
      return value;
    case 'object': {
      const prototype = Object.getPrototypeOf(value);
      if (prototype !== Object.prototype && prototype !== null) {
        throw new TypeError('Cannot sanitize non-JSON ActivityPub delivery object');
      }
      if (seen.has(value)) throw new TypeError('Cannot sanitize cyclic ActivityPub delivery payload');
      seen.add(value);
      const state = buildContextState(value['@context'], inheritedContext);
      const output = {};
      for (const [key, item] of Object.entries(value)) {
        const term = canonicalAddressingTerm(key, state);
        if (term === 'bto' || term === 'bcc') continue;
        // SemApps reattaches optional `capability` after persistence even when it
        // was absent, producing an own property whose value is undefined. Its
        // native remote transport serializes with JSON.stringify(), which omits
        // undefined object properties. Preserve that incumbent wire semantic
        // without weakening arrays or other unsupported JSON values below.
        if (item === undefined) continue;
        output[key] = sanitizeDeliveryActivity(item, seen, state);
      }
      seen.delete(value);
      return output;
    }
    default:
      throw new TypeError(`Cannot sanitize unsupported ${typeof value} ActivityPub delivery value`);
  }
}

function validateLocalRecipient(target) {
  return Boolean(
    target &&
      typeof target === 'object' &&
      !Array.isArray(target) &&
      hasOnlyKeys(target, LOCAL_TARGET_KEYS) &&
      isHttpUrl(target.actorUri) &&
      isCleanString(target.dataset) &&
      parseDeliveryEndpointUrl(target.inboxUri)
  );
}

function validateRemoteRecipient(target) {
  if (!(
    target &&
    typeof target === 'object' &&
    !Array.isArray(target) &&
    hasOnlyKeys(target, REMOTE_TARGET_KEYS) &&
    isHttpUrl(target.actorUri) &&
    parseDeliveryEndpointUrl(target.inboxUrl) &&
    (target.sharedInboxUrl === undefined || parseDeliveryEndpointUrl(target.sharedInboxUrl)) &&
    isCleanString(target.targetDomain)
  )) return false;

  const deliveryUrl = target.sharedInboxUrl || target.inboxUrl;
  const parsed = parseDeliveryEndpointUrl(deliveryUrl);
  const expectedDomain = parsed && normalizeDeliveryTargetDomain(parsed.hostname);
  return Boolean(expectedDomain && target.targetDomain === expectedDomain);
}

function canonicalize(value) {
  if (value === null) return 'null';
  if (Array.isArray(value)) {
    assertDenseArray(value, 'canonicalize');
    return `[${value.map(canonicalize).join(',')}]`;
  }

  switch (typeof value) {
    case 'string':
    case 'boolean':
      return JSON.stringify(value);
    case 'number':
      if (!Number.isFinite(value)) throw new TypeError('Cannot canonicalize non-finite number');
      return JSON.stringify(value);
    case 'object': {
      const prototype = Object.getPrototypeOf(value);
      if (prototype !== Object.prototype && prototype !== null) {
        throw new TypeError('Cannot canonicalize non-JSON object');
      }
      return `{${Object.keys(value)
        .sort()
        .map(key => `${JSON.stringify(key)}:${canonicalize(value[key])}`)
        .join(',')}}`;
    }
    default:
      throw new TypeError(`Cannot canonicalize unsupported ${typeof value} value`);
  }
}

function computeDeliveryPlanIntentId({ activityId, actorUri, localRecipientUris = [], remoteRecipientUris = [] }) {
  const material = canonicalize({
    schema: DELIVERY_PLAN_SCHEMA,
    activityId,
    actorUri,
    localRecipientUris: [...new Set(localRecipientUris)].sort(),
    remoteRecipientUris: [...new Set(remoteRecipientUris)].sort()
  });
  return `apdm-v1-${crypto.createHash('sha256').update(material).digest('hex')}`;
}

function hasDuplicate(values) {
  return new Set(values).size !== values.length;
}

function validateSemanticInvariants(plan) {
  const embeddedActivityId = normalizeId(plan.activity.id || plan.activity['@id']);
  const embeddedActorUri = normalizeId(plan.activity.actor);
  if (embeddedActivityId !== plan.activityId || embeddedActorUri !== plan.actorUri) return false;
  if (containsBlindAudienceFields(plan.activity)) return false;
  if (hasSenderFollowersAudience(plan.activity)) return false;

  const expectedVisibility = determineActivityVisibility(plan.activity);
  if (plan.meta.visibility !== expectedVisibility) return false;
  const expectedPublic = expectedVisibility === 'public' || expectedVisibility === 'unlisted';
  if (plan.meta.isPublicActivity !== expectedPublic) return false;
  if (plan.meta.isPublicIndexable === true && !expectedPublic) return false;

  const localUris = plan.localRecipients.map(target => target.actorUri);
  const remoteUris = plan.remoteRecipients.map(target => target.actorUri);
  if (hasDuplicate(localUris) || hasDuplicate(remoteUris)) return false;
  const localSet = new Set(localUris);
  if (remoteUris.some(uri => localSet.has(uri))) return false;

  const plannedRecipients = new Set([...localUris, ...remoteUris]);
  const explicitRecipients = getExplicitConcreteRecipientUris(plan.activity);
  if (explicitRecipients.some(uri => !plannedRecipients.has(uri))) return false;

  const expectedIntentId = computeDeliveryPlanIntentId({
    activityId: plan.activityId,
    actorUri: plan.actorUri,
    localRecipientUris: localUris,
    remoteRecipientUris: remoteUris
  });
  return plan.intentId === expectedIntentId;
}

function validateDeliveryPlanV1(plan) {
  if (!plan || typeof plan !== 'object' || Array.isArray(plan)) return false;
  if (!hasOnlyKeys(plan, PLAN_KEYS)) return false;
  if (plan.schema !== DELIVERY_PLAN_SCHEMA) return false;
  if (!APDM_INTENT_ID_PATTERN.test(plan.intentId || '')) return false;
  if (!isHttpUrl(plan.activityId) || !isHttpUrl(plan.actorUri)) return false;
  if (!plan.activity || typeof plan.activity !== 'object' || Array.isArray(plan.activity)) return false;
  if (!Array.isArray(plan.localRecipients) || !plan.localRecipients.every(validateLocalRecipient)) return false;
  if (!Array.isArray(plan.remoteRecipients) || !plan.remoteRecipients.every(validateRemoteRecipient)) return false;
  if (!plan.meta || typeof plan.meta !== 'object' || Array.isArray(plan.meta)) return false;
  if (!hasOnlyKeys(plan.meta, META_KEYS)) return false;
  if (!VISIBILITIES.has(plan.meta.visibility)) return false;
  if (typeof plan.meta.isPublicActivity !== 'boolean') return false;
  if (plan.meta.isPublicIndexable !== undefined && typeof plan.meta.isPublicIndexable !== 'boolean') return false;
  if (
    plan.meta.searchConsent !== undefined &&
    plan.meta.searchConsent !== null &&
    (typeof plan.meta.searchConsent !== 'object' || Array.isArray(plan.meta.searchConsent))
  ) {
    return false;
  }
  return validateSemanticInvariants(plan);
}

function deliveryPlanFingerprint(value) {
  return crypto.createHash('sha256').update(canonicalize(value)).digest('hex');
}

module.exports = {
  APDM_INTENT_ID_PATTERN,
  DELIVERY_PLAN_SCHEMA,
  DELIVERY_PLAN_FIXTURE_SHA256,
  DELIVERY_PLAN_JSON_SCHEMA_SHA256,
  addressingValues,
  canonicalize,
  computeDeliveryPlanIntentId,
  containsBlindAudienceFields,
  deliveryPlanFingerprint,
  determineActivityVisibility,
  getExplicitConcreteRecipientUris,
  hasSenderFollowersAudience,
  isActorFollowersAddress,
  normalizeDeliveryTargetDomain,
  parseDeliveryEndpointUrl,
  sanitizeDeliveryActivity,
  validateDeliveryPlanV1
};
