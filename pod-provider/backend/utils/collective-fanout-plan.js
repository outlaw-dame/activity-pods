'use strict';

/**
 * G2 internal planning kernel. Consumes an already authorized, complete
 * membership/recipient snapshot; it neither grants authority nor resolves
 * actors, reads Pods, writes inboxes or executes federation.
 *
 * Critically, no ctx.call/fetch/redis/queue operations occur per recipient.
 * The caller is responsible for providing its authoritative membership
 * revision, ACL policy and current local/remote target resolution.
 *
 * NOT an ActivityPub Delivery Plan v1 and never a second delivery authority.
 */
const crypto = require('node:crypto');
const {
  parseDeliveryEndpointUrl,
  normalizeDeliveryTargetDomain
} = require('./activitypub-delivery-plan');

const MAX_RECIPIENTS = 1000;
const MAX_LOCAL_BATCH = 32;
// Remote sharedInbox is one delivery destination, NEVER one POST per N actors.
// A single bounded page (<=1000) may reference one destination. The actual
// Fedify sidecar is responsible for the eventual one-destination delivery.
const MAX_REMOTE_BATCH = MAX_RECIPIENTS;
const DATASET = /^[a-zA-Z0-9][a-zA-Z0-9_-]{0,127}$/u;
const INTENT = /^[a-zA-Z0-9_-]{16,128}$/u;
const HEX = /^[0-9a-f]{64}$/u;

function invalid(message) {
  throw new TypeError('Invalid Group fan-out input: ' + message);
}
function exactHttps(value) {
  if (typeof value !== 'string' || value.length > 2048 ||
      /[\u0000-\u0020\u007f\\]/u.test(value)) return null;
  try {
    const u = new URL(value);
    return u.protocol === 'https:' && u.href === value &&
      !u.username && !u.password && !u.hash && !u.search ? u : null;
  } catch { return null; }
}
function cleanLocal(row) {
  if (!row || typeof row !== 'object' || Array.isArray(row) ||
      !exactHttps(row.actorUri) || !exactHttps(row.inboxUri) ||
      !DATASET.test(row.dataset || '') ||
      Object.keys(row).some(k => !['actorUri', 'inboxUri', 'dataset'].includes(k))) {
    invalid('local recipient requires exact actorUri, inboxUri and dataset');
  }
  return Object.freeze({ actorUri: row.actorUri, dataset: row.dataset, inboxUri: row.inboxUri });
}
function cleanRemote(row) {
  if (!row || typeof row !== 'object' || Array.isArray(row) ||
      !exactHttps(row.actorUri) ||
      Object.keys(row).some(k => !['actorUri', 'inboxUrl', 'sharedInboxUrl', 'targetDomain'].includes(k))) {
    invalid('remote recipient requires an actor and resolved inbox');
  }
  const inbox = parseDeliveryEndpointUrl(row.inboxUrl);
  const shared = row.sharedInboxUrl == null || row.sharedInboxUrl === ''
    ? null : parseDeliveryEndpointUrl(row.sharedInboxUrl);
  const domain = normalizeDeliveryTargetDomain(row.targetDomain);
  if (!inbox || inbox.protocol !== 'https:' || !domain || inbox.hostname !== domain ||
      (shared && (shared.protocol !== 'https:' || shared.hostname !== domain))) {
    invalid('remote delivery endpoint/domain mismatch');
  }
  return Object.freeze({
    actorUri: row.actorUri, inboxUrl: inbox.href,
    sharedInboxUrl: shared ? shared.href : null,
    targetDomain: domain
  });
}
function groupBatches(rows, key, capacity, make) {
  const buckets = new Map();
  for (const row of rows) {
    const id = key(row);
    let bucket = buckets.get(id);
    if (!bucket) {
      bucket = [];
      buckets.set(id, bucket);
    }
    bucket.push(row);
  }
  const result = [];
  for (const id of [...buckets.keys()].sort()) {
    const items = buckets.get(id).sort((a, b) => a.actorUri.localeCompare(b.actorUri));
    for (let start = 0; start < items.length; start += capacity) {
      result.push(make(id, items.slice(start, start + capacity)));
    }
  }
  return result;
}
function normalizedRecipients(localRecipients, remoteRecipients) {
  if (!Array.isArray(localRecipients) || !Array.isArray(remoteRecipients) ||
      localRecipients.length + remoteRecipients.length > MAX_RECIPIENTS) {
    invalid('recipient snapshot must be an array with at most 1000 entries');
  }
  const seen = new Set();
  const local = [], remote = [];
  for (const [rows, map, out] of [
    [localRecipients, cleanLocal, local],
    [remoteRecipients, cleanRemote, remote]
  ]) {
    for (let index = 0; index < rows.length; index += 1) {
      if (!Object.hasOwn(rows, index)) invalid('sparse recipient array');
      const item = map(rows[index]);
      if (seen.has(item.actorUri)) invalid('duplicate or conflicting recipient identity');
      seen.add(item.actorUri);
      out.push(item);
    }
  }
  return { local, remote };
}

/**
 * A caller MUST NOT interpret this function as verifying Group membership.
 * Membership enumeration, admission, ACLs, actor identity, and privacy
 * decisions must already be proven by the Group authority before calling it.
 * Output is internal only; never return recipient enumerations through an API.
 */
function planGroupFanout({
  intentId, groupActorUri, membershipRevision, visibility,
  localRecipients, remoteRecipients
}) {
  if (!INTENT.test(intentId || '') || !exactHttps(groupActorUri) ||
      !Number.isSafeInteger(membershipRevision) || membershipRevision < 1 ||
      !['public', 'unlisted', 'members'].includes(visibility)) {
    invalid('canonical intent, Group actor, membership revision and visibility required');
  }
  const { local, remote } = normalizedRecipients(localRecipients, remoteRecipients);
  // Unlisted is intentionally not merged into an instance-wide sharedInbox:
  // sharing delivery endpoints is an information-disclosure policy decision.
  // Members-only delivery ALWAYS uses the named actor's inbox.
  const sharePublic = visibility === 'public';
  const locals = groupBatches(local, row => row.dataset, MAX_LOCAL_BATCH,
    (dataset, rows) => Object.freeze({
      dataset, recipients: Object.freeze(rows)
    }));
  const remotes = groupBatches(remote,
    row => sharePublic && row.sharedInboxUrl
      ? 'shared:' + row.sharedInboxUrl
      : 'direct:' + row.actorUri,
    MAX_REMOTE_BATCH,
    (key, rows) => Object.freeze({
      destination: key.startsWith('shared:')
        ? key.slice('shared:'.length) : rows[0].inboxUrl,
      mode: key.startsWith('shared:') ? 'sharedInbox' : 'actorInbox',
      recipientActors: Object.freeze(rows.map(row => row.actorUri)),
      targetDomain: rows[0].targetDomain
    }));
  // Deterministic fixed-size digest: not a bearer credential or identity.
  // Includes target routing and revision so a replan after membership change
  // cannot accidentally be mistaken for the previous intent.
  const fingerprint = crypto.createHash('sha256')
    .update(JSON.stringify([intentId, groupActorUri, membershipRevision, visibility,
      locals, remotes])).digest('hex');
  if (!HEX.test(fingerprint)) invalid('invalid fingerprint');
  return Object.freeze({
    version: 'paper.groups.fanout-plan.v1',
    intentId, groupActorUri, membershipRevision, visibility, fingerprint,
    recipientCount: local.length + remote.length,
    localRecipientCount: local.length,
    remoteRecipientCount: remote.length,
    localBatches: Object.freeze(locals),
    remoteBatches: Object.freeze(remotes)
  });
}
module.exports = Object.freeze({
  planGroupFanout,
  MAX_RECIPIENTS, MAX_LOCAL_BATCH, MAX_REMOTE_BATCH
});
