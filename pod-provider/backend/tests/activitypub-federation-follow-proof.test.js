'use strict';

const {
  boundedNonNegativeInteger,
  createProofSummary,
  extractExternalDeliveryTarget
} = require('../scripts/activitypub-federation-follow-proof');
const { computeDeliveryPlanIntentId } = require('../utils/activitypub-delivery-plan');

const ACTOR_URI = 'https://activitypods.example/alice';
const ACTIVITY_ID = 'https://activitypods.example/alice/data/follow-1';
const REMOTE_ACTOR_URI = 'https://mastodon.example/users/bob';

function createExternalHandoff() {
  const activity = {
    id: ACTIVITY_ID,
    type: 'Follow',
    actor: ACTOR_URI,
    object: REMOTE_ACTOR_URI,
    to: REMOTE_ACTOR_URI
  };
  const deliveryPlan = {
    schema: 'ap.delivery-plan.v1',
    intentId: computeDeliveryPlanIntentId({
      activityId: ACTIVITY_ID,
      actorUri: ACTOR_URI,
      remoteRecipientUris: [REMOTE_ACTOR_URI]
    }),
    activityId: ACTIVITY_ID,
    actorUri: ACTOR_URI,
    activity,
    localRecipients: [],
    remoteRecipients: [{
      actorUri: REMOTE_ACTOR_URI,
      inboxUrl: 'https://mastodon.example/users/bob/inbox',
      sharedInboxUrl: 'https://mastodon.example/inbox',
      targetDomain: 'mastodon.example'
    }],
    meta: {
      visibility: 'direct',
      isPublicActivity: false
    }
  };
  return {
    activity,
    deliveryPlan,
    remoteRecipients: [REMOTE_ACTOR_URI]
  };
}

describe('ActivityPub real federation proof payload', () => {
  test('keeps the normal proof unpadded by default', () => {
    expect(boundedNonNegativeInteger(undefined, 0, 64 * 1024, 'proof summary bytes')).toBe(0);
    expect(createProofSummary(0)).toBeUndefined();
  });

  test('creates an exact-size ASCII summary suitable for a real compressible Activity', () => {
    const summary = createProofSummary(8192);
    expect(Buffer.byteLength(summary, 'utf8')).toBe(8192);
    expect(summary.startsWith('activitypods-sidecar-compression-proof|')).toBe(true);
  });

  test('rejects negative, fractional, non-numeric, and oversized proof sizes', () => {
    const parse = value => boundedNonNegativeInteger(value, 0, 64 * 1024, 'proof summary bytes');
    expect(() => parse(-1)).toThrow(/between 0 and 65536/u);
    expect(() => parse(1.5)).toThrow(/between 0 and 65536/u);
    expect(() => parse('not-a-number')).toThrow(/between 0 and 65536/u);
    expect(() => parse(64 * 1024 + 1)).toThrow(/between 0 and 65536/u);
  });

  test('accepts the maximum bounded proof size without exceeding it', () => {
    const bytes = boundedNonNegativeInteger(64 * 1024, 0, 64 * 1024, 'proof summary bytes');
    const summary = createProofSummary(bytes);
    expect(Buffer.byteLength(summary, 'utf8')).toBe(64 * 1024);
  });

  test('binds external proof evidence to the authoritative shared inbox target', () => {
    expect(extractExternalDeliveryTarget({
      handoff: createExternalHandoff(),
      postResult: { id: ACTIVITY_ID },
      senderWebId: ACTOR_URI,
      remoteActorUri: REMOTE_ACTOR_URI
    })).toEqual({
      actorUri: REMOTE_ACTOR_URI,
      inboxUrl: 'https://mastodon.example/users/bob/inbox',
      sharedInboxUrl: 'https://mastodon.example/inbox',
      targetDomain: 'mastodon.example',
      deliveryUrl: 'https://mastodon.example/inbox'
    });
  });

  test.each([
    ['persisted activity drift', handoff => { handoff.deliveryPlan.activityId = 'https://activitypods.example/alice/data/other'; }],
    ['sender authority drift', handoff => { handoff.deliveryPlan.actorUri = 'https://activitypods.example/mallory'; }],
    ['remote recipient drift', handoff => { handoff.remoteRecipients[0] = 'https://other.example/users/eve'; }],
    ['extra remote recipient', handoff => { handoff.deliveryPlan.remoteRecipients.push(handoff.deliveryPlan.remoteRecipients[0]); }],
    ['local-recipient contamination', handoff => { handoff.deliveryPlan.localRecipients.push({ actorUri: 'https://activitypods.example/carol', dataset: 'carol', inboxUri: 'https://activitypods.example/carol/inbox' }); }]
  ])('rejects %s', (_label, mutate) => {
    const handoff = createExternalHandoff();
    mutate(handoff);
    expect(() => extractExternalDeliveryTarget({
      handoff,
      postResult: { id: ACTIVITY_ID },
      senderWebId: ACTOR_URI,
      remoteActorUri: REMOTE_ACTOR_URI
    })).toThrow();
  });
});
