'use strict';

const {
  assertPublicActorReady,
  fetchPublicActorWithCurl,
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
  test('requires an exact bounded ActivityPub actor through the public authority', async () => {
    const response = new Response(JSON.stringify({ id: ACTOR_URI, type: 'Person' }), {
      status: 200,
      headers: { 'content-type': 'application/activity+json' }
    });
    const fetchImpl = jest.fn(async () => response);

    await expect(assertPublicActorReady(ACTOR_URI, { fetchImpl, attempts: 1 })).resolves.toBeUndefined();
    expect(fetchImpl).toHaveBeenCalledWith(ACTOR_URI, expect.objectContaining({
      method: 'GET',
      redirect: 'error',
      headers: { accept: 'application/activity+json' }
    }));
  });

  test('fails closed when the public document claims a different actor', async () => {
    const fetchImpl = async () => new Response(JSON.stringify({ id: 'https://activitypods.example/mallory' }), {
      status: 200,
      headers: { 'content-type': 'application/activity+json' }
    });
    await expect(assertPublicActorReady(ACTOR_URI, { fetchImpl, attempts: 1 })).rejects.toThrow(
      /identifier did not match/u
    );
  });

  test('curl readiness uses the exact HTTPS URL without redirects and validates the actor', async () => {
    const execFileImpl = jest.fn(async (_command, args) => {
      const writeOut = args[args.indexOf('--write-out') + 1];
      const marker = writeOut.match(/\n([^\t]+)\t/u)[1];
      return {
        stdout: Buffer.from(`${JSON.stringify({ id: ACTOR_URI, type: 'Person' })}\n${marker}\t200\tapplication/activity+json\t${ACTOR_URI}`)
      };
    });

    await expect(assertPublicActorReady(ACTOR_URI, {
      transport: 'curl', execFileImpl, attempts: 1
    })).resolves.toBeUndefined();
    expect(execFileImpl).toHaveBeenCalledWith('curl', expect.arrayContaining([
      '--proto', '=https', '--max-redirs', '0', ACTOR_URI
    ]), expect.objectContaining({ encoding: 'buffer' }));
  });

  test('curl readiness rejects effective URL drift even when the document claims the expected actor', async () => {
    const execFileImpl = async (_command, args) => {
      const writeOut = args[args.indexOf('--write-out') + 1];
      const marker = writeOut.match(/\n([^\t]+)\t/u)[1];
      return {
        stdout: Buffer.from(`${JSON.stringify({ id: ACTOR_URI })}\n${marker}\t200\tapplication/activity+json\thttps://other.example/alice`)
      };
    };
    await expect(assertPublicActorReady(ACTOR_URI, {
      transport: 'curl', execFileImpl, attempts: 1
    })).rejects.toThrow(/changed authority or URL/u);
  });

  test('curl parser rejects malformed status evidence', async () => {
    await expect(fetchPublicActorWithCurl(ACTOR_URI, {
      execFileImpl: async () => ({ stdout: Buffer.from('{}') })
    })).rejects.toThrow(/missing its status marker/u);
  });

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
