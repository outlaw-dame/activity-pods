'use strict';

const {
  buildDeliveryPlanV1,
  createDeliveryIntentId,
  determineVisibility,
  isFollowersCollectionUri,
  mapWithConcurrency
} = require('../utils/activitypub-delivery-planner');
const { validateDeliveryPlanV1 } = require('../utils/activitypub-delivery-plan');

const ACTOR = 'https://pods.example/alice';
const ACTIVITY_ID = 'https://pods.example/alice/activities/phase3';

function createActivity(overrides = {}) {
  return {
    id: ACTIVITY_ID,
    type: 'Create',
    actor: ACTOR,
    to: ['https://www.w3.org/ns/activitystreams#Public'],
    cc: [`${ACTOR}/followers`],
    object: {
      id: 'https://pods.example/alice/objects/phase3',
      type: 'Note',
      attributedTo: ACTOR,
      content: 'phase 3'
    },
    ...overrides
  };
}

function createRemoteOnlyContext() {
  return {
    async call(action, params) {
      if (action === 'activitypub.actor.get') {
        const url = new URL(params.actorUri);
        return {
          id: params.actorUri,
          inbox: `${url.origin}${url.pathname}/inbox`,
          endpoints: { sharedInbox: `${url.origin}/inbox` }
        };
      }
      throw new Error(`Unexpected call ${action}`);
    }
  };
}

describe('APDM Phase 3 authoritative delivery planner', () => {
  test('builds concrete local and remote targets from the already-expanded SemApps partition', async () => {
    const calls = [];
    const ctx = {
      async call(action, params, options) {
        calls.push({ action, params, options });
        if (action === 'auth.account.findByWebId') return { username: 'bob' };
        if (action === 'triplestore.query') {
          return [{ inboxUri: { value: 'https://pods.example/bob/inbox' } }];
        }
        if (action === 'activitypub.actor.get') {
          return {
            id: params.actorUri,
            inbox: 'https://remote.example/users/carol/inbox',
            endpoints: { sharedInbox: 'https://remote.example/inbox' }
          };
        }
        throw new Error(`Unexpected call ${action}`);
      }
    };

    const plan = await buildDeliveryPlanV1(ctx, {
      activity: createActivity(),
      localRecipientUris: ['https://pods.example/bob'],
      remoteRecipientUris: ['https://remote.example/users/carol']
    });

    expect(validateDeliveryPlanV1(plan)).toBe(true);
    expect(plan.localRecipients).toEqual([
      {
        actorUri: 'https://pods.example/bob',
        dataset: 'bob',
        inboxUri: 'https://pods.example/bob/inbox'
      }
    ]);
    expect(plan.remoteRecipients).toEqual([
      {
        actorUri: 'https://remote.example/users/carol',
        inboxUrl: 'https://remote.example/users/carol/inbox',
        sharedInboxUrl: 'https://remote.example/inbox',
        targetDomain: 'remote.example'
      }
    ]);
    expect(plan.remoteRecipients.some(target => target.actorUri.endsWith('/followers'))).toBe(false);
    expect(plan.meta).toEqual({ visibility: 'public', isPublicActivity: true });
    const localInboxQuery = calls.find(call => call.action === 'triplestore.query');
    expect(localInboxQuery).toBeDefined();
    expect(localInboxQuery.params).toEqual(
      expect.objectContaining({ dataset: 'bob', webId: 'system' })
    );
    expect(localInboxQuery.params.query).toContain('<https://pods.example/bob> ldp:inbox ?inboxUri');
    expect(localInboxQuery.params.query).toMatch(/LIMIT 2/u);
    expect(calls.some(call => call.action === 'activitypub.actor.getCollectionUri')).toBe(false);
  });

  test('followers-only addressing produces concrete remote follower targets, never the collection URI', async () => {
    const remoteFollower = 'https://remote.example/users/follower';
    const activity = createActivity({
      id: 'https://pods.example/alice/activities/followers-only',
      to: [`${ACTOR}/followers`],
      cc: []
    });

    const plan = await buildDeliveryPlanV1(createRemoteOnlyContext(), {
      activity,
      remoteRecipientUris: [remoteFollower]
    });

    expect(plan.meta).toEqual({ visibility: 'followers', isPublicActivity: false });
    expect(plan.remoteRecipients).toHaveLength(1);
    expect(plan.remoteRecipients[0]).toEqual(
      expect.objectContaining({
        actorUri: remoteFollower,
        inboxUrl: `${remoteFollower}/inbox`,
        sharedInboxUrl: 'https://remote.example/inbox',
        targetDomain: 'remote.example'
      })
    );
    expect(plan.remoteRecipients.some(target => isFollowersCollectionUri(target.actorUri))).toBe(false);
  });

  test('refuses an unresolved followers collection before attempting actor resolution', async () => {
    const ctx = { call: jest.fn() };

    await expect(
      buildDeliveryPlanV1(ctx, {
        activity: createActivity({ to: [`${ACTOR}/followers`], cc: [] }),
        remoteRecipientUris: [`${ACTOR}/followers`]
      })
    ).rejects.toThrow(/unresolved remote followers collection/u);

    expect(ctx.call).not.toHaveBeenCalled();
  });

  test('direct mention addressing remains a concrete direct plan', async () => {
    const recipient = 'https://remote.example/users/direct';
    const plan = await buildDeliveryPlanV1(createRemoteOnlyContext(), {
      activity: createActivity({
        id: 'https://pods.example/alice/activities/direct',
        to: [recipient],
        cc: []
      }),
      remoteRecipientUris: [recipient]
    });

    expect(plan.meta.visibility).toBe('direct');
    expect(plan.remoteRecipients.map(target => target.actorUri)).toEqual([recipient]);
  });

  test('reply addressing preserves the concrete addressed actor', async () => {
    const recipient = 'https://remote.example/users/replied-to';
    const activity = createActivity({
      id: 'https://pods.example/alice/activities/reply',
      to: [recipient],
      cc: [],
      object: {
        id: 'https://pods.example/alice/objects/reply',
        type: 'Note',
        attributedTo: ACTOR,
        inReplyTo: 'https://remote.example/objects/original',
        content: 'reply'
      }
    });

    const plan = await buildDeliveryPlanV1(createRemoteOnlyContext(), {
      activity,
      remoteRecipientUris: [recipient]
    });

    expect(plan.meta.visibility).toBe('direct');
    expect(plan.remoteRecipients[0].actorUri).toBe(recipient);
    expect(plan.activity.object.inReplyTo).toBe('https://remote.example/objects/original');
  });

  test('Follow addressing resolves the Follow object actor as a concrete remote target', async () => {
    const followee = 'https://remote.example/users/followee';
    const activity = {
      id: 'https://pods.example/alice/activities/follow',
      type: 'Follow',
      actor: ACTOR,
      object: followee,
      to: [followee],
      cc: []
    };

    const plan = await buildDeliveryPlanV1(createRemoteOnlyContext(), {
      activity,
      remoteRecipientUris: [followee]
    });

    expect(validateDeliveryPlanV1(plan)).toBe(true);
    expect(plan.meta.visibility).toBe('direct');
    expect(plan.remoteRecipients[0].actorUri).toBe(followee);
  });

  test('deduplicates expanded recipient URIs without collapsing distinct actors that share an inbox', async () => {
    const ctx = createRemoteOnlyContext();
    const plan = await buildDeliveryPlanV1(ctx, {
      activity: createActivity(),
      remoteRecipientUris: [
        'https://remote.example/users/a',
        'https://remote.example/users/a',
        'https://remote.example/users/b'
      ]
    });

    expect(plan.remoteRecipients.map(target => target.actorUri)).toEqual([
      'https://remote.example/users/a',
      'https://remote.example/users/b'
    ]);
    expect(plan.remoteRecipients.map(target => target.sharedInboxUrl)).toEqual([
      'https://remote.example/inbox',
      'https://remote.example/inbox'
    ]);
  });

  test('intent IDs are deterministic and independent of recipient ordering or duplicates', () => {
    const first = createDeliveryIntentId({
      activityId: ACTIVITY_ID,
      actorUri: ACTOR,
      localRecipientUris: ['https://pods.example/b', 'https://pods.example/a'],
      remoteRecipientUris: ['https://remote.example/z', 'https://remote.example/y', 'https://remote.example/z']
    });
    const second = createDeliveryIntentId({
      activityId: ACTIVITY_ID,
      actorUri: ACTOR,
      localRecipientUris: ['https://pods.example/a', 'https://pods.example/b', 'https://pods.example/a'],
      remoteRecipientUris: ['https://remote.example/y', 'https://remote.example/z']
    });

    expect(first).toBe(second);
    expect(first).toMatch(/^apdm-v1-[a-f0-9]{64}$/u);
  });

  test('fails closed when a remote actor has no concrete inbox', async () => {
    const ctx = {
      async call(action) {
        if (action === 'activitypub.actor.get') return { id: 'https://remote.example/users/missing' };
        throw new Error(`Unexpected call ${action}`);
      }
    };

    await expect(
      buildDeliveryPlanV1(ctx, {
        activity: createActivity(),
        remoteRecipientUris: ['https://remote.example/users/missing']
      })
    ).rejects.toThrow(/Unable to resolve remote inbox/u);
  });

  test('fails closed when a local actor has no dataset metadata', async () => {
    const ctx = {
      async call(action) {
        if (action === 'auth.account.findByWebId') return { username: '' };
        throw new Error(`Unexpected call ${action}`);
      }
    };

    await expect(
      buildDeliveryPlanV1(ctx, {
        activity: createActivity(),
        localRecipientUris: ['https://pods.example/bob']
      })
    ).rejects.toThrow(/Unable to resolve local dataset/u);
  });

  test('enforces the configured resolver concurrency bound', async () => {
    let active = 0;
    let maxActive = 0;
    const values = Array.from({ length: 12 }, (_, index) => index);

    const result = await mapWithConcurrency(values, 3, async value => {
      active += 1;
      maxActive = Math.max(maxActive, active);
      await new Promise(resolve => setTimeout(resolve, 5));
      active -= 1;
      return value * 2;
    });

    expect(result).toEqual(values.map(value => value * 2));
    expect(maxActive).toBeLessThanOrEqual(3);
    expect(maxActive).toBe(3);
  });

  test('visibility classification preserves public, unlisted, followers, and direct semantics', () => {
    expect(determineVisibility(createActivity())).toBe('public');
    expect(
      determineVisibility(createActivity({
        to: ['https://remote.example/users/a'],
        cc: ['https://www.w3.org/ns/activitystreams#Public']
      }))
    ).toBe('unlisted');
    expect(determineVisibility(createActivity({ to: [`${ACTOR}/followers`], cc: [] }))).toBe('followers');
    expect(determineVisibility(createActivity({ to: ['https://remote.example/users/a'], cc: [] }))).toBe('direct');
  });
});
