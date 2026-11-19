'use strict';

const {
  createActivityPubServiceWithDeliveryStrategy
} = require('../lib/activitypub-service-with-delivery-strategy');

function namedService(name, extra = {}) {
  return { name, ...extra };
}

function fakeInternals() {
  return {
    ActorService: namedService('activitypub.actor'),
    ActivityService: namedService('activitypub.activity'),
    ApiService: namedService('activitypub.api'),
    CollectionService: namedService('activitypub.collection'),
    FollowService: namedService('activitypub.follow'),
    InboxService: namedService('activitypub.inbox'),
    LikeService: namedService('activitypub.like'),
    ObjectService: namedService('activitypub.object'),
    OutboxService: namedService('activitypub.outbox', {
      actions: { async post() {} }
    }),
    CollectionsRegistryService: namedService('activitypub.collections-registry'),
    ReplyService: namedService('activitypub.reply'),
    ShareService: namedService('activitypub.share'),
    SideEffectsService: namedService('activitypub.side-effects'),
    FakeQueueMixin: {}
  };
}

function primaryMixinName(schema) {
  return Array.isArray(schema.mixins)
    ? schema.mixins.map(mixin => mixin?.name).find(Boolean)
    : undefined;
}

function podSubservices() {
  const serviceSchema = createActivityPubServiceWithDeliveryStrategy({
    remoteDeliveryMode: 'native',
    allowExternalDeliveryPreview: false,
    settings: {
      baseUri: 'https://pods.example',
      podProvider: true,
      queueServiceUrl: null
    },
    internals: fakeInternals(),
    buildDeliveryPlan: jest.fn(),
    enqueueHandoff: jest.fn()
  });

  const registered = [];
  serviceSchema.created.call({
    settings: serviceSchema.settings,
    broker: {
      createService(schema) {
        registered.push(schema);
      }
    }
  });
  return registered;
}

describe('APDM Phase 2 SemApps 1.1.4 service-registration parity', () => {
  test('registers the complete upstream ActivityPub subservice set exactly once', () => {
    const registered = podSubservices();
    const names = registered.map(primaryMixinName).filter(Boolean);
    expect(names).toEqual([
      'activitypub.side-effects',
      'activitypub.collection',
      'activitypub.collections-registry',
      'activitypub.actor',
      'activitypub.api',
      'activitypub.object',
      'activitypub.activity',
      'activitypub.follow',
      'activitypub.inbox',
      'activitypub.like',
      'activitypub.share',
      'activitypub.reply',
      'activitypub.outbox'
    ]);
    expect(new Set(names).size).toBe(names.length);
  });
});

test('registration binds actor bootstrap to the native account owner', async () => {
  const actor = podSubservices().find(schema => primaryMixinName(schema) === 'activitypub.actor').mixins[0];
  const webId = 'https://pods.example/alice';
  const ctx = { params: { webId, accountData: {username:'other'} }, meta: { dataset: 'other' } };
  const appendActorData = jest.fn();
  const call = jest.fn().mockResolvedValue({ webId, username: 'alice' });
  const deliver = () => actor.events['auth.registered'].call({ broker: { call }, actions: { appendActorData } }, ctx);
  await deliver();
  expect(call).toHaveBeenCalledWith('auth.account.findByWebId', { webId }, { meta: {}, timeout: 5000, retries: 0 });
  expect(appendActorData).toHaveBeenCalledWith({ actorUri: webId },
    { parentCtx: ctx, meta: { dataset: 'alice', webId: null } });
  for (const account of [null, { webId, username: 'other' }, { webId: 'https://elsewhere.test/alice', username: 'alice' }]) {
    call.mockResolvedValueOnce(account);
    await expect(deliver()).rejects.toThrow('no matching local account');
  }
  expect(appendActorData).toHaveBeenCalledTimes(1);
  expect(ctx.meta.dataset).toBe('other');
});
