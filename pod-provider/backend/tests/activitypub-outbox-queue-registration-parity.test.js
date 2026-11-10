'use strict';

const {
  createOutboxServiceSchema
} = require('../lib/activitypub-service-with-delivery-strategy');
const {
  DELIVERY_HANDOFF_QUEUE
} = require('../utils/activitypub-delivery-handoff');

describe('ActivityPub outbox queue registration parity', () => {
  test('preserves the exact SemApps native remotePost processor while adding durable handoff', () => {
    const nativeRemotePostProcess = async function nativeRemotePostProcess() {
      return { ok: true };
    };
    const OutboxService = {
      name: 'activitypub.outbox',
      actions: {
        async post() {}
      },
      queues: {
        remotePost: {
          name: '*',
          process: nativeRemotePostProcess
        }
      }
    };

    const schema = createOutboxServiceSchema({
      baseUri: 'https://pods.example',
      podProvider: true,
      queueServiceUrl: 'redis://127.0.0.1:6379/1',
      remoteDeliveryMode: 'native',
      allowExternalDeliveryPreview: false,
      deliveryHandoffUrl: null,
      deliveryHandoffToken: '',
      deliveryHandoffTimeoutMs: 5000,
      internals: {
        OutboxService,
        FakeQueueMixin: {}
      },
      buildDeliveryPlan: jest.fn(),
      enqueueHandoff: jest.fn()
    });

    expect(schema.queues.remotePost).toBe(OutboxService.queues.remotePost);
    expect(schema.queues.remotePost.process).toBe(nativeRemotePostProcess);
    expect(schema.queues[DELIVERY_HANDOFF_QUEUE]).toBeDefined();
    expect(typeof schema.queues[DELIVERY_HANDOFF_QUEUE].process).toBe('function');
    expect(Object.keys(schema.queues).sort()).toEqual(['remotePost', DELIVERY_HANDOFF_QUEUE].sort());
  });
});
