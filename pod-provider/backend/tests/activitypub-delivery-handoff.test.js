'use strict';

const {
  DELIVERY_HANDOFF_JOB_NAME,
  DELIVERY_HANDOFF_QUEUE,
  assertDurableHandoffConfigured,
  enqueueDeliveryHandoff,
  processDeliveryHandoffJob,
  toSidecarOutboxPayload
} = require('../utils/activitypub-delivery-handoff');

function createPlan() {
  return {
    schema: 'ap.delivery-plan.v1',
    intentId: 'apdm-v1-test-intent',
    activityId: 'https://pods.example/alice/activities/1',
    actorUri: 'https://pods.example/alice',
    activity: {
      id: 'https://pods.example/alice/activities/1',
      type: 'Create',
      actor: 'https://pods.example/alice'
    },
    localRecipients: [],
    remoteRecipients: [
      {
        actorUri: 'https://remote.example/users/bob',
        inboxUrl: 'https://remote.example/users/bob/inbox',
        sharedInboxUrl: 'https://remote.example/inbox',
        targetDomain: 'remote.example'
      }
    ],
    meta: { visibility: 'followers', isPublicActivity: false }
  };
}

function createSettings() {
  return {
    queueServiceUrl: 'redis://queue.example:6379',
    deliveryHandoffUrl: 'http://fedify-sidecar:8080/webhook/outbox',
    deliveryHandoffToken: 'secret',
    deliveryHandoffTimeoutMs: 1000
  };
}

describe('APDM durable ActivityPub handoff', () => {
  test('external durability fails closed without queue, URL, HTTP(S), or token configuration', () => {
    expect(() => assertDurableHandoffConfigured({ deliveryHandoffUrl: 'http://sidecar', deliveryHandoffToken: 'x' })).toThrow(
      /SEMAPPS_QUEUE_SERVICE_URL/u
    );
    expect(() => assertDurableHandoffConfigured({ queueServiceUrl: 'redis://queue', deliveryHandoffToken: 'x' })).toThrow(
      /handoff URL/u
    );
    expect(() => assertDurableHandoffConfigured({
      queueServiceUrl: 'redis://queue',
      deliveryHandoffUrl: 'ftp://sidecar/outbox',
      deliveryHandoffToken: 'x'
    })).toThrow(/HTTP\(S\)/u);
    expect(() => assertDurableHandoffConfigured({
      queueServiceUrl: 'redis://queue',
      deliveryHandoffUrl: 'http://sidecar/outbox',
      deliveryHandoffToken: ''
    })).toThrow(/SIDECAR_TOKEN/u);
  });

  test('maps authoritative Delivery Plan targets onto the Phase 6 sidecar webhook contract', () => {
    expect(toSidecarOutboxPayload(createPlan())).toEqual({
      actorUri: 'https://pods.example/alice',
      activityId: 'https://pods.example/alice/activities/1',
      activity: expect.objectContaining({ type: 'Create' }),
      remoteTargets: [
        {
          inboxUrl: 'https://remote.example/users/bob/inbox',
          sharedInboxUrl: 'https://remote.example/inbox',
          targetDomain: 'remote.example',
          apdmAuthority: {
            schema: 'ap.delivery-plan.v1',
            intentId: 'apdm-v1-test-intent'
          }
        }
      ],
      meta: {
        visibility: 'followers',
        isPublicActivity: false,
        deliveryPlanIntentId: 'apdm-v1-test-intent',
        deliveryPlanSchema: 'ap.delivery-plan.v1'
      }
    });
  });

  test('awaits Bull insertion and sets deterministic uniqueness through opts.jobId', async () => {
    const plan = createPlan();
    let release;
    const insertion = new Promise(resolve => {
      release = resolve;
    });
    const createJob = jest.fn(() => insertion);
    const service = { settings: createSettings(), createJob };

    let settled = false;
    const pending = enqueueDeliveryHandoff(service, plan).finally(() => {
      settled = true;
    });
    await Promise.resolve();
    expect(settled).toBe(false);
    expect(createJob).toHaveBeenCalledWith(
      DELIVERY_HANDOFF_QUEUE,
      DELIVERY_HANDOFF_JOB_NAME,
      { deliveryPlan: plan },
      expect.objectContaining({ jobId: plan.intentId })
    );

    release({ id: plan.intentId });
    await expect(pending).resolves.toBe(plan.intentId);
  });

  test('propagates Bull insertion failure so the outbox action cannot report success', async () => {
    const service = {
      settings: createSettings(),
      createJob: jest.fn(() => Promise.reject(new Error('redis insertion failed')))
    };
    await expect(enqueueDeliveryHandoff(service, createPlan())).rejects.toThrow(/redis insertion failed/u);
  });

  test('worker treats sidecar 202 acknowledgement as durable acceptance', async () => {
    const plan = createPlan();
    const progress = jest.fn();
    const fetchImpl = jest.fn(async () => ({
      ok: true,
      status: 202,
      async json() {
        return { accepted: true, intentId: plan.intentId, jobCount: 1 };
      }
    }));
    const service = { settings: createSettings() };

    const result = await processDeliveryHandoffJob(service, { data: { deliveryPlan: plan }, progress }, fetchImpl);

    expect(result).toEqual({
      status: 'accepted',
      deliveryPlanIntentId: plan.intentId,
      sidecarIntentId: plan.intentId,
      jobCount: 1
    });
    expect(progress).toHaveBeenCalledWith(100);
    const [, request] = fetchImpl.mock.calls[0];
    expect(request.headers.Authorization).toBe('Bearer secret');
    expect(request.headers['X-APDM-Intent-Id']).toBe(plan.intentId);
    const body = JSON.parse(request.body);
    expect(body.meta.deliveryPlanIntentId).toBe(plan.intentId);
    expect(body.meta.deliveryPlanSchema).toBe(plan.schema);
    expect(body.remoteTargets[0].apdmAuthority).toEqual({
      schema: plan.schema,
      intentId: plan.intentId
    });
  });

  test('worker rejects a generic 200 even when the body says accepted', async () => {
    const fetchImpl = jest.fn(async () => ({
      ok: true,
      status: 200,
      async json() {
        return { accepted: true, intentId: 'not-durable-proof' };
      }
    }));
    await expect(
      processDeliveryHandoffJob(
        { settings: createSettings() },
        { data: { deliveryPlan: createPlan() }, progress: jest.fn() },
        fetchImpl
      )
    ).rejects.toThrow(/expected durable 202 acceptance/u);
  });

  test('worker throws on non-202 so Bull retries instead of dropping the handoff', async () => {
    const fetchImpl = jest.fn(async () => ({ ok: false, status: 503 }));
    await expect(
      processDeliveryHandoffJob(
        { settings: createSettings() },
        { data: { deliveryPlan: createPlan() }, progress: jest.fn() },
        fetchImpl
      )
    ).rejects.toThrow(/returned 503/u);
  });

  test('worker rejects malformed acknowledgement JSON', async () => {
    const fetchImpl = jest.fn(async () => ({
      status: 202,
      async json() {
        throw new SyntaxError('bad json');
      }
    }));
    await expect(
      processDeliveryHandoffJob(
        { settings: createSettings() },
        { data: { deliveryPlan: createPlan() }, progress: jest.fn() },
        fetchImpl
      )
    ).rejects.toThrow(/invalid acknowledgement body/u);
  });

  test('worker throws when 202 body does not prove Redis acceptance', async () => {
    for (const body of [
      { accepted: false, intentId: 'x' },
      { accepted: true },
      { intentId: 'x' },
      null
    ]) {
      const fetchImpl = jest.fn(async () => ({
        status: 202,
        async json() {
          return body;
        }
      }));
      await expect(
        processDeliveryHandoffJob(
          { settings: createSettings() },
          { data: { deliveryPlan: createPlan() }, progress: jest.fn() },
          fetchImpl
        )
      ).rejects.toThrow(/did not confirm Redis acceptance/u);
    }
  });


  test('rejects a 202 receipt for a different request and invalid job counts', async () => {
    for (const ack of [
      { accepted: true, intentId: 'another-intent', jobCount: 1 },
      { accepted: true, intentId: createPlan().intentId, jobCount: 0 },
      { accepted: true, intentId: createPlan().intentId, jobCount: 2 },
      { accepted: true, intentId: createPlan().intentId, jobCount: 1.5 },
      { accepted: true, intentId: createPlan().intentId },
    ]) {
      await expect(processDeliveryHandoffJob(
        { settings: createSettings() }, { data: { deliveryPlan: createPlan() } },
        async () => new Response(JSON.stringify(ack), { status: 202 })
      )).rejects.toThrow(/did not confirm Redis acceptance/u);
    }
  });

  test('bounds streamed receipt JSON before allocating an unbounded body', async () => {
    const plan = createPlan();
    const hugeAck = JSON.stringify({
      accepted: true, intentId: plan.intentId, jobCount: 1,
      padding: 'a'.repeat(5000)
    });
    await expect(processDeliveryHandoffJob(
      { settings: createSettings() }, { data: { deliveryPlan: plan } },
      async () => new Response(hugeAck, { status: 202 })
    )).rejects.toThrow(/exceeds size limit/u);
  });

  test('does not parse an oversized Content-Length response', async () => {
    const plan = createPlan();
    const response = new Response('{"accepted":true}', {
      status: 202, headers: { 'Content-Length': '1000000' }
    });
    await expect(processDeliveryHandoffJob(
      { settings: createSettings() }, { data: { deliveryPlan: plan } },
      async () => response
    )).rejects.toThrow(/exceeds size limit/u);
  });

  test('rejects embedded URL credentials and fragments', () => {
    for (const url of [
      'http://u:p@fedify-sidecar:8080/webhook/outbox',
      'http://fedify-sidecar:8080/webhook/outbox#fragment',
    ]) {
      expect(() => assertDurableHandoffConfigured({
        ...createSettings(), deliveryHandoffUrl: url
      })).toThrow(/canonical/u);
    }
  });

  test('same Delivery Plan retry keeps identical Bull opts.jobId and stable wire authority', async () => {
    const plan = createPlan();
    const createJob = jest.fn(async () => ({ id: plan.intentId }));
    const service = { settings: createSettings(), createJob };

    await enqueueDeliveryHandoff(service, plan);
    await enqueueDeliveryHandoff(service, plan);

    expect(createJob).toHaveBeenCalledTimes(2);
    expect(createJob.mock.calls.map(call => call[1])).toEqual([
      DELIVERY_HANDOFF_JOB_NAME,
      DELIVERY_HANDOFF_JOB_NAME
    ]);
    expect(createJob.mock.calls.map(call => call[3].jobId)).toEqual([plan.intentId, plan.intentId]);
    const payload = toSidecarOutboxPayload(plan);
    expect(payload.meta.deliveryPlanIntentId).toBe(plan.intentId);
    expect(payload.remoteTargets[0].apdmAuthority.intentId).toBe(plan.intentId);
  });
});