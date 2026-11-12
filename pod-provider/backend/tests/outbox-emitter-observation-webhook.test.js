'use strict';

const service = require('../services/outbox-emitter.service');

const event = {
  eventId: '01TESTOBSERVATIONEVENTEXACT',
  schema: 'ap.outbox.committed.v1',
  actorUri: 'https://paper.example.test/alice',
  activityId: 'https://paper.example.test/as/1',
  activity: { id: 'https://paper.example.test/as/1', type: 'Create' },
  meta: { visibility: 'public' }
};
const previousFetch = global.fetch;
afterEach(() => { global.fetch = previousFetch; });
function host(overrides = {}) {
  return {
    settings: {
      sidecarObservationWebhookUrl: 'http://fedify-sidecar:8080/webhook/outbox-observation',
      sidecarToken: 'test-only-token',
      observationWebhookRetries: 1,
      observationWebhookTimeoutMs: 1000,
      ...overrides
    },
    logger: { error: jest.fn(), info: jest.fn() }
  };
}

test('observation webhook requires the exact 202 targetless durable receipt', async () => {
  const subject = host();
  global.fetch = jest.fn(async () => new Response(JSON.stringify({
    accepted: true, intentId: 'apdm-observation:' + event.eventId,
    jobCount: 0, observationOnly: true
  }), { status: 202 }));
  await service.methods.deliverObservationToSidecar.call(subject, event);
  expect(subject.logger.error).not.toHaveBeenCalled();
  expect(global.fetch).toHaveBeenCalledTimes(1);
  const args = global.fetch.mock.calls[0][1];
  expect(args.headers.Authorization).toBe('Bearer test-only-token');
  expect(args.headers['X-Event-Id']).toBe(event.eventId);
});

test('200 or wrong durable intent does not masquerade as observation acceptance', async () => {
  for (const bad of [
    { status: 200, body: { accepted: true, intentId: 'apdm-observation:' + event.eventId, jobCount: 0, observationOnly: true } },
    { status: 202, body: { accepted: true, intentId: 'different', jobCount: 0, observationOnly: true } },
    { status: 202, body: { accepted: true, intentId: 'apdm-observation:' + event.eventId, jobCount: 1, observationOnly: false } }
  ]) {
    const subject = host();
    global.fetch = jest.fn(async () => new Response(JSON.stringify(bad.body), { status: bad.status }));
    await service.methods.deliverObservationToSidecar.call(subject, event);
    expect(subject.logger.error).toHaveBeenCalledTimes(1);
  }
});

test('the native observation webhook retry budget is bounded at service construction', () => {
  const originalRetries = process.env.OBSERVATION_WEBHOOK_RETRIES;
  const originalTimeout = process.env.OBSERVATION_WEBHOOK_TIMEOUT_MS;
  try {
    process.env.OBSERVATION_WEBHOOK_RETRIES = '1000000';
    process.env.OBSERVATION_WEBHOOK_TIMEOUT_MS = '999999999';
    jest.resetModules();
    const fresh = require('../services/outbox-emitter.service');
    expect(fresh.settings.observationWebhookRetries).toBe(3);
    expect(fresh.settings.observationWebhookTimeoutMs).toBe(3000);
  } finally {
    if (originalRetries === undefined) delete process.env.OBSERVATION_WEBHOOK_RETRIES;
    else process.env.OBSERVATION_WEBHOOK_RETRIES = originalRetries;
    if (originalTimeout === undefined) delete process.env.OBSERVATION_WEBHOOK_TIMEOUT_MS;
    else process.env.OBSERVATION_WEBHOOK_TIMEOUT_MS = originalTimeout;
    jest.resetModules();
  }
});
