'use strict';

const bridge = require('../services/internal-bridge-canonical-notification-api.service');

function harness(overrides = {}) {
  return {
    ...bridge.methods,
    settings: { dedupeMaxEntries: 10000, baseUrl: 'https://paper.example.test' },
    processedIds: new Set(),
    inFlightIds: new Set(),
    logger: {
      info: jest.fn(), error: jest.fn(),
      warn: jest.fn(), debug: jest.fn()
    },
    resolveActorUri: jest.fn(async () => 'https://remote.example/alice'),
    resolveLocalRecipients: jest.fn(async () => ['https://paper.example.test/bob']),
    deliverToLocalInboxes: jest.fn(async () => ['https://paper.example.test/bob']),
    ...overrides
  };
}
function context() {
  return {
    params: {
      canonicalIntentId: 'test-canonical-id',
      kind: 'FollowAdd', sourceProtocol: 'activitypub',
      actor: { activityPubActorUri: 'https://remote.example/alice' },
      createdAt: '2026-11-11T12:00:00.000Z'
    },
    meta: {}
  };
}

test('failed notification delivery is retriable rather than falsely acknowledged', async () => {
  const host = harness({
    deliverToLocalInboxes: jest.fn(async () => { throw new Error('pod timeout'); })
  });
  await expect(bridge.actions.ingest.handler.call(host, context()))
    .rejects.toMatchObject({ code: 503 });
  expect(host.processedIds.size).toBe(0);
  expect(host.inFlightIds.size).toBe(0);
  host.deliverToLocalInboxes = jest.fn(async () => ['https://paper.example.test/bob']);
  const success = await bridge.actions.ingest.handler.call(host, context());
  expect(success).toMatchObject({ ok: true, duplicate: false, delivered: true });
  const duplicate = context();
  expect(await bridge.actions.ingest.handler.call(host, duplicate))
    .toMatchObject({ ok: true, duplicate: true });
  expect(duplicate.meta.$statusCode).toBe(409);
});

test('in-flight duplicates cannot be confused with completed notifications', async () => {
  let release;
  const host = harness({
    deliverToLocalInboxes: jest.fn(() => new Promise(resolve => { release = resolve; }))
  });
  const pending = bridge.actions.ingest.handler.call(host, context());
  await Promise.resolve();
  await Promise.resolve();
  expect(host.inFlightIds.size).toBe(1);
  await expect(bridge.actions.ingest.handler.call(host, context()))
    .rejects.toMatchObject({ code: 503 });
  release(['https://paper.example.test/bob']);
  await expect(pending).resolves.toMatchObject({ delivered: true });
  expect(host.inFlightIds.size).toBe(0);
});

test('local recipient discovery fails instead of silently losing an event', async () => {
  const host = harness({
    resolveLocalRecipients: jest.fn(async () => { throw new Error('lookup timeout'); })
  });
  await expect(bridge.actions.ingest.handler.call(host, context()))
    .rejects.toMatchObject({ code: 503 });
  expect(host.processedIds.size).toBe(0);
});

test('bounded local recipient calls complete without sequential O(N) latency', async () => {
  const host = harness();
  const ctx = { call: jest.fn(async (name, params) => {
    if (name === 'activitypub.actor.get') return { inbox: params.actorUri + '/inbox' };
  }) };
  const recipients = Array.from({ length: 8 }, (_, i) => 'https://paper.example.test/user-' + i);
  host.buildBridgeActivity = jest.fn(() => ({ type: 'Follow', actor: 'https://remote.example/alice' }));
  const delivered = await bridge.methods.deliverToLocalInboxes.call(host,
    ctx, { kind: 'FollowAdd' }, recipients, 'https://remote.example/alice');
  expect(delivered).toEqual(recipients);
  expect(ctx.call).toHaveBeenCalledTimes(16);
});
