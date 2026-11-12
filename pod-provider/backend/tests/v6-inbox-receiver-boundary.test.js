'use strict';

const service = require('../services/v6-inbox-receiver.service');

function harness() {
  return {
    ...service.methods,
    settings: {
      localInboxOrigins: 'https://paper.example.test',
      maxActivityBytes: 262144
    },
    logger: { info: jest.fn(), error: jest.fn() }
  };
}

test('verified targetInbox wins over activity-supplied collectionUri', async () => {
  const host = harness();
  const call = jest.fn(async () => undefined);
  const ctx = {
    params: {
      targetInbox: 'https://paper.example.test/alice/inbox',
      activity: {
        id: 'https://remote.example/posts/1',
        actor: 'https://remote.example/users/author',
        type: 'Create',
        collectionUri: 'https://paper.example.test/other-user/inbox'
      },
      verifiedActorUri: 'https://remote.example/users/author',
      receivedAt: Date.now(),
      remoteIp: '203.0.113.12'
    },
    call, meta: {}
  };
  const result = await service.actions.receive.call(host, ctx);
  expect(result).toEqual({ success: true });
  expect(ctx.meta.$statusCode).toBe(202);
  expect(call).toHaveBeenCalledTimes(1);
  const [, payload, opts] = call.mock.calls[0];
  expect(payload.collectionUri).toBe('https://paper.example.test/alice/inbox');
  expect(opts.meta.webId).toBe(ctx.params.verifiedActorUri);
});

test('inbox webhook rejects query, fragment, and embedded credentials', () => {
  const host = harness();
  expect(host.normalizeTrustedInboxUrl('https://paper.example.test/alice/inbox'))
    .toBe('https://paper.example.test/alice/inbox');
  for (const url of [
    'https://paper.example.test/alice/inbox?collectionUri=other',
    'https://paper.example.test/alice/inbox#fragment',
    'https://user:pass@paper.example.test/alice/inbox',
    'https://evil.example.test/alice/inbox'
  ]) expect(host.normalizeTrustedInboxUrl(url)).toBeNull();
});

test('inbound sidecar route has a pre-parser payload cap', () => {
  const fs = require('node:fs');
  const path = require('node:path');
  const source = fs.readFileSync(
    path.join(__dirname, '../services/v6-inbox-receiver.service.js'), 'utf8'
  );
  expect(source).toContain("limit: '512kb'");
});

test('inbox errors do not reflect arbitrary backend exception messages', async () => {
  const host = harness();
  const params = {
    targetInbox: 'https://paper.example.test/alice/inbox',
    activity: { id: 'https://remote.example/activity/2', type: 'Create',
      actor: 'https://remote.example/alice' },
    verifiedActorUri: 'https://remote.example/alice',
    receivedAt: Date.now(), remoteIp: '203.0.113.12'
  };
  for (const error of [
    Object.assign(new Error('secret: db user alice'), { code: 404 }),
    Object.assign(new Error('secret: db password'), { code: 500 })
  ]) {
    const ctx = { params, meta: {}, call: jest.fn(async () => { throw error; }) };
    const answer = await service.actions.receive.call(host, ctx);
    expect(JSON.stringify(answer)).not.toContain('secret');
    expect(JSON.stringify(host.logger.error.mock.calls)).not.toContain('secret');
    expect(ctx.meta.$statusCode).toBe(error.code);
  }
});
