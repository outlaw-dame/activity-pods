'use strict';

jest.mock('../config/config', () => ({ BASE_URL: 'https://activitypods' }));

const service = require('../services/core/webfinger');

describe('local WebFinger directory isolation', () => {
  function instance(broker = { call: jest.fn() }) {
    return { settings: { domainName: 'activitypods', baseUrl: 'https://activitypods' }, broker };
  }

  test('derives the canonical local actor without a datastore or request-context round trip', async () => {
    const broker = { call: jest.fn() };
    const self = instance(broker);
    const ctx = {
      params: { resource: 'acct:alice@activitypods' },
      meta: { webId: 'https://remote.example/users/bob' },
      call: jest.fn(() => { throw new Error('request context must not be propagated'); })
    };

    await expect(service.actions.get.call(self, ctx)).resolves.toEqual({
      subject: 'acct:alice@activitypods',
      aliases: ['https://activitypods/alice'],
      links: [{ rel: 'self', type: 'application/activity+json', href: 'https://activitypods/alice' }]
    });
    expect(broker.call).not.toHaveBeenCalled();
    expect(ctx.call).not.toHaveBeenCalled();
  });

  test.each([
    'acct:alice@remote.example',
    'acct:ali@ce@activitypods',
    'acct:../alice@activitypods',
    'https://activitypods/alice'
  ])('fails closed for non-local or malformed resource %s', async resource => {
    const broker = { call: jest.fn() };
    const ctx = { params: { resource }, meta: {} };

    await expect(service.actions.get.call(instance(broker), ctx)).resolves.toBeUndefined();
    expect(ctx.meta.$statusCode).toBe(404);
    expect(broker.call).not.toHaveBeenCalled();
  });

  test('returns the deterministic actor URI while leaving actor existence authoritative to that endpoint', async () => {
    const ctx = { params: { resource: 'acct:missing@activitypods' }, meta: {} };
    await expect(service.actions.get.call(instance(), ctx)).resolves.toMatchObject({
      aliases: ['https://activitypods/missing']
    });
    expect(ctx.meta.$statusCode).toBeUndefined();
  });
});
