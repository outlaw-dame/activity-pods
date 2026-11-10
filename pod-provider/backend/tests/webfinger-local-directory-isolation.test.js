'use strict';

jest.mock('../config/config', () => ({ BASE_URL: 'https://activitypods' }));

const service = require('../services/core/webfinger');

describe('local WebFinger directory isolation', () => {
  function instance(broker = { call: jest.fn() }) {
    return {
      settings: { domainName: 'activitypods', baseUrl: 'https://activitypods' },
      broker,
      logger: { debug: jest.fn() }
    };
  }

  test('derives the canonical local acct actor without a datastore or request-context round trip', async () => {
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
    'https://activitypods/alice',
    'https://activitypods/alice/keys/main'
  ])('resolves exact authoritative local ActivityPub resource %s to the actor', async resource => {
    const broker = {
      call: jest.fn().mockResolvedValue({ username: 'alice', webId: 'https://activitypods/alice' })
    };
    const ctx = { params: { resource }, meta: {} };

    await expect(service.actions.get.call(instance(broker), ctx)).resolves.toEqual({
      subject: resource,
      aliases: ['https://activitypods/alice'],
      links: [{ rel: 'self', type: 'application/activity+json', href: 'https://activitypods/alice' }]
    });
    expect(broker.call).toHaveBeenCalledTimes(1);
    expect(broker.call).toHaveBeenCalledWith('auth.account.findByUsername', { username: 'alice' });
    expect(ctx.meta.$statusCode).toBeUndefined();
  });

  test.each([
    null,
    { username: 'alice', webId: 'https://activitypods/mallory' },
    { username: 'mallory', webId: 'https://activitypods/alice' }
  ])('fails closed when a local HTTP resource has no exact account/WebID binding: %p', async account => {
    const broker = { call: jest.fn().mockResolvedValue(account) };
    const ctx = { params: { resource: 'https://activitypods/alice/keys/main' }, meta: {} };

    await expect(service.actions.get.call(instance(broker), ctx)).resolves.toBeUndefined();
    expect(ctx.meta.$statusCode).toBe(404);
    expect(broker.call).toHaveBeenCalledWith('auth.account.findByUsername', { username: 'alice' });
  });

  test('fails closed when the authoritative account lookup is unavailable', async () => {
    const broker = { call: jest.fn().mockRejectedValue(new Error('settings unavailable')) };
    const self = instance(broker);
    const ctx = { params: { resource: 'https://activitypods/alice' }, meta: {} };

    await expect(service.actions.get.call(self, ctx)).resolves.toBeUndefined();
    expect(ctx.meta.$statusCode).toBe(404);
    expect(self.logger.debug).toHaveBeenCalledTimes(1);
  });

  test.each([
    'acct:alice@remote.example',
    'acct:ali@ce@activitypods',
    'acct:../alice@activitypods',
    'https://remote.example/alice',
    'https://activitypods/alice/inbox',
    'https://activitypods/alice/keys/other',
    'https://activitypods/alice?query=1',
    'https://activitypods/%61lice'
  ])('fails closed for non-local, non-canonical, or malformed resource %s', async resource => {
    const broker = { call: jest.fn() };
    const ctx = { params: { resource }, meta: {} };

    await expect(service.actions.get.call(instance(broker), ctx)).resolves.toBeUndefined();
    expect(ctx.meta.$statusCode).toBe(404);
    expect(broker.call).not.toHaveBeenCalled();
  });

  test('returns the deterministic acct actor URI while leaving actor existence authoritative to that endpoint', async () => {
    const ctx = { params: { resource: 'acct:missing@activitypods' }, meta: {} };
    await expect(service.actions.get.call(instance(), ctx)).resolves.toMatchObject({
      aliases: ['https://activitypods/missing']
    });
    expect(ctx.meta.$statusCode).toBeUndefined();
  });
});
