'use strict';

const service = require('../services/activitypub-conversation-context.service');

describe('conversation collection distributed readiness barrier', () => {
  const uri = 'https://example.test/alice/data/123/context/history';
  const dataset = 'alice';

  test('does not mutate or accept a registry URI before actual persisted collection existence', async () => {
    let reads = 0;
    const ctx = {
      call: jest.fn(async (action, params, options) => {
        expect(action).toBe('activitypub.collection.exist');
        expect(params).toEqual({ resourceUri: uri, webId: 'system' });
        expect(options).toEqual({ meta: { dataset, webId: 'system', $cache: false } });
        reads += 1;
        return reads === 3;
      })
    };
    await expect(service.methods.awaitPersistedCollection(ctx, uri, 'https://example.test/alice', dataset))
      .resolves.toBeUndefined();
    expect(reads).toBe(3);
    expect(ctx.call).toHaveBeenCalledTimes(3);
  });

  test('fails closed on persistent absence with ten bounded read-only checks', async () => {
    const ctx = { call: jest.fn(async () => false) };
    await expect(service.methods.awaitPersistedCollection(ctx, uri, 'https://example.test/alice', dataset))
      .rejects.toMatchObject({ code: 'CONVERSATION_COLLECTION_NOT_READY' });
    expect(ctx.call).toHaveBeenCalledTimes(10);
    expect(ctx.call.mock.calls.every(call => call[0] === 'activitypub.collection.exist')).toBe(true);
  });

  test('does not swallow authorization or datastore errors', async () => {
    const cause = Object.assign(new Error('Permission denied'), { code: 403 });
    const ctx = { call: jest.fn(async () => { throw cause; }) };
    await expect(service.methods.awaitPersistedCollection(ctx, uri, 'https://example.test/alice', dataset))
      .rejects.toBe(cause);
    expect(ctx.call).toHaveBeenCalledTimes(1);
  });

  test('both context and history are checked before use', () => {
    const source = service.methods.ensureConversationCollections.toString();
    expect(source).toContain('await this.awaitPersistedCollection(ctx, contextCollectionUri, actorUri, dataset)');
    expect(source).toContain('await this.awaitPersistedCollection(ctx, historyCollectionUri, actorUri, dataset)');
    expect(source.indexOf('await this.awaitPersistedCollection(ctx, historyCollectionUri'))
      .toBeLessThan(source.indexOf('return { contextCollectionUri, historyCollectionUri }'));
  });
});
