const service = require('../services/activitypub-conversation-context.service');

function bindMethods() {
  const methods = { settings: service.settings, ...service.methods };
  for (const [name, method] of Object.entries(methods)) {
    if (typeof method === 'function') methods[name] = method.bind(methods);
  }
  return methods;
}

describe('ActivityPub conversation collection readiness', () => {
  test('waits for each concurrently-created collection before returning it to writers', async () => {
    const rootObjectUri = 'https://pod.example/alice/data/root';
    const actorUri = 'https://pod.example/alice';
    const dataset = 'alice';
    const readinessAttempts = new Map();
    const calls = [];
    const ctx = {
      async call(action, params, options) {
        calls.push({ action, params, options });
        if (action === 'activitypub.collections-registry.createAndAttachCollection') {
          return `${rootObjectUri}${params.collection.path}`;
        }
        if (action === 'activitypub.collection.exist') {
          const attempts = (readinessAttempts.get(params.resourceUri) || 0) + 1;
          readinessAttempts.set(params.resourceUri, attempts);
          return attempts >= 2;
        }
        throw new Error(`Unexpected action ${action}`);
      }
    };

    const result = await bindMethods().ensureConversationCollections(ctx, rootObjectUri, actorUri, dataset);

    expect(result).toEqual({
      contextCollectionUri: `${rootObjectUri}/context`,
      historyCollectionUri: `${rootObjectUri}/context/history`
    });
    expect(readinessAttempts).toEqual(
      new Map([
        [`${rootObjectUri}/context`, 2],
        [`${rootObjectUri}/context/history`, 2]
      ])
    );
    expect(calls.filter(call => call.action === 'activitypub.collection.exist')).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          params: { resourceUri: `${rootObjectUri}/context` },
          options: { meta: { webId: actorUri, dataset } }
        }),
        expect.objectContaining({
          params: { resourceUri: `${rootObjectUri}/context/history` },
          options: { meta: { webId: actorUri, dataset } }
        })
      ])
    );
  });
});
