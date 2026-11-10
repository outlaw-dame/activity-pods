'use strict';

const TrustEvaluatorMiddleware = require('../middlewares/trust-evaluator');

const WEB_ID = 'https://activitypods.test/alice';

function makeBroker(callImpl) {
  return {
    call: jest.fn(callImpl),
    emit: jest.fn(),
    logger: {
      warn: jest.fn(),
      info: jest.fn(),
      debug: jest.fn()
    }
  };
}

function makeContext(broker) {
  return {
    // The authenticated principal is the remote HTTP-signature actor. It must
    // never be used to select the local recipient's trust dataset.
    meta: { webId: 'https://remote.example/users/bob' },
    params: {
      collectionUri: `${WEB_ID}/inbox`,
      id: 'https://remote.example/activities/accept-1',
      type: 'Accept',
      actor: 'https://remote.example/users/bob',
      object: 'https://activitypods.test/activities/follow-1'
    },
    broker
  };
}

function wrappedHandler({ mode = 'enforce', broker, next = jest.fn().mockResolvedValue('stored') }) {
  const middleware = TrustEvaluatorMiddleware({ mode, blockThreshold: 0.9 });
  return {
    next,
    handler: middleware.localAction(next, { name: 'activitypub.inbox.post' }),
    ctx: makeContext(broker)
  };
}

describe('TrustEvaluatorMiddleware dataset authority', () => {
  test('uses the exact authoritative account username as the trust dataset', async () => {
    const broker = makeBroker(async (action, params) => {
      if (action === 'activitypub.collection.getOwner') {
        expect(params).toEqual({ collectionUri: `${WEB_ID}/inbox`, collectionKey: 'inbox' });
        return WEB_ID;
      }
      if (action === 'auth.account.findByWebId') {
        expect(params).toEqual({ webId: WEB_ID });
        return { username: 'alice', webId: WEB_ID };
      }
      if (action === 'triplestore.query') {
        expect(params).toEqual(expect.objectContaining({ dataset: 'alice', webId: 'system' }));
        expect(params.dataset).not.toBe('ap');
        return [];
      }
      throw new Error(`Unexpected call ${action}`);
    });
    const { handler, ctx, next } = wrappedHandler({ broker });

    await expect(handler(ctx)).resolves.toBe('stored');
    expect(next).toHaveBeenCalledTimes(1);
    expect(broker.call).toHaveBeenNthCalledWith(1, 'activitypub.collection.getOwner', {
      collectionUri: `${WEB_ID}/inbox`,
      collectionKey: 'inbox'
    });
    expect(broker.call).toHaveBeenNthCalledWith(2, 'auth.account.findByWebId', { webId: WEB_ID });
    expect(broker.call).toHaveBeenNthCalledWith(3, 'triplestore.query', expect.objectContaining({ dataset: 'alice' }));
  });

  test('fails closed in enforce mode when the account/WebID binding is not exact', async () => {
    const broker = makeBroker(async action => {
      if (action === 'activitypub.collection.getOwner') return WEB_ID;
      if (action === 'auth.account.findByWebId') {
        return { username: 'alice', webId: 'https://activitypods.test/mallory' };
      }
      throw new Error(`Unexpected call ${action}`);
    });
    const { handler, ctx, next } = wrappedHandler({ broker });

    await expect(handler(ctx)).rejects.toMatchObject({
      code: 503,
      type: 'TRUST_EVAL_UNAVAILABLE',
      message: 'Trust evaluation unavailable'
    });
    expect(next).not.toHaveBeenCalled();
  });

  test('fails closed in enforce mode when the account authority is unavailable', async () => {
    const broker = makeBroker(async action => {
      if (action === 'activitypub.collection.getOwner') return WEB_ID;
      if (action === 'auth.account.findByWebId') throw new Error('settings dataset unavailable');
      throw new Error(`Unexpected call ${action}`);
    });
    const { handler, ctx, next } = wrappedHandler({ broker });

    await expect(handler(ctx)).rejects.toMatchObject({
      code: 503,
      type: 'TRUST_EVAL_UNAVAILABLE',
      message: 'Trust evaluation unavailable'
    });
    expect(next).not.toHaveBeenCalled();
  });

  test('fails closed in enforce mode when trust data cannot be queried', async () => {
    const broker = makeBroker(async action => {
      if (action === 'activitypub.collection.getOwner') return WEB_ID;
      if (action === 'auth.account.findByWebId') return { username: 'alice', webId: WEB_ID };
      if (action === 'triplestore.query') throw new Error('raw fuseki diagnostic');
      throw new Error(`Unexpected call ${action}`);
    });
    const { handler, ctx, next } = wrappedHandler({ broker });

    let thrown;
    try {
      await handler(ctx);
    } catch (error) {
      thrown = error;
    }
    expect(thrown).toMatchObject({ code: 503, type: 'TRUST_EVAL_UNAVAILABLE' });
    expect(thrown.message).toBe('Trust evaluation unavailable');
    expect(thrown.message).not.toContain('fuseki');
    expect(next).not.toHaveBeenCalled();
  });

  test('preserves observation-only availability semantics when trust data is unavailable', async () => {
    const broker = makeBroker(async action => {
      if (action === 'activitypub.collection.getOwner') return WEB_ID;
      if (action === 'auth.account.findByWebId') return { username: 'alice', webId: WEB_ID };
      if (action === 'triplestore.query') throw new Error('temporary query failure');
      throw new Error(`Unexpected call ${action}`);
    });
    const { handler, ctx, next } = wrappedHandler({ mode: 'observe', broker });

    await expect(handler(ctx)).resolves.toBe('stored');
    expect(next).toHaveBeenCalledTimes(1);
    expect(broker.logger.warn).toHaveBeenCalledWith(
      '[TrustEval] evaluation unavailable',
      expect.objectContaining({ mode: 'observe' })
    );
  });

  test('fails closed when the registered inbox owner cannot be resolved', async () => {
    const broker = makeBroker(async action => {
      if (action === 'activitypub.collection.getOwner') return null;
      throw new Error(`Unexpected call ${action}`);
    });
    const { handler, ctx, next } = wrappedHandler({ broker });

    await expect(handler(ctx)).rejects.toMatchObject({
      code: 503,
      type: 'TRUST_EVAL_UNAVAILABLE',
      message: 'Trust evaluation unavailable'
    });
    expect(next).not.toHaveBeenCalled();
  });
});
