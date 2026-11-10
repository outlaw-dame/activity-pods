const activityPubProvisioning = require('../services/activitypub-provisioning');

const WEB_ID = 'https://pod.example/alice';
const DATASET = 'alice';

function makeContext({ account = { username: DATASET }, actor } = {}) {
  const calls = [];
  const ctx = {
    params: {
      canonicalAccountId: WEB_ID,
      webId: WEB_ID,
      username: DATASET,
      profile: {}
    },
    async call(action, params, options) {
      calls.push({ action, params, options });
      if (action === 'auth.account.findByWebId') return account;
      if (action === 'activitypub.actor.awaitCreateComplete') {
        return (
          actor || {
            id: WEB_ID,
            preferredUsername: DATASET,
            inbox: `${WEB_ID}/inbox`,
            outbox: `${WEB_ID}/outbox`,
            followers: `${WEB_ID}/followers`,
            following: `${WEB_ID}/following`
          }
        );
      }
      throw new Error(`Unexpected action ${action}`);
    }
  };
  return { ctx, calls };
}

describe('ActivityPub provisioning dataset authority', () => {
  test('resolves the owner dataset and scopes actor completeness polling to it', async () => {
    const { ctx, calls } = makeContext();

    const result = await activityPubProvisioning.actions.provisionForAccount.handler.call(activityPubProvisioning, ctx);

    expect(calls[0]).toEqual({
      action: 'auth.account.findByWebId',
      params: { webId: WEB_ID },
      options: undefined
    });
    expect(calls[1]).toEqual({
      action: 'activitypub.actor.awaitCreateComplete',
      params: {
        actorUri: WEB_ID,
        additionalKeys: ['preferredUsername'],
        delayMs: 1000,
        maxTries: 60
      },
      options: { meta: { dataset: DATASET } }
    });
    expect(result).toEqual({
      actorId: WEB_ID,
      handle: '@alice@pod.example',
      inbox: `${WEB_ID}/inbox`,
      outbox: `${WEB_ID}/outbox`,
      followers: `${WEB_ID}/followers`,
      following: `${WEB_ID}/following`
    });
  });

  test('fails closed when the local account cannot establish dataset authority', async () => {
    const { ctx, calls } = makeContext({ account: null });

    await expect(activityPubProvisioning.actions.provisionForAccount.handler.call(activityPubProvisioning, ctx)).rejects.toMatchObject({
      type: 'ACTIVITYPUB_PROVISIONING_DATASET_UNAVAILABLE'
    });
    expect(calls.map(call => call.action)).toEqual(['auth.account.findByWebId']);
  });

  test('fails closed when caller username conflicts with the authoritative account dataset', async () => {
    const { ctx, calls } = makeContext({ account: { username: 'mallory' } });

    await expect(activityPubProvisioning.actions.provisionForAccount.handler.call(activityPubProvisioning, ctx)).rejects.toMatchObject({
      type: 'ACTIVITYPUB_PROVISIONING_DATASET_MISMATCH'
    });
    expect(calls.map(call => call.action)).toEqual(['auth.account.findByWebId']);
  });
});
