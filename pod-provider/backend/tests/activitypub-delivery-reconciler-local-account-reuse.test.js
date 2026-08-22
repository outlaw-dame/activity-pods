'use strict';

process.env.SEMAPPS_AVAILABLE_LOCALES ||= 'en';
process.env.SEMAPPS_AUTH_RESERVED_USER_NAMES ||= 'admin';

const service = require('../services/activitypub-delivery-reconciler.service');

const SENDER = 'https://pods.example/alice';
const LOCAL = 'https://pods.example/bob';
const REMOTE = 'https://remote.example/users/carol';

function accountBinding(webId = LOCAL, username = 'bob') {
  return {
    accountUri: { value: `urn:account:${username}` },
    webId: { value: webId },
    username: { value: username }
  };
}

test('reconcileActivity resolves accepted local accounts once in a batch and reuses them in the planner', async () => {
  const accountQuery = jest.fn(async params => {
    expect(params.dataset).toBe('settings');
    expect(params.webId).toBe('system');
    expect(params.query).toContain(`<${LOCAL}>`);
    return [accountBinding()];
  });
  const localInboxQuery = jest.fn(async params => {
    expect(params.dataset).toBe('bob');
    expect(params.webId).toBe('system');
    expect(params.query).toContain(`<${LOCAL}> ldp:inbox ?inboxUri`);
    expect(params.query).toMatch(/LIMIT 2/u);
    return [{ inboxUri: { value: `${LOCAL}/inbox` } }];
  });
  const calls = [];
  const ctx = {
    async call(action, params, options) {
      calls.push({ action, params, options });
      if (action === 'activitypub.activity.getRecipients') return [LOCAL, REMOTE];
      if (action === 'triplestore.query') {
        if (params.dataset === 'settings') return accountQuery(params);
        if (params.dataset === 'bob') return localInboxQuery(params);
        throw new Error(`Unexpected triplestore dataset ${params.dataset}`);
      }
      if (action === 'auth.account.findByWebId') throw new Error('duplicate account lookup');
      if (action === 'activitypub.actor.getCollectionUri') {
        throw new Error('heavy actor materialization path must not be used');
      }
      if (action === 'activitypub.actor.get') {
        expect(params).toEqual({ actorUri: REMOTE, webId: SENDER });
        return {
          id: REMOTE,
          inbox: `${REMOTE}/inbox`,
          endpoints: { sharedInbox: 'https://remote.example/inbox' }
        };
      }
      throw new Error(`Unexpected call ${action}`);
    }
  };
  const context = {
    settings: { baseUri: 'https://pods.example', accountsDataset: 'settings' },
    logger: { debug: jest.fn() },
    expandConcreteRecipients: service.methods.expandConcreteRecipients,
    findLocalAccountsByWebIds: service.methods.findLocalAccountsByWebIds
  };
  const activity = {
    id: `${SENDER}/activities/reconcile-account-reuse`,
    type: 'Create',
    actor: SENDER,
    published: new Date().toISOString(),
    to: [LOCAL, REMOTE],
    cc: [],
    object: {
      id: `${SENDER}/objects/reconcile-account-reuse`,
      type: 'Note',
      attributedTo: SENDER,
      content: 'reuse local account metadata'
    }
  };

  const plan = await service.methods.reconcileActivity.call(context, ctx, activity, 'alice');

  expect(accountQuery).toHaveBeenCalledTimes(1);
  expect(localInboxQuery).toHaveBeenCalledTimes(1);
  expect(plan.localRecipients).toEqual([
    { actorUri: LOCAL, dataset: 'bob', inboxUri: `${LOCAL}/inbox` }
  ]);
  expect(plan.remoteRecipients).toEqual([
    expect.objectContaining({ actorUri: REMOTE, targetDomain: 'remote.example' })
  ]);
  expect(calls.some(call => call.action === 'auth.account.findByWebId')).toBe(false);
  expect(calls.some(call => call.action === 'activitypub.actor.getCollectionUri')).toBe(false);
});

test('reconcileActivity preserves fail-closed coverage when a directly addressed local-looking recipient has no account', async () => {
  const missing = 'https://pods.example/not-an-account';
  const accountQuery = jest.fn(async () => []);
  const localInboxLookup = jest.fn();
  const ctx = {
    async call(action, params) {
      if (action === 'activitypub.activity.getRecipients') return [missing, REMOTE];
      if (action === 'triplestore.query') {
        if (params.dataset === 'settings') return accountQuery(params);
        localInboxLookup();
        throw new Error('missing local account must never reach local inbox resolution');
      }
      if (action === 'auth.account.findByWebId') throw new Error('per-recipient account lookup must not run');
      if (action === 'activitypub.actor.get') {
        return { id: REMOTE, inbox: `${REMOTE}/inbox` };
      }
      if (action === 'activitypub.actor.getCollectionUri') {
        throw new Error('heavy actor materialization path must not be used');
      }
      throw new Error(`Unexpected call ${action}`);
    }
  };
  const context = {
    settings: { baseUri: 'https://pods.example', accountsDataset: 'settings' },
    logger: { debug: jest.fn() },
    expandConcreteRecipients: service.methods.expandConcreteRecipients,
    findLocalAccountsByWebIds: service.methods.findLocalAccountsByWebIds
  };
  const activity = {
    id: 'https://pods.example/alice/activities/missing-local-account',
    type: 'Create',
    actor: 'https://pods.example/alice',
    to: [missing, REMOTE],
    cc: []
  };

  await expect(service.methods.reconcileActivity.call(context, ctx, activity, 'alice')).rejects.toThrow(
    new RegExp(`omitted explicitly addressed recipient ${missing.replace(/[.*+?^${}()|[\]\\]/gu, '\\$&')}`, 'u')
  );

  expect(accountQuery).toHaveBeenCalledTimes(1);
  expect(localInboxLookup).not.toHaveBeenCalled();
});
