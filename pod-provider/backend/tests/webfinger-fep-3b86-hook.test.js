'use strict';

jest.mock('../config/config', () => ({
  BASE_URL: 'https://pod.example',
  FRONTEND_URL: 'https://app.example'
}));

jest.mock('@semapps/webfinger', () => ({
  WebfingerService: { name: '__webfinger_stub__' }
}));

const path = require('path');
const webfinger = require(path.resolve(__dirname, '../services/core/webfinger'));

function makeBrokerWithIntents(intentLinks, throwInstead = false) {
  return {
    call: jest.fn().mockImplementation(async action => {
      expect(action).toBe('fep-3b86-activity-intents.getLinks');
      if (throwInstead) throw new Error('service unavailable');
      return intentLinks;
    })
  };
}

const intentLinks = [
  {
    rel: 'https://w3id.org/fep/3b86/Follow',
    template: 'https://pod.example/intents/follow?object={object}&on-success={on-success}&on-cancel={on-cancel}'
  }
];

describe('webfinger FEP-3B86 hook', () => {
  const hook = webfinger.hooks.after.get;
  function host(intentLinks, throwInstead = false) {
    return {
      broker: makeBrokerWithIntents(intentLinks, throwInstead),
      logger: { debug: jest.fn(), info: jest.fn(), warn: jest.fn(), error: jest.fn() }
    };
  }

  it('appends intent links to a successful WebFinger response', async () => {
    const self = host(intentLinks);
    const ctx = { call: jest.fn(() => { throw new Error('request context must remain isolated'); }) };
    const res = {
      subject: 'acct:alice@pod.example',
      links: [{ rel: 'self', href: 'https://pod.example/alice' }]
    };
    const out = await hook.call(self, ctx, res);
    expect(out.links).toHaveLength(2);
    expect(out.links[1]).toEqual(intentLinks[0]);
    expect(self.broker.call).toHaveBeenCalledWith('fep-3b86-activity-intents.getLinks', {}, { timeout: 1000 });
    expect(ctx.call).not.toHaveBeenCalled();
  });

  it('degrades gracefully when the intent service throws', async () => {
    const self = host([], true);
    const ctx = { call: jest.fn() };
    const res = { subject: 'acct:alice@pod.example', links: [] };
    const out = await hook.call(self, ctx, res);
    expect(out).toBe(res);
    expect(out.links).toHaveLength(0);
    expect(self.logger.debug).toHaveBeenCalled();
  });

  it('returns the original response untouched when links is missing', async () => {
    const self = host(intentLinks);
    const ctx = { call: jest.fn() };
    const res = { subject: 'acct:alice@pod.example' };
    const out = await hook.call(self, ctx, res);
    expect(out).toBe(res);
    expect(self.broker.call).not.toHaveBeenCalled();
  });

  it('returns nullish upstream results untouched', async () => {
    const self = host(intentLinks);
    const ctx = { call: jest.fn() };
    const out = await hook.call(self, ctx, undefined);
    expect(out).toBeUndefined();
    expect(self.broker.call).not.toHaveBeenCalled();
  });

  it('does not append when getLinks returns an empty array', async () => {
    const self = host([]);
    const ctx = { call: jest.fn() };
    const res = {
      subject: 'acct:alice@pod.example',
      links: [{ rel: 'self', href: 'https://pod.example/alice' }]
    };
    const out = await hook.call(self, ctx, res);
    expect(out.links).toHaveLength(1);
  });
});
