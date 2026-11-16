jest.mock('../../../app-framework/app/mixins/fetch-pod-or-proxy', () => ({}));
jest.mock('../../../app-framework/node_modules/@semapps/ldp', () => ({
  arrayOf: value => value == null ? [] : Array.isArray(value) ? value : [value],
  isURL: value => typeof value === 'string' && /^https?:/.test(value)
}));
const service = require('../../../app-framework/app/services/pod-handling/pod-containers');

describe('pod container actor context', () => {
  test.each(['alice', 'bob'])('preserves %s authority through type-index lookup', async name => {
    const actorUri = `https://pods.example/${name}`;
    const index = `${actorUri}/types`;
    const registration = `${actorUri}/registration`;
    const container = `${actorUri}/notes`;
    const fetch = jest.fn()
      .mockResolvedValueOnce({ body: { 'solid:publicTypeIndex': index } })
      .mockResolvedValueOnce({ body: { 'solid:hasTypeRegistration': registration } })
      .mockResolvedValueOnce({ body: {
        'solid:forClass': 'https://www.w3.org/ns/activitystreams#Note',
        'solid:instanceContainer': container
      } });
    const ctx = {
      params: { type: 'as:Note', actorUri },
      call: jest.fn().mockResolvedValue(['https://www.w3.org/ns/activitystreams#Note'])
    };
    await expect(service.actions.getByType.handler.call({ actions: { fetch } }, ctx)).resolves.toBe(container);
    expect(fetch.mock.calls.map(([params]) => ({ url: params.url, actorUri: params.actorUri }))).toEqual([
      { url: actorUri, actorUri }, { url: index, actorUri }, { url: registration, actorUri }
    ]);
  });
});
