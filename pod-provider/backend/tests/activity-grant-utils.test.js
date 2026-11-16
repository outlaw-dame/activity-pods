jest.mock('@semapps/ldp', () => ({ arrayOf: value => value == null ? [] : Array.isArray(value) ? value : [value] }));
const { hasActivityGrant } = require('../utils');

describe('activity grant matching', () => {
  const template = { type: 'Create' };
  const capability = { verifiableCredential: [{ credentialSubject: {
    hasActivityGrant: [{ type: 'ActivityGrant', activity: { type: 'Create', actor: 'https://pods.example/alice' } }]
  } }] };
  test('requires an actual activity and checks all grant restrictions', () => {
    expect(hasActivityGrant(capability, template)).toBe(false);
    expect(hasActivityGrant(capability, template, { type: 'Create', actor: 'https://pods.example/alice' })).toBe(true);
    expect(hasActivityGrant(capability, template, { type: 'Create', actor: 'https://pods.example/bob' })).toBe(false);
    expect(hasActivityGrant(capability, { type: 'Delete' }, { type: 'Create', actor: 'https://pods.example/alice' })).toBe(false);
  });
});
