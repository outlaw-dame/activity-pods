'use strict';

const {
  CollectiveIdentityError,
  validatePublicCollectiveActor,
  validateManagedGroupDidSyntax
} = require('../services/utils/collective-identity-boundary');

const ID = 'cg_KD82p9aL4vQ1';
const ORIGIN = 'https://social.example';
const URI = ORIGIN + '/groups/' + ID;
const input = (overrides = {}) => ({
  canonicalGroupId: ID,
  actorType: 'Group',
  status: 'active',
  actorUri: URI,
  displayName: 'An independent community',
  preferredUsername: 'community',
  inboxUri: URI + '/inbox',
  outboxUri: URI + '/outbox',
  followersUri: URI + '/followers',
  publicKeyId: URI + '#main-key',
  identityRevision: 1,
  policyRevision: 1,
  ...overrides
});
const opts = (overrides = {}) => ({ providerOrigin: ORIGIN, expectedActorUri: URI, ...overrides });

function rejects(record, code, options = opts()) {
  try {
    validatePublicCollectiveActor(record, options);
  } catch (e) {
    expect(e).toBeInstanceOf(CollectiveIdentityError);
    expect(e.code).toBe(code);
    return;
  }
  throw new Error('Expected rejection: ' + code);
}

describe('G1 public collective identity boundary', () => {
  test('returns frozen public fields only; drops private membership and key material', () => {
    const record = input({
      ownerWebId: 'https://social.example/users/alice',
      memberWebIds: ['https://social.example/users/bob'],
      governancePolicy: { permitted: ['delete'] },
      signingPrivateKeyPem: 'SECRET',
      atprotoRotationKey: 'SECRET',
      rawRecord: { internal: true }
    });
    const result = validatePublicCollectiveActor(record, opts());
    expect(Object.isFrozen(result)).toBe(true);
    expect(result.actorType).toBe('Group');
    expect(result.actorUri).toBe(URI);
    expect(result.publicKeyId).toBe(URI + '#main-key');
    expect(result).not.toHaveProperty('ownerWebId');
    expect(result).not.toHaveProperty('memberWebIds');
    expect(result).not.toHaveProperty('governancePolicy');
    expect(JSON.stringify(result)).not.toContain('SECRET');
    expect(Object.keys(result).sort()).toEqual([
      'actorType', 'actorUri', 'canonicalGroupId', 'displayName', 'followersUri',
      'identityRevision', 'inboxUri', 'outboxUri', 'policyRevision',
      'preferredUsername', 'publicKeyId'
    ].sort());
  });

  test.each([
    ['missing record', null, 'GROUP_NOT_FOUND'],
    ['array record', [], 'GROUP_NOT_FOUND'],
    ['fake Person', input({ actorType: 'Person' }), 'GROUP_TYPE_MISMATCH'],
    ['legacy FOAF actor type', input({ actorType: 'foaf:Group' }), 'GROUP_TYPE_MISMATCH'],
    ['provisioning', input({ status: 'provisioning' }), 'GROUP_NOT_ACTIVE'],
    ['suspended', input({ status: 'suspended' }), 'GROUP_NOT_ACTIVE'],
    ['retired', input({ status: 'retired' }), 'GROUP_NOT_ACTIVE'],
    ['missing status', input({ status: undefined }), 'GROUP_NOT_ACTIVE'],
    ['short id', input({ canonicalGroupId: 'abc' }), 'GROUP_INVALID_ID'],
    ['path identifier', input({ canonicalGroupId: '../private/group' }), 'GROUP_INVALID_ID'],
    ['invalid revision', input({ identityRevision: 0 }), 'GROUP_INVALID_REVISION'],
    ['floating revision', input({ policyRevision: 1.5 }), 'GROUP_INVALID_REVISION'],
    ['unsafe integer', input({ identityRevision: Number.MAX_SAFE_INTEGER + 1 }), 'GROUP_INVALID_REVISION'],
    ['different provider actor', input({ actorUri: 'https://evil.example/groups/' + ID }), 'GROUP_CROSS_PROVIDER_URI'],
    ['query in actor', input({ actorUri: URI + '?view=internal' }), 'GROUP_INVALID_ACTOR_URI'],
    ['fragment in actor', input({ actorUri: URI + '#private' }), 'GROUP_INVALID_ACTOR_URI'],
    ['actor credentials', input({ actorUri: 'https://alice:secret@social.example/groups/' + ID }), 'GROUP_INVALID_ACTOR_URI'],
    ['insecure actor', input({ actorUri: 'http://social.example/groups/' + ID }), 'GROUP_INVALID_ACTOR_URI'],
    ['ambiguous dot path', input({ actorUri: 'https://social.example/groups/../users/alice' }), 'GROUP_INVALID_ACTOR_URI'],
    ['encoded separator', input({ actorUri: 'https://social.example/groups/%2f' + ID }), 'GROUP_INVALID_ACTOR_URI'],
    ['backslash in actor', input({ actorUri: 'https://social.example/groups\\' + ID }), 'GROUP_INVALID_ACTOR_URI'],
    ['foreign inbox', input({ inboxUri: 'https://evil.example/inbox' }), 'GROUP_CROSS_PROVIDER_URI'],
    ['foreign outbox', input({ outboxUri: 'https://evil.example/outbox' }), 'GROUP_CROSS_PROVIDER_URI'],
    ['foreign followers', input({ followersUri: 'https://evil.example/followers' }), 'GROUP_CROSS_PROVIDER_URI'],
    ['duplicate endpoints', input({ inboxUri: URI + '/outbox' }), 'GROUP_DUPLICATE_ENDPOINT'],
    ['another actors key', input({ publicKeyId: 'https://social.example/users/alice#main-key' }), 'GROUP_INVALID_KEY_ID'],
    ['arbitrary key fragment', input({ publicKeyId: URI + '#../../alice' }), 'GROUP_INVALID_KEY_ID'],
    ['private info display name', input({ displayName: 'private' + String.fromCharCode(10) + 'metadata' }), 'GROUP_INVALID_DISPLAY_NAME']
  ])('fails closed for %s', (_scenario, record, code) => rejects(record, code));

  test.each([
    ['wrong expected actor', opts({ expectedActorUri: ORIGIN + '/users/alice' }), 'GROUP_ACTOR_URI_MISMATCH'],
    ['missing expected actor', opts({ expectedActorUri: undefined }), 'GROUP_ACTOR_URI_MISMATCH'],
    ['wrong provider', opts({ providerOrigin: 'https://other.example' }), 'GROUP_CROSS_PROVIDER_URI'],
    ['invalid provider scheme', opts({ providerOrigin: 'http://social.example' }), 'GROUP_INVALID_PROVIDER'],
    ['provider slash path', opts({ providerOrigin: 'https://social.example/foo' }), 'GROUP_INVALID_PROVIDER'],
    ['provider with user info', opts({ providerOrigin: 'https://user:pass@social.example' }), 'GROUP_INVALID_PROVIDER'],
    ['provider with newline', opts({ providerOrigin: 'https://social.example' + String.fromCharCode(10) }), 'GROUP_INVALID_PROVIDER'],
    ['missing provider', opts({ providerOrigin: undefined }), 'GROUP_INVALID_PROVIDER']
  ])('rejects authority mismatch %s', (_scenario, options, code) => {
    rejects(input(), code, options);
  });

  test('never mistakes a legacy Group Pod record for a canonical collective', () => {
    rejects({ webId: URI, '@type': ['as:Group', 'foaf:Group'], owns: ORIGIN + '/users/alice' }, 'GROUP_INVALID_ID');
  });
});

describe('ATProto group DID screening only', () => {
  test('accepts did:plc syntax without claiming proof of control', () => {
    const did = 'did:plc:abcdefghijklmnopqrstuvwx';
    expect(validateManagedGroupDidSyntax(did)).toBe(did);
  });
  test.each([
    'did:web:social.example', 'did:plc:AAAABBBBCCCCDDDDEEEEFFFF',
    'did:plc:abc', 'did:plc:abcdefghijklmnopqrstuvwxyz',
    'did:plc:abcdefghijklmnopqrstuvw0', 'did:plc:abcdefghijklmnopqrstuvwx ',
    'did:key:z6MkFake', 'javascript:alert(1)', '', null
  ])('rejects invalid or unsupported DID %s', value => {
    expect(() => validateManagedGroupDidSyntax(value)).toThrow(CollectiveIdentityError);
  });
});
