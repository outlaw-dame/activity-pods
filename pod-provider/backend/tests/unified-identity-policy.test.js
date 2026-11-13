'use strict';
const { assertUnifiedRequest, assertUnifiedResult } = require('../utils/unified-identity-policy');

describe('mandatory unified identity for each newly created account', () => {
  const webId = 'https://paper.example/users/alice';
  const result = {
    webId, actorId: webId,
    did: 'did:plc:abcdefghijklmnopqrstuvwx',
    repoInitialized: true
  };
  test('normal request mandates Solid + ActivityPub + ATProto did:plc', () => {
    expect(assertUnifiedRequest({})).toEqual({
      solid: true, activitypub: true, atproto: true, didMethod: 'plc'
    });
    expect(assertUnifiedRequest({atproto:{didMethod:'did:plc'}}).didMethod).toBe('plc');
    expect(assertUnifiedResult(result)).toBe(true);
  });
  test.each([
    {solid:{enabled:false}},
    {activitypub:{enabled:false}},
    {atproto:{enabled:false}},
    {atproto:{didMethod:'web'}},
    {atproto:{didMethod:'did:web'}},
    {solid:false}, {activitypub:false}, {atproto:false},
    {protocols:{solid:false}},
    {protocols:{activitypub:false}},
    {protocols:{atproto:false}},
    {protocols:{solid:{enabled:false}}},
    {protocols:{activitypub:{enabled:false}}},
    {protocols:{atproto:{enabled:false}}},
    []
  ])('rejects unsupported optional identity configuration %o', request => {
    expect(() => assertUnifiedRequest(request)).toThrow('UNIFIED_IDENTITY_REQUIRED');
  });
  test.each([
    { did: 'did:plc:abcdefghijklmnopqrstuvwx' },
    { webId: 'https://old.example/alice' },
    { canonicalAccountId: 'https://old.example/alice' },
    { actorId: 'https://old.example/alice' },
    { existingAccountId: 'https://old.example/alice' },
    { migration: true },
    { import: { from: 'existing-account' } },
    { linkExisting: false },
    { atproto: { did: 'did:plc:abcdefghijklmnopqrstuvwx' } },
    { atproto: { existingDid: 'did:plc:abcdefghijklmnopqrstuvwx' } },
    { atproto: { force: true } },
    { protocols: { atproto: { importDid: 'did:plc:abcdefghijklmnopqrstuvwx' } } },
    { protocols: { activitypub: { actorId: 'https://old.example/alice' } } },
    { protocols: { solid: { webId: 'https://old.example/alice' } } }
  ])('new-account policy rejects existing-identity adoption before provisioning: %o', invalid => {
    try {
      assertUnifiedRequest(invalid);
      throw new Error('Expected existing-identity adoption to be rejected');
    } catch (error) {
      expect(error.code).toBe('UNIFIED_ACCOUNT_NEW_ONLY');
    }
  });
  test('new accounts may still choose a new handle without importing a DID', () => {
    expect(assertUnifiedRequest({
      username: 'newuser',
      atproto: { requestedHandle: 'newuser.pods.example', didMethod: 'plc' }
    })).toEqual({ solid: true, activitypub: true, atproto: true, didMethod: 'plc' });
  });
  test.each([
    {...result, actorId:'https://paper.example/users/other'},
    {...result, did:'did:web:paper.example'},
    {...result, did:'did:plc:short'},
    {...result, repoInitialized:false},
    {...result, repoInitialized:null},
    {...result, webId:'http://paper.example/users/alice'},
    {...result, webId:'https:///users/alice', actorId:'https:///users/alice'},
    {...result, webId:'https://alice:secret@paper.example/users/alice', actorId:'https://alice:secret@paper.example/users/alice'},
    {...result, webId:'https://paper.example:443/users/alice', actorId:'https://paper.example:443/users/alice'},
    {...result, webId:'https://paper.example/users/../alice', actorId:'https://paper.example/users/../alice'},
    {...result, actorId:null}
  ])('does not report account provisioned with missing or different identities %o', invalid => {
    expect(() => assertUnifiedResult(invalid)).toThrow('UNIFIED_IDENTITY_INCOMPLETE');
  });
  test.each([null, undefined, [], 'https://paper.example/users/alice'])(
    'rejects malformed provisioning results instead of throwing an unclassified error: %p',
    invalid => {
      expect(() => assertUnifiedResult(invalid)).toThrow('UNIFIED_IDENTITY_INCOMPLETE');
    }
  );
});
