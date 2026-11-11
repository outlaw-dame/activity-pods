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
    {protocols:{atproto:{enabled:false}}}
  ])('rejects unsupported optional identity configuration %o', request => {
    expect(() => assertUnifiedRequest(request)).toThrow('UNIFIED_IDENTITY_REQUIRED');
  });
  test.each([
    {...result, actorId:'https://paper.example/users/other'},
    {...result, did:'did:web:paper.example'},
    {...result, did:'did:plc:short'},
    {...result, repoInitialized:false},
    {...result, repoInitialized:null},
    {...result, webId:'http://paper.example/users/alice'},
    {...result, actorId:null}
  ])('does not report account provisioned with missing or different identities %o', invalid => {
    expect(() => assertUnifiedResult(invalid)).toThrow('UNIFIED_IDENTITY_INCOMPLETE');
  });
});
