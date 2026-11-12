'use strict';
const { createCanonicalAtprotoPgAuthority } =
  require('../utils/atproto-canonical-pg-authority');

function mockPg(response) {
  return {query:jest.fn(async()=>response)};
}
test('only canonical HTTPS owner/app/grant arguments reach PostgreSQL',async()=>{
  const pg=mockPg({rowCount:0,rows:[]});
  const a=createCanonicalAtprotoPgAuthority({pool:pg});
  for(const owner of [
    'http://insecure.example/alice',
    'https://example.test/alice#fragment',
    'https://user:secret@example.test/alice',
    'https://example.test/alice?x=1'
  ]) {
    await expect(a.getConsent({owner,app:'https://paper.example.test/app'}))
      .rejects.toMatchObject({code:'ATPROTO_PG_AUTHORITY_INPUT'});
  }
  expect(pg.query).not.toHaveBeenCalled();
});

test('blocked state from PG cannot be upgraded by caller-supplied RDF values',async()=>{
  const pg=mockPg({rowCount:1,rows:[{
    owner_webid:'https://paper.example.test/alice',
    app_uri:'https://paper.example.test/app',
    grant_uri:'https://paper.example.test/alice/data/grant',
    state:'blocked',revision:'2',
    did:'did:plc:aaaaaaaaaaaaaaaaaaaaaaaa',
    identity_state:'active'
  }]});
  const a=createCanonicalAtprotoPgAuthority({pool:pg});
  const result=await a.getConsent({
    owner:'https://paper.example.test/alice',
    app:'https://paper.example.test/app'
  });
  expect(result.state).toBe('blocked');
  expect(pg.query.mock.calls[0][0]).toContain('paper_atproto_authority.consents');
});

test('revocation rejects zero-row CAS even when database call returns success',async()=>{
  const pg=mockPg({rowCount:0,rows:[]});
  const a=createCanonicalAtprotoPgAuthority({pool:pg});
  await expect(a.revoke({
    owner:'https://paper.example.test/alice',
    app:'https://paper.example.test/app',
    grantUri:'https://paper.example.test/alice/data/grant',
    expectedRevision:'1'
  })).rejects.toMatchObject({code:'ATPROTO_PG_AUTHORITY_STALE'});
});

test('canonical PG authority cannot be opened in production by environment flag',async()=>{
  const name='../utils/atproto-canonical-pg-authority';
  const original={...process.env};
  try{
    process.env.NODE_ENV='production';
    process.env.APODS_ATPROTO_CANONICAL_PG_AUTHORITY_ENABLED='true';
    delete process.env.APODS_ATPROTO_TEST_STORAGE_DISPOSABLE;
    jest.resetModules();
    await expect(require(name).getProviderAtprotoPgAuthority())
      .rejects.toMatchObject({code:'ATPROTO_PG_AUTHORITY_NOT_RELEASED'});
  }finally{
    for(const k of Object.keys(process.env))if(!(k in original))delete process.env[k];
    Object.assign(process.env,original);
    jest.resetModules();
  }
});
