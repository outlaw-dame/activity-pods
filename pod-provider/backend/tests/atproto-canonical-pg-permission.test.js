'use strict';

const { createCanonicalAtprotoPgAuthority } =
  require('../utils/atproto-canonical-pg-authority');

const owner='https://paper.example.test/users/alice';
const app='https://paper.example.test/apps/writer';
const grant=owner+'/data/access-grants/repo';
const did='did:plc:aaaaaaaaaaaaaaaaaaaaaaaa';
const approved={
  did,identity_state:'active',consent_state:'active',
  grant_uri:grant,consent_revision:'1'
};
function authority(row=approved,rows=1){
  const pool={query:jest.fn(async()=>({
    rowCount:rows,rows:rows ? [row]:[]
  }))};
  return { api:createCanonicalAtprotoPgAuthority({pool}),pool };
}
function request(){
  return {owner,app,grantUri:grant,did,consentRevision:'1'};
}

test('canonical grant is verified by one indexed PG lookup, not mutable RDF', async()=>{
  const {api,pool}=authority();
  await expect(api.verifyActiveGrant(request())).resolves.toBe(true);
  expect(pool.query).toHaveBeenCalledTimes(1);
  const [sql,params]=pool.query.mock.calls[0];
  expect(sql).toMatch(/WHERE c.owner_webid=\$1 AND c.app_uri=\$2 LIMIT 2/u);
  expect(sql).toMatch(/paper_atproto_authority\.consents/u);
  expect(params).toEqual([owner,app]);
});

test.each([
  ['revoked consent',{consent_state:'blocked'}],
  ['deactivated identity',{identity_state:'blocked'}],
  ['different managed DID',{did:'did:plc:bbbbbbbbbbbbbbbbbbbbbbbb'}],
  ['different grant',{grant_uri:owner+'/data/access-grants/other'}],
  ['older consent revision',{consent_revision:'2'}],
])('canonical permission denies %s after exact-row lookup',async(_,change)=>{
  const {api}=authority({...approved,...change});
  await expect(api.verifyActiveGrant(request()))
    .rejects.toMatchObject({code:'ATPROTO_PG_PERMISSION_DENIED'});
});

test('missing or ambiguous canonical authority refuses authorization',async()=>{
  const no=authority(null,0);
  await expect(no.api.verifyActiveGrant(request()))
    .rejects.toMatchObject({code:'ATPROTO_PG_PERMISSION_DENIED'});
  const many=authority(approved,2);
  await expect(many.api.verifyActiveGrant(request()))
    .rejects.toMatchObject({code:'ATPROTO_PG_PERMISSION_DENIED'});
});

test.each([
  [{owner:'http://paper.example.test/users/alice'},'ATPROTO_PG_AUTHORITY_INPUT'],
  [{app:'https://paper.example.test/apps/writer?owner=other'},'ATPROTO_PG_AUTHORITY_INPUT'],
  [{grantUri:'https://user:secret@paper.example.test/grant'},'ATPROTO_PG_AUTHORITY_INPUT'],
  [{did:'did:plc:not-valid'},'ATPROTO_PG_PERMISSION_SCOPE_INVALID'],
  [{consentRevision:'01'},'ATPROTO_PG_AUTHORITY_EPOCH'],
])('malformed canonical authorization is rejected without any query',async(change,code)=>{
  const {api,pool}=authority();
  await expect(api.verifyActiveGrant({...request(),...change}))
    .rejects.toMatchObject({code});
  expect(pool.query).not.toHaveBeenCalled();
});

test('a PostgreSQL outage does not turn a failure into authorization',async()=>{
  const pool={query:jest.fn(async()=>{throw new Error('database outage')})};
  const api=createCanonicalAtprotoPgAuthority({pool});
  await expect(api.verifyActiveGrant(request())).rejects.toThrow('database outage');
  expect(pool.query).toHaveBeenCalledTimes(1);
});
