/**
 * NONACTIVATED canonical PostgreSQL consent read with a row lock.
 *
 * Use ONLY with the SAME pg transaction/connection that commits the new
 * signed repository head, MST blocks, native outbox and projection intent.
 * The provider resolves the app and grant from authenticated OIDC/SAI state;
 * a caller must not control this identity binding or its revision.
 */
const DID=/^did:plc:[a-z2-7]{24}$/u;
const REV=/^[1-9][0-9]{0,18}$/u;
const MAX=9223372036854775807n;
function fail(code){
  const e=new Error('Canonical repository-write consent is unavailable');
  e.code=code;throw e;
}
function web(value){
  if(typeof value!=='string'||value.length<8||value.length>2048){
    fail('WRITE_CONSENT_SCOPE_INVALID');
  }
  let u;
  try{u=new URL(value);}catch{fail('WRITE_CONSENT_SCOPE_INVALID');}
  if(u.protocol!=='https:'||!u.hostname||u.href!==value||
     u.username||u.password||u.search||u.hash){
    fail('WRITE_CONSENT_SCOPE_INVALID');
  }
  return value;
}
export function createCanonicalRecordWriteConsentFence({
  appUri,grantUri,consentRevision
}={}){
  web(appUri);web(grantUri);
  if(typeof consentRevision!=='string'||!REV.test(consentRevision)||
     BigInt(consentRevision)>MAX)fail('WRITE_CONSENT_SCOPE_INVALID');
  return async function lockCanonicalConsent(client,{accountId,did}={}){
    web(accountId);
    if(!DID.test(did||'')||typeof client?.query!=='function'){
      fail('WRITE_CONSENT_SCOPE_INVALID');
    }
    // The same connection MUST already be inside BEGIN and hold the signed
    // repo + projection rows FOR UPDATE. A separate pool query would re-open
    // the revocation race, so never create another connection here.
    const r=await client.query(
      'SELECT i.did,i.state AS identity_state,i.managed,'+
      'c.state AS consent_state,c.grant_uri,c.revision::text AS revision '+
      'FROM paper_atproto_authority.consents c '+
      'JOIN paper_atproto_authority.identities i ON i.owner_webid=c.owner_webid '+
      'WHERE c.owner_webid=$1 AND c.app_uri=$2 FOR SHARE OF c,i',
      [accountId,appUri]
    );
    if(r.rowCount!==1||r.rows[0].did!==did||
       r.rows[0].identity_state!=='active'||r.rows[0].managed!==true||
       r.rows[0].consent_state!=='active'||r.rows[0].grant_uri!==grantUri||
       r.rows[0].revision!==consentRevision){
      fail('WRITE_CONSENT_NOT_CURRENT');
    }
    return true;
  };
}
