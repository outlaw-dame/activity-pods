/**
 * NONACTIVATED canonical PostgreSQL consent read with a row lock.
 *
 * Use ONLY with the SAME pg transaction/connection that commits the new
 * signed repository head, MST blocks, native outbox and projection intent.
 * The provider resolves the app and grant from authenticated OIDC/SAI state;
 * a caller must not control this identity binding or its revision.
 */
import crypto from 'node:crypto';
const DID=/^did:plc:[a-z2-7]{24}$/u;
const OAUTH_GRANT=/^[A-Za-z0-9_-]{32}$/u;
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
  appUri,grantUri,consentRevision,restrictedCredential=false,
  oauthEpoch=null
}={}){
  web(appUri);web(grantUri);
  if(typeof restrictedCredential!=='boolean')fail('WRITE_CONSENT_SCOPE_INVALID');
  if(typeof consentRevision!=='string'||!REV.test(consentRevision)||
     BigInt(consentRevision)>MAX)fail('WRITE_CONSENT_SCOPE_INVALID');
  const oauthGate=()=>{
    if(process.env.NODE_ENV!=='test'||
       process.env.PAPER_OAUTH_PG_EPOCH_DISPOSABLE!=='confirmed'||
       process.env.ATPROTO_REPO_WRITER_ROLE_TEST_DISPOSABLE!=='confirmed'||
       restrictedCredential!==true)
      fail('WRITE_OAUTH_EPOCH_NOT_RELEASED');
  };
  let oauthArgs=null;
  if(oauthEpoch!==null){
    oauthGate();
    if(!oauthEpoch||typeof oauthEpoch!=='object'||
       Array.isArray(oauthEpoch)||
       Object.keys(oauthEpoch).sort().join(',')!=='clientId,grantId,revision,scope'||
       !web(oauthEpoch.clientId)||!OAUTH_GRANT.test(oauthEpoch.grantId||'')||
       typeof oauthEpoch.scope!=='string'||oauthEpoch.scope.length<1||
       oauthEpoch.scope.length>8192||
       typeof oauthEpoch.revision!=='string'||!REV.test(oauthEpoch.revision)||
       BigInt(oauthEpoch.revision)>MAX)fail('WRITE_OAUTH_EPOCH_SCOPE_INVALID');
    oauthArgs=Object.freeze({
      clientId:oauthEpoch.clientId,grantId:oauthEpoch.grantId,
      revision:oauthEpoch.revision,
      scopeHash:crypto.createHash('sha256').update(oauthEpoch.scope,'utf8').digest()
    });
  }
  async function lockOauth(client,accountId){
    if(oauthArgs===null)return;
    oauthGate();
    // This SQL locks the exact OAuth and native SAI rows as part of the
    // signed writer's ALREADY-OPEN transaction (never another pool).
    const q=await client.query(
      'SELECT paper_atproto_authority.lock_oauth_generation_for_write('+
      '$1::text,$2::text,$3::text,$4::text,$5::bytea,$6::bigint) AS allowed',
      [accountId,appUri,oauthArgs.clientId,oauthArgs.grantId,
        oauthArgs.scopeHash,oauthArgs.revision]
    );
    if(q.rowCount!==1||q.rows[0].allowed!==true)
      fail('WRITE_OAUTH_EPOCH_NOT_CURRENT');
  }
  return async function lockCanonicalConsent(client,{accountId,did}={}){
    web(accountId);
    if(!DID.test(did||'')||typeof client?.query!=='function'){
      fail('WRITE_CONSENT_SCOPE_INVALID');
    }
    // The same connection MUST already be inside BEGIN and hold the signed
    // repo + projection rows FOR UPDATE. A separate pool query would re-open
    // the revocation race, so never create another connection here.
    if(restrictedCredential){
      // PostgreSQL FOR SHARE requires an UPDATE permission. Do not grant the
      // signed repo worker ANY UPDATE permission on canonical consents.
      // A narrowly scoped SECURITY DEFINER function performs the check and
      // takes the locks as part of this exact caller transaction instead.
      const answer=await client.query(
        'SELECT paper_atproto_authority.lock_writer_consent('+
        '$1,$2,$3,$4,$5::bigint) AS allowed',
        [accountId,did,appUri,grantUri,consentRevision]
      );
      if(answer.rowCount!==1||answer.rows[0].allowed!==true){
        fail('WRITE_CONSENT_NOT_CURRENT');
      }
      await lockOauth(client,accountId);
      return true;
    }
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
    await lockOauth(client,accountId);
    return true;
  };
}
