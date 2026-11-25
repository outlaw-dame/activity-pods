'use strict';
// NONACTIVATED: real isolated PG18 owner/SAI/OAuth/credential join,
// independently challenge-signed credential latest head, restricted LOGIN,
// and deliberately mocked native-Jena/WORM/browser transports.
// Never treat fixture callbacks as a production owner/witness service.
const assert=require('node:assert/strict');
const fs=require('node:fs/promises');
const crypto=require('node:crypto');
const {Pool}=require('pg');
const {createDisposableCredentialHeadAuthority}=
  require('../candidates/credential-signed-latest-head');
const {createDisposableCertifiedCredentialReader}=
  require('../candidates/credential-pg-certified-reader');
const {createDisposablePostEnrollmentOwnerReader}=
  require('../candidates/oauth-post-enrollment-owner-reader.cjs');

const FLAGS=['CI','NODE_ENV','PAPER_OAUTH_POST_ENROLLMENT_DISPOSABLE',
  'PAPER_CREDENTIAL_PG_DISPOSABLE','PAPER_CREDENTIAL_HEAD_DISPOSABLE',
  'PAPER_OAUTH_WITNESS_DISPOSABLE','PAPER_OAUTH_WORM_HIGHWATER_DISPOSABLE'];
if(FLAGS.some(k=>process.env[k]!==({CI:'true',NODE_ENV:'test'}[k]||'confirmed')))
  throw Error('Refusing nondisposable post-enrollment PG18 fixture');
if(process.env.PGHOST!=='127.0.0.1'||process.env.PGPORT!=='5548'||
   process.env.PGDATABASE!=='paper_credential_head_test')
  throw Error('Wrong disposable PG18 fixture endpoint');
const OWNER='https://paper.example.org/users/post-enrollment-owner';
const OTHER='https://paper.example.org/users/other';
const APP='https://paper.example.org/apps/paper';
const CLIENT='https://paper-client.example.org/oauth';
const DID='did:plc:'+'g'.repeat(24);
const GRANT='a'.repeat(32);
const SCOPE='atproto repo:app.bsky.feed.post?action=create';
const OP=crypto.randomUUID();
const B32=crypto.randomBytes(32);
const fixedNow=1800000000;
const DOMAIN=Buffer.from('paper:credential:attest:v1\0');
const user='post_enrollment_reader_'+crypto.randomBytes(5).toString('hex');
const credentialUser='post_enrollment_credential_'+crypto.randomBytes(5).toString('hex');
const secrets=[crypto.randomBytes(20).toString('hex'),crypto.randomBytes(20).toString('hex')];
const ident=s=>'"'+s.replaceAll('"','""')+'"';
const base={host:process.env.PGHOST,port:Number(process.env.PGPORT),
  database:process.env.PGDATABASE};
const admin=new Pool({...base,user:process.env.PGUSER,
  password:process.env.PGPASSWORD,max:1,connectionTimeoutMillis:2500});
let pgPool,credPool,error;
// Use relative paths from the script directory. No filesystem writes.
const read=async name=>fs.readFile(
  require('node:path').join(__dirname,'../sql',name),'utf8');
const expectCode=async(fn,code)=>assert.rejects(fn(),
  e=>e?.code===code,'Expected secure rejection '+code);
const controls={
  live:true,native:true,head:true,witness:true,
  sessionEpoch:'1',credentialSeal:'v'.repeat(43),
  sessionId:'s'.repeat(43),owner:OWNER
};
const head={epoch:'1',state:'active',digest:'0'.repeat(64)};
const {publicKey,privateKey}=crypto.generateKeyPairSync('ed25519');
const headAuthority=createDisposableCredentialHeadAuthority({
  trustedPublicKey:publicKey,authority:'post-enrollment-independent.test',
  fixtureOnly:true,now:()=>fixedNow,
  readHead:async challenge=>{
    if(!controls.head)throw Error('Independent signer offline');
    const body=Buffer.from(JSON.stringify({
      kind:'paper.credential.head.v1',
      authority:'post-enrollment-independent.test',
      subject:challenge.subject,
      epoch:head.epoch,state:head.state,digest:head.digest,
      nonce:challenge.nonce,issuedAt:fixedNow
    }));
    return {body,signature:crypto.sign(null,
      Buffer.concat([DOMAIN,body]),privateKey)};
  }
});
const browser=async()=>{
  if(!controls.live)throw Error('Browser signed cookie/Redis session revoked');
  return {webId:controls.owner,sessionId:controls.sessionId,
    credentialSeal:controls.credentialSeal,
    credentialEpoch:controls.sessionEpoch};
};
const nativeSai={async verifyFresh(){
  return controls.native===true;
}};
const independentWitness={async verify(record){
  return controls.witness===true&&record.canonicalAccountId===OWNER&&
    record.clientId===CLIENT&&record.consentGrantId===GRANT&&
    record.oauthPgRevision==='1';
}};
async function main(){
  const sqlFiles=[
    'paper-credential-epoch-authority-v1.sql',
    'paper-credential-epoch-authority-v2-certified-head.sql',
    'paper-atproto-canonical-authority-v1.sql',
    'paper-atproto-canonical-authority-v2-owner-consent.sql',
    'paper-atproto-canonical-authority-v4-oauth-generations.sql',
    'paper-atproto-canonical-authority-v8-post-enrollment-read.sql'
  ];
  for(const name of sqlFiles)await admin.query(await read(name));
  await admin.query(
    'INSERT INTO paper_credential_epoch.owners(webid,epoch,state)'+
      " VALUES($1,1,'active')",[OWNER]);
  await admin.query(
    'INSERT INTO paper_atproto_authority.identities '+
    '(owner_webid,did,state,managed,revision,source_proof_sha256) '+
    "VALUES($1,$2,'active',true,1,$3)",[OWNER,DID,B32]);
  await admin.query(
    'INSERT INTO paper_atproto_authority.consents '+
    '(owner_webid,app_uri,grant_uri,state,revision,grant_proof_sha256,'+
    'activation_operation,activation_request_sha256,activation_native_readback_at) '+
    "VALUES($1,$2,$3,'active',1,$4,$5,$6,clock_timestamp())",
    [OWNER,APP,OWNER+'/data/grants/paper',B32,OP,B32]);
  await admin.query(
    'INSERT INTO paper_atproto_authority.oauth_generations '+
    '(owner_webid,app_uri,client_id,grant_id,scope_sha256,revision,sai_revision,state) '+
    "VALUES($1,$2,$3,$4,$5,1,1,'active')",
    [OWNER,APP,CLIENT,GRANT,crypto.createHash('sha256').update(SCOPE).digest()]);
  for(const [login,pw,role] of [
    [user,secrets[0],'paper_oauth_post_enrollment_reader'],
    [credentialUser,secrets[1],'paper_credential_reader']
  ]){
    await admin.query('CREATE ROLE '+ident(login)+
      " LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '"+pw+"'");
    await admin.query('GRANT '+ident(role)+' TO '+ident(login)+
      ' WITH INHERIT TRUE,SET FALSE,ADMIN FALSE');
  }
  pgPool=new Pool({...base,user,password:secrets[0],
    max:3,connectionTimeoutMillis:2500});
  credPool=new Pool({...base,user:credentialUser,password:secrets[1],
    max:2,connectionTimeoutMillis:2500});
  const certified=createDisposableCertifiedCredentialReader({
    pool:credPool,headAuthority,fixtureOnly:true
  });
  const options={pool:pgPool,verifyBrowserSession:browser,
    certifiedCredentialReader:certified,nativeSaiReader:nativeSai,
    immutableWitnessReader:independentWitness,
    approvedClients:[CLIENT],fixtureOnly:true};
  const reader=createDisposablePostEnrollmentOwnerReader(options);
  const inspect=(ctx={})=>reader.inspectForDeny({
    context:{...ctx,webId:OTHER,owner:OTHER},
    clientId:CLIENT,expectedGrantId:GRANT
  });
  const initial=await inspect();
  assert.deepEqual(initial,{
    ownerWebId:OWNER,clientId:CLIENT,appUri:APP,grantId:GRANT,
    oauthRevision:'1',saiRevision:'1',credentialEpoch:'1',
    scopeSha256:crypto.createHash('sha256').update(SCOPE).digest('hex')
  });
  // The trusted cookie proof cannot be replaced with a browser-supplied
  // WebID/client/grant ID. A second owner has no selectable authority.
  await expectCode(()=>reader.inspectForDeny({
    context:{webId:OTHER},
    clientId:CLIENT,expectedGrantId:'b'.repeat(32)
  }),'OWNER_POST_ENROLLMENT_GRANT_NOT_CURRENT');
  await expectCode(()=>reader.inspectForDeny({
    context:{webId:OTHER},clientId:'https://evil.example.org/oauth',
    expectedGrantId:GRANT
  }),'OWNER_POST_ENROLLMENT_SCOPE_INVALID');
  const absent=await pgPool.query(
    'SELECT * FROM paper_atproto_authority.current_post_enrollment_owner_grant($1,$2)',
    [OTHER,CLIENT]);
  assert.equal(absent.rowCount,0);
  await assert.rejects(pgPool.query(
    'SELECT * FROM paper_atproto_authority.oauth_generations'),
    e=>e?.code==='42501');
  await assert.rejects(pgPool.query(
    "SELECT paper_atproto_authority.revoke_oauth_generation($1,$2,$3,1)",
    [OWNER,CLIENT,GRANT]),e=>e?.code==='42501');

  controls.native=false;
  await expectCode(inspect,'OWNER_POST_ENROLLMENT_SAI_NOT_CURRENT');
  controls.native=true;
  controls.witness=false;
  await expectCode(inspect,'OWNER_POST_ENROLLMENT_WITNESS_NOT_CURRENT');
  controls.witness=true;
  controls.head=false;
  await expectCode(inspect,'OWNER_POST_ENROLLMENT_CREDENTIAL_NOT_CURRENT');
  controls.head=true;
  controls.live=false;
  await expectCode(inspect,'OWNER_POST_ENROLLMENT_SESSION_INVALID');
  controls.live=true;
  controls.sessionEpoch='2';
  await expectCode(inspect,'OWNER_POST_ENROLLMENT_CREDENTIAL_NOT_CURRENT');
  controls.sessionEpoch='1';

  // A password change in progress suspends PG credential admission.
  await admin.query(
    "UPDATE paper_credential_epoch.owners SET state='pending',"+
    'operation_id=$2,next_epoch=2,mutation_digest=NULL WHERE webid=$1',
    [OWNER,crypto.randomUUID()]);
  head.state='pending';
  await expectCode(inspect,'OWNER_POST_ENROLLMENT_CREDENTIAL_NOT_CURRENT');
  await admin.query(
    "UPDATE paper_credential_epoch.owners SET state='active',"+
    'epoch=2,operation_id=NULL,next_epoch=NULL WHERE webid=$1',[OWNER]);
  head.state='active';head.epoch='2';
  await expectCode(inspect,'OWNER_POST_ENROLLMENT_CREDENTIAL_NOT_CURRENT');
  // Only a new, independently verified credential-epoch-bound login passes.
  controls.sessionEpoch='2';
  controls.credentialSeal='w'.repeat(43);
  controls.sessionId='q'.repeat(43);
  assert.equal((await inspect()).credentialEpoch,'2');

  // Primary SQL (or physical PITR) returning to old epoch is rejected by the
  // independently challenge-signed latest credential head, even if the
  // signed browser session remains present in Redis.
  await admin.query(
    'UPDATE paper_credential_epoch.owners SET epoch=1 WHERE webid=$1',[OWNER]);
  await expectCode(inspect,'OWNER_POST_ENROLLMENT_CREDENTIAL_NOT_CURRENT');
  await admin.query(
    'UPDATE paper_credential_epoch.owners SET epoch=2 WHERE webid=$1',[OWNER]);
  assert.equal((await inspect()).credentialEpoch,'2');

  // Revocation/SAI permission changes between readback passes deny.
  let raced=false;
  const racingReader=createDisposablePostEnrollmentOwnerReader({
    ...options,nativeSaiReader:{
      async verifyFresh(){
        if(!raced){
          raced=true;
          await admin.query(
            "UPDATE paper_atproto_authority.consents SET state='blocked',revision=2"+
            ' WHERE owner_webid=$1 AND app_uri=$2',[OWNER,APP]);
        }
        return true;
      }
    }
  });
  await expectCode(()=>racingReader.inspectForDeny({
    context:{},clientId:CLIENT,expectedGrantId:GRANT
  }),'OWNER_POST_ENROLLMENT_GRANT_NOT_CURRENT');
  assert.equal(raced,true);

  // Harden the actual restricted login: extra issuer/revoker role membership
  // (even with SET ROLE disabled) invalidates every subsequent read.
  await admin.query('GRANT paper_oauth_epoch_revoker TO '+ident(user)+
    ' WITH INHERIT TRUE,SET FALSE,ADMIN FALSE');
  await expectCode(inspect,'OWNER_POST_ENROLLMENT_ROLE_UNSAFE');
  await admin.query('REVOKE paper_oauth_epoch_revoker FROM '+ident(user));

  // A blocked canonical grant is denied independently of native callbacks.
  await admin.query(
    "UPDATE paper_atproto_authority.oauth_generations SET state='blocked',revision=2"+
    ' WHERE owner_webid=$1 AND client_id=$2',[OWNER,CLIENT]);
  await expectCode(inspect,'OWNER_POST_ENROLLMENT_GRANT_NOT_CURRENT');
  console.log('PASS: real PG18 managed WebID/SAI/OAuth/credential join, signed Ed25519 latest credential head, restricted reader, browser epoch, SAI and revocation race; NONACTIVATED');

}
async function run(){
  try{await main()}
  catch(e){error=e;process.exitCode=1;console.error(e?.stack||String(e))}
  finally{
    for(const p of [pgPool,credPool])if(p)await p.end().catch(()=>{});
    const failures=[];
    const clean=async s=>{try{await admin.query(s)}catch(e){failures.push(e)}};
    await clean('DROP SCHEMA IF EXISTS paper_atproto_authority CASCADE');
    await clean('DROP SCHEMA IF EXISTS paper_credential_epoch CASCADE');
    for(const login of [user,credentialUser])await clean('DROP ROLE IF EXISTS '+ident(login));
    for(const role of [
      'paper_oauth_post_enrollment_reader','paper_oauth_epoch_issuer',
      'paper_oauth_epoch_revoker','paper_oauth_epoch_reader','paper_oauth_epoch_signer',
      'paper_atproto_consent_issuer','paper_atproto_consent_attestor',
      'paper_atproto_authority_reader','paper_atproto_authority_revoker',
      'paper_atproto_authority_importer','paper_credential_reader',
      'paper_credential_enroller','paper_credential_coordinator'
    ])await clean('DROP ROLE IF EXISTS '+ident(role));
    await admin.end().catch(()=>{});
    if(failures.length&&!error){
      process.exitCode=1;console.error('Fixture cleanup failed:',failures[0]?.message);
    }
  }
}
run().catch(e=>{console.error(e);process.exitCode=1});
