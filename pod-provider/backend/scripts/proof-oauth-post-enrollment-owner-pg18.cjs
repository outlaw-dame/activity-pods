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
const CERT_EPOCH='1';
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
const sql=path=>fs.readFile(new URL(path,__filename.startsWith('file:')
  ?__filename:'file://'+__filename),'utf8');
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
  assert.equal(await admin.query('SELECT count(*)::int AS n FROM paper_credential_epoch.owners'),
    undefined,'unreachable');
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
