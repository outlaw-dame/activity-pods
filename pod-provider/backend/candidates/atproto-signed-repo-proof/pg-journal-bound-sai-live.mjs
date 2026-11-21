/** Disposable PostgreSQL18 journal-bound new-account SAI consent acceptance.
 * Uses REAL candidate account v1-v4/v6, reservation/bridge and canonical
 * identity/consent v1-v3 schemas. Never opens the production signup fuse.
 */
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {readFile} from 'node:fs/promises';
import {Client,Pool} from 'pg';
import {createRequire} from 'node:module';
import {createDisposableNativeSaiReader} from './native-sai-pg-consent-attestor.mjs';
import {createSignedRepoProofStore} from './store.mjs';
import {createSignedSingleRecordWriter} from './single-record-writer.mjs';
import {verifySignedSingleRecordSnapshot} from './signed-single-record.mjs';
import {createDisposableJournalBoundSaiAttestor} from './journal-bound-sai-pg-attestor.mjs';
const require=createRequire(import.meta.url);
const {createCanonicalAtprotoPgAuthority}=require('../../utils/atproto-canonical-pg-authority.js');
const {createDisposableJournalBoundConsentIssuer}=require('../journal-bound-consent-issuer');
const DSN='postgres://paper_probe:probe_local_only@127.0.0.1:5548/atproto_signed_repo_proof_test';
if(process.env.NODE_ENV!=='test'||
 process.env.PAPER_JOURNAL_BOUND_SAI_DISPOSABLE!=='confirmed'||
 process.env.ATPROTO_REPO_PROOF_DISPOSABLE!=='confirmed'||
 process.env.ATPROTO_REPO_PROOF_DSN!==DSN)throw Error('Test-only PG18 journal authority');
const root=new URL('../../sql/',import.meta.url),here=new URL('./',import.meta.url);
const realJena=process.env.PAPER_JOURNAL_BOUND_SAI_JENA==='confirmed';
const JENA='http://127.0.0.1:3041';
if((process.env.PAPER_JOURNAL_BOUND_SAI_JENA &&
    process.env.PAPER_JOURNAL_BOUND_SAI_JENA!=='confirmed')||
   (realJena&&(process.env.ATPROTO_SAI_ACTIVATION_DISPOSABLE!=='confirmed'||
     process.env.ATPROTO_FUSEKI_ISOLATION_DISPOSABLE!=='confirmed'||
     process.env.FUSEKI_ISOLATION_URL!==JENA))){
 throw Error('Journal-bound Jena requires exact isolated disposable authority');
}
const scripts=[
 new URL('paper-account-postgres-candidate-v1.sql',root),
 new URL('paper-account-postgres-candidate-v2-signup-ledger.sql',root),
 new URL('paper-account-postgres-candidate-v3-evidence-seal.sql',root),
 new URL('paper-account-postgres-candidate-v4-atomic-completion.sql',root),
 new URL('paper-account-postgres-candidate-v6-enrollment.sql',root),
 new URL('paper-atproto-canonical-authority-v1.sql',root),
 new URL('paper-atproto-canonical-authority-v2-owner-consent.sql',root),
 new URL('pg-preaccount-reservations.sql',here),
 new URL('schema.sql',here),
 new URL('single-record-mutation.sql',here),
 new URL('pg-v4-reservation-completion-bridge.sql',here),
 new URL('paper-atproto-canonical-authority-v3-bound-enrollment.sql',root),
 new URL('paper-atproto-canonical-authority-v4-oauth-generations.sql',root),
 new URL('paper-atproto-canonical-authority-v7-session-oauth.sql',root)
];
const schemas=['paper_atproto_authority','paper_atproto_repo_proof',
 'paper_account_reservation_proof','paper_account_candidate'];
const memberships={issuer:'paper_atproto_consent_issuer',
 attestor:'paper_atproto_consent_attestor',
 attestor2:'paper_atproto_consent_attestor',
 revoker:'paper_atproto_authority_revoker',
 revoker2:'paper_atproto_authority_revoker',
 oauthissuer:'paper_oauth_epoch_issuer',
 oauthrevoker:'paper_oauth_epoch_revoker',ordinary:null};
const cleanupRoles=[
 'paper_atproto_consent_issuer','paper_atproto_consent_attestor',
 'paper_atproto_authority_reader','paper_atproto_authority_revoker',
 'paper_atproto_authority_importer','paper_enrollment_runtime',
 'paper_account_proof_worker','paper_account_proof_issuer',
 'paper_account_bridge_binder','paper_account_bridge_finalizer',
 'paper_oauth_epoch_issuer','paper_oauth_epoch_revoker',
 'paper_oauth_epoch_reader','paper_oauth_epoch_signer'
];
const label=crypto.randomBytes(5).toString('hex');
const names=Object.fromEntries(Object.keys(memberships).map(k=>[k,'paper_sai_journal_'+k+'_'+label]));
const passwords=Object.fromEntries(Object.keys(memberships).map(k=>[k,crypto.randomBytes(32).toString('hex')]));
const admin=new Client({connectionString:DSN,connectionTimeoutMillis:3000,query_timeout:6500});
const clients=[];
const sha=s=>crypto.createHash('sha256').update(s).digest();
const uuid=()=>crypto.randomUUID();
const ident=s=>{assert.match(s,/^[a-z_][a-z0-9_]{0,62}$/u);return '"'+s+'"';};
const base='https://paper.example.org',app='https://app-e2e.test:3443/app';
const approvedAppScope=sha('activitypods:approved-app:v1\0'+app).toString('hex');
const rights=['apods:CreateGroup','apods:ReadGroups','apods:ManageMembers'];
const a=(name,letter)=>({
 name,owner:base+'/'+name,did:'did:plc:'+letter.repeat(24),
 account:uuid(),operation:uuid(),reservation:uuid(),
 key:sha('key:'+name),request:sha('request:'+name),
 tokenHash:sha('token:'+name),
 registration:base+'/'+name+'/data/app-registrations/native',
 grant:base+'/'+name+'/data/access-grants/native'
});
const owner=a('paperjournal01','k'),incomplete=a('paperjournal02','l'),pending=a('paperjournal03','m');
const overbroad=a('paperjournal04','n'),wrongKind=a('paperjournal05','p');
let digest=sha('native-jena-typed-rights:confirmed');
const INTEROP='http://www.w3.org/ns/solid/interop#';
const APODS='http://activitypods.org/ns/core#';
const iri=x=>'<'+x+'>';
const nativeRights=rights.map(x=>APODS+x.slice('apods:'.length));
const needGroup='https://app-e2e.test:3443/access-need';
function nativeGraph(actor){
 const registry=actor.owner+'/data/agent-registry';
 const set=actor.owner+'/data/registry-set';
 return [
   iri(actor.owner)+' '+iri(INTEROP+'hasRegistrySet')+' '+iri(set)+' .',
   iri(set)+' '+iri(INTEROP+'hasAgentRegistry')+' '+iri(registry)+' .',
   iri(registry)+' '+iri(INTEROP+'hasApplicationRegistration')+' '+iri(actor.registration)+' .',
   iri(actor.registration)+' a '+iri(INTEROP+'ApplicationRegistration')+' ;',
   ' '+iri(INTEROP+'registeredBy')+' '+iri(actor.owner)+' ;',
   ' '+iri(INTEROP+'registeredAgent')+' '+iri(app)+' ;',
   ' '+iri(INTEROP+'hasAccessGrant')+' '+iri(actor.grant)+' .',
   iri(actor.grant)+' a '+iri(INTEROP+'AccessGrant')+' ;',
   ' '+iri(INTEROP+'grantedBy')+' '+iri(actor.owner)+' ;',
   ' '+iri(INTEROP+'grantee')+' '+iri(app)+' ;',
   ' '+iri(INTEROP+'hasAccessNeedGroup')+' '+iri(needGroup)+' ;',
   ' '+iri(APODS+'hasSpecialRights')+' '+nativeRights.map(iri).join(', ')+' .'
 ].join('\n');
}
async function projectJena(update){
 const res=await fetch(JENA+'/protected-proof/update',{
  method:'POST',redirect:'error',signal:AbortSignal.timeout(7000),
  headers:{authorization:'Basic '+Buffer.from(
   'fixture-projector:fixture-projector-only').toString('base64'),
   'content-type':'application/sparql-update'},body:update});
 if(![200,204].includes(res.status))throw Error('Protected native Jena UPDATE rejected');
 await res.body?.cancel().catch(()=>{});
}
const failDigest=sha('native-jena-drifted');
async function login(kind){
 const url=new URL(DSN);url.username=names[kind];url.password=passwords[kind];
 const c=new Client({connectionString:url.toString(),connectionTimeoutMillis:3000,query_timeout:6500});
 await c.connect();clients.push(c);
 assert.equal((await c.query('SELECT current_user AS name')).rows[0].name,names[kind]);
 return c;
}
async function denied(c,sql,args=[]){
 await assert.rejects(c.query(sql,args),e=>e?.code==='42501');
}
async function call(c,fn,args,types){
 const r=await c.query('SELECT paper_atproto_authority.'+fn+
  '('+args.map((_,i)=>'$'+(i+1)+'::'+types[i]).join(',')+') AS allowed',args);
 assert.equal(r.rowCount,1);return r.rows[0].allowed;
}
const begin=(db,actor)=>call(db,'begin_session_owner_consent',
 [actor.provider||base,actor.origin||'https://app-e2e.test:3443',actor.tokenHash],
 ['text','text','bytea']);
const attest=(db,actor,registration=actor.registration,grant=actor.grant,proof=digest)=>
 call(db,'attest_bound_owner_consent',
 [actor.reservation,actor.operation,registration,grant,proof],
 ['uuid','uuid','text','text','bytea']);
const confirm=(db,actor,registration=actor.registration,grant=actor.grant,proof=digest)=>
 call(db,'confirm_bound_owner_consent',
 [actor.reservation,actor.operation,registration,grant,proof],
 ['uuid','uuid','text','text','bytea']);
async function seed(actor,selected=rights){
 const req={revision:'a'.repeat(64),required:rights,optional:[]};
 const choice={acceptedSpecialRights:selected,acceptedAccessNeeds:[]};
 await admin.query('INSERT INTO paper_account_candidate.accounts '+
  '(account_id,provider_id,username_key,webid,activitypub_actor_uri,atproto_did,'+
  'atproto_handle,atproto_pds_url,atproto_repo_initialized,state,generation) '+
  "VALUES($1,$2,$3,$4,$4,$5,$6,$7,true,'provisioning',2)",
  [actor.account,base,actor.name,actor.owner,actor.did,
   actor.name+'.paper.example.org','https://pds.paper.example.org']);
 await admin.query('INSERT INTO paper_account_candidate.signup_operations '+
  '(operation_id,provider_id,account_id,app_client_id,hmac_key_version,'+
  'idempotency_hmac,request_hmac,state,generation,may_have_side_effects,'+
  'enrollment_token_hash,enrollment_csrf_hash,enrollment_origin,'+
  'enrollment_app_uri,enrollment_return_uri,enrollment_requirements,'+
  'enrollment_expires_at,enrollment_state,enrollment_selection) '+
  "VALUES($1,$2,$3,$4,1,$5,$6,'reconciliation_required',2,true,"+
  "$7,$8,$9,$10,$11,$12,clock_timestamp()+interval '10 minutes','consent_claimed',$13)",
  [actor.operation,base,actor.account,app,actor.key,actor.request,
   actor.tokenHash,sha('csrf:'+actor.name),'https://app-e2e.test:3443',
   app,'https://app-e2e.test:3443/callback',JSON.stringify(req),JSON.stringify(choice)]);
 await admin.query('INSERT INTO paper_account_reservation_proof.reservations '+
  '(provider_id,app_client_id,idempotency_hash,request_hash,username,expected_webid,'+
  'reservation_id,state,lease_expires_at,started_at,signup_claimed_at,'+
  'v4_provider_id,v4_app_client_id,v4_account_id,v4_operation_id,v4_hmac_key_version,'+
  'v4_idempotency_hmac,v4_request_hmac,v4_bound_at) '+
  "VALUES($1,$2,$3,$4,$5,$6,$7,'side_effects_started',"+
  "clock_timestamp()+interval '10 minutes',clock_timestamp(),clock_timestamp(),"+
  '$8,$9,$10,$11,1,$12,$13,clock_timestamp())',
  [base+'/provider',approvedAppScope,sha('resv-key:'+actor.name),
   sha('resv-request:'+actor.name),actor.name,actor.owner,actor.reservation,
   base,app,actor.account,actor.operation,actor.key,actor.request]);
 await admin.query('INSERT INTO paper_atproto_authority.identities '+
  '(owner_webid,did,state,managed,revision,source_proof_sha256) '+
  "VALUES($1,$2,'active',true,1,$3)",[actor.owner,actor.did,sha('managed:'+actor.name)]);
}
async function journalRecorded(actor){
 await admin.query("UPDATE paper_account_candidate.signup_operations "+
  "SET enrollment_state='consent_recorded',enrollment_registration_uri=$1 "+
  'WHERE operation_id=$2',[actor.registration,actor.operation]);
}
async function state(actor){
 const r=await admin.query('SELECT state,revision::text AS revision,grant_uri '+
  'FROM paper_atproto_authority.consents WHERE owner_webid=$1',[actor.owner]);
 return r.rows[0]||null;
}
let created=false,originalError,jenaWritten=false;
await admin.connect();
try{
 for(const schema of schemas){
  const result=await admin.query('SELECT to_regnamespace($1) AS name',[schema]);
  assert.equal(result.rows[0].name,null,'Refuse test against existing '+schema);
 }
 created=true;
 for(const script of scripts)await admin.query(await readFile(script,'utf8'));
 for(const [kind,member] of Object.entries(memberships)){
  await admin.query('CREATE ROLE '+ident(names[kind])+
   " LOGIN PASSWORD '"+passwords[kind]+"' "+
   'NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS');
  if(member)await admin.query('GRANT '+ident(member)+' TO '+ident(names[kind])+
   ' WITH INHERIT TRUE,SET FALSE,ADMIN FALSE');
 }
 const [issuer,attestor,attestor2,revoker,revoker2,
  oauthissuer,oauthrevoker,ordinary]=
  await Promise.all(Object.keys(memberships).map(login));
 for(const c of [issuer,attestor,ordinary]){
  await denied(c,'UPDATE paper_atproto_authority.consents SET state=$1',['active']);
  await denied(c,'SELECT * FROM paper_atproto_authority.bound_signup_owner_scope($1,$2,$3)',
   [owner.reservation,owner.operation,'begin']);
 }
 await denied(issuer,'SELECT paper_atproto_authority.begin_owner_consent($1,$2,$3,$4,$5)',
  [owner.owner,owner.did,app,owner.operation,digest]);
 await denied(attestor,'SELECT paper_atproto_authority.attest_owner_consent($1,$2,$3,$4,$5,$6)',
  [owner.owner,owner.did,app,owner.operation,owner.grant,digest]);
 await denied(ordinary,'SELECT paper_atproto_authority.begin_bound_owner_consent($1,$2)',
  [owner.reservation,owner.operation]);
 await denied(issuer,'SELECT paper_atproto_authority.begin_bound_owner_consent($1,$2)',
  [owner.reservation,owner.operation]);
 await denied(issuer,'SELECT paper_atproto_authority.attest_bound_owner_consent($1,$2,$3,$4,$5)',
  [owner.reservation,owner.operation,owner.registration,owner.grant,digest]);
 await denied(attestor,'SELECT paper_atproto_authority.begin_bound_owner_consent($1,$2)',
  [owner.reservation,owner.operation]);
 await seed(owner);await seed(incomplete,rights.slice(0,2));await seed(pending);
 await seed(overbroad,[...rights,'apods:UpdateWebId']);
 await seed(wrongKind);
 await admin.query('UPDATE paper_account_candidate.signup_operations '+
  'SET enrollment_selection=$1 WHERE operation_id=$2',[
   JSON.stringify({acceptedSpecialRights:rights,
    acceptedAccessNeeds:['apods:CreateGroup']}),wrongKind.operation
  ]);
 assert.equal(await begin(issuer,overbroad),false,
  'Unadvertised native special rights must never issue pending authority');
 assert.equal(await begin(issuer,wrongKind),false,
  'Native group rights cannot be smuggled into acceptedAccessNeeds');
 assert.equal(await state(overbroad),null);
 assert.equal(await state(wrongKind),null);
 // The actual issuer borrows a PG session for both role audit and CAS;
 // a shared pg.Client cannot satisfy its lease/release discipline.
 const issuerDsn=new URL(DSN);
 issuerDsn.username=names.issuer;issuerDsn.password=passwords.issuer;
 const issuerPool=new Pool({connectionString:issuerDsn.toString(),max:2,
  connectionTimeoutMillis:2500,query_timeout:5500,idleTimeoutMillis:2500,
  allowExitOnIdle:true});
 clients.push(issuerPool);
 const issuerApi=createDisposableJournalBoundConsentIssuer({
  pool:issuerPool,providerId:base,browserOrigin:'https://app-e2e.test:3443',
  fixtureOnly:true
 });
 await assert.rejects(issuerApi.reserve({
  providerId:base,origin:'https://attacker.example.org',tokenHash:owner.tokenHash
 }),e=>e?.code==='OWNER_CONSENT_ISSUER_SCOPE_INVALID');
 // A forged app-scope alias in a previously bridged reservation is not
 // sufficient just because its copied v4_app_client_id still matches.
 await admin.query('UPDATE paper_account_reservation_proof.reservations '+
   'SET app_client_id=$1 WHERE reservation_id=$2',
   ['forged-approved-app-scope',owner.reservation]);
 assert.equal(await begin(issuer,owner),false,
   'App-scope hash mismatch must prevent initial authorization');
 await admin.query('UPDATE paper_account_reservation_proof.reservations '+
   'SET app_client_id=$1 WHERE reservation_id=$2',
   [approvedAppScope,owner.reservation]);
 assert.equal(await begin(issuer,{...owner,origin:'https://attacker.example.org'}),false,
  'Unrelated browser origin cannot begin another owner consent');
 assert.equal(await begin(issuer,{...owner,tokenHash:sha('forged-session')}),false);
 assert.equal(await begin(issuer,{...owner,provider:'https://another.example.org'}),false);
 assert.equal(await begin(issuer,incomplete),false,'Missing ManageMembers must fail');
 assert.equal(await state(incomplete),null);
 assert.equal(await issuerApi.reserve({
  providerId:base,origin:'https://app-e2e.test:3443',tokenHash:owner.tokenHash
 }),true,'Real restricted issuer grants only canonical pending owner consent');
 assert.equal(await begin(issuer,owner),true,'Idempotent lost BEGIN acknowledgement');
 assert.equal((await state(owner)).state,'pending');
 const api=createCanonicalAtprotoPgAuthority({pool:revoker});
 await assert.rejects(api.verifyActiveGrant({
  owner:owner.owner,app,did:owner.did,grantUri:owner.grant,consentRevision:'1'
 }),e=>e?.code==='ATPROTO_PG_PERMISSION_DENIED');
 assert.equal(await attest(attestor,owner),false,'No native registration recorded yet');
 await journalRecorded(owner);
 assert.equal(await attest(attestor,owner,owner.registration+'-forged'),false);
 assert.equal(await attest(attestor,{...owner,operation:incomplete.operation}),false);
 assert.equal(await attest(attestor,owner,owner.registration,'https://evil.example/grant'),false);
 // Digest is tied to immutable enrollment selection + required app manifest.
 const initialChoice={acceptedSpecialRights:rights,acceptedAccessNeeds:[]};
 await admin.query('UPDATE paper_account_candidate.signup_operations SET enrollment_selection=$1 WHERE operation_id=$2',
  [JSON.stringify({acceptedSpecialRights:[...rights,'apods:UpdateWebId'],acceptedAccessNeeds:[]}),owner.operation]);
 assert.equal(await attest(attestor,owner),false,'Consent selection drift invalidates receipt');
 await admin.query('UPDATE paper_account_candidate.signup_operations SET enrollment_selection=$1 WHERE operation_id=$2',
  [JSON.stringify(initialChoice),owner.operation]);
 if(realJena){
  await projectJena('INSERT DATA { '+nativeGraph(owner)+' }');
  jenaWritten=true;
  const read=createDisposableNativeSaiReader({
   origin:JENA,username:'fixture-attestor',
   password:'fixture-attestor-only',fixtureOnly:true
  });
  const attestorDsn=new URL(DSN);
  attestorDsn.username=names.attestor;attestorDsn.password=passwords.attestor;
  const attestorPool=new Pool({connectionString:attestorDsn.toString(),max:2,
   connectionTimeoutMillis:2500,query_timeout:5500,idleTimeoutMillis:2500,
   allowExitOnIdle:true});
  clients.push(attestorPool);
  const trusted=await createDisposableJournalBoundSaiAttestor({
   pool:attestorPool,readNativeSai:read,fixtureOnly:true,
   config:{owner:owner.owner,app,needGroup,requiredRights:nativeRights}
  });
  const independentlyRead=await trusted.inspect();
  assert.equal(independentlyRead.registration,owner.registration);
  assert.equal(independentlyRead.grant,owner.grant);
  digest=independentlyRead.digest;
  const admitted=await trusted.attest({
   reservationId:owner.reservation,operationId:owner.operation
  });
  assert.equal(admitted.status,'evidence_only');
  assert.equal(admitted.evidenceSha256,digest.toString('hex'));
  assert.equal(await attest(attestor2,owner),true,'Attestor retry after exact native Jena readback');
 }else{
  assert.deepEqual(await Promise.all([attest(attestor,owner),attest(attestor2,owner)]),
   [true,true],'Two independent PG attestors recover identical evidence');
 }
 assert.equal(await confirm(attestor,owner),true);
 assert.equal(await confirm(attestor,owner,owner.registration,owner.grant,failDigest),false);
 // The only OAuth issuer API now derives owner, DID, app/client and SAI
 // revision directly from the same *authenticated owner enrollment token*
 // used to create native consent. The SQL roles cannot choose a WebID.
 const oauthGrant=crypto.randomBytes(24).toString('base64url');
 const oauthGrant2=crypto.randomBytes(24).toString('base64url');
 const oauthScope='atproto repo:app.bsky.feed.post?action=create';
 const issue=(actor,grantId,scope,expected)=>call(oauthissuer,
  'issue_session_oauth_generation',
  [actor.provider||base,actor.origin||'https://app-e2e.test:3443',
   actor.tokenHash,grantId,scope,expected],
  ['text','text','bytea','text','text','bigint']);
 const revokeOAuth=(actor,grantId,expected)=>call(oauthrevoker,
  'revoke_session_oauth_generation',
  [actor.provider||base,actor.origin||'https://app-e2e.test:3443',
   actor.tokenHash,grantId,expected],
  ['text','text','bytea','text','bigint']);
 await denied(oauthissuer,
  'SELECT paper_atproto_authority.issue_oauth_generation('+
  '$1,$2,$3,$4,$5,$6,$7)',
  [owner.owner,app,app,oauthGrant,sha(oauthScope),0,1]);
 await denied(oauthrevoker,
  'SELECT paper_atproto_authority.revoke_oauth_generation($1,$2,$3,$4)',
  [owner.owner,app,oauthGrant,1]);
 await denied(ordinary,
  'SELECT paper_atproto_authority.issue_session_oauth_generation('+
  '$1,$2,$3,$4,$5,$6)',
  [base,'https://app-e2e.test:3443',owner.tokenHash,oauthGrant,oauthScope,0]
 );
 assert.equal(await issue(incomplete,oauthGrant,oauthScope,0),'0',
  'No attested consent for another owner');
 assert.equal(await issue({...owner,tokenHash:sha('forged-token')},oauthGrant,
  oauthScope,0),'0');
 assert.equal(await issue({...owner,origin:'https://evil.example.org'},oauthGrant,
  oauthScope,0),'0');
 assert.equal(await issue(owner,oauthGrant,'atproto repo:*',0),'0',
  'Owner cannot authorize a wildcard scope outside reviewed manifest');
 assert.equal(await issue(owner,oauthGrant,oauthScope,0),'1');
 assert.equal(await issue(owner,oauthGrant,oauthScope,0),'0',
  'Replay cannot mint second credential');
 const actual=(await admin.query('SELECT owner_webid,app_uri,client_id,'+
  'revision::text,encode(scope_sha256,\'hex\') AS scope_sha,state '+
  'FROM paper_atproto_authority.oauth_generations WHERE owner_webid=$1',
  [owner.owner])).rows[0];
 assert.equal(actual.owner_webid,owner.owner);
 assert.equal(actual.app_uri,app);
 assert.equal(actual.client_id,app);
 assert.equal(actual.scope_sha,sha(oauthScope).toString('hex'));
 assert.equal(actual.revision,'1');assert.equal(actual.state,'active');
 assert.equal(await revokeOAuth({...owner,tokenHash:sha('wrong')},
   oauthGrant,1),'0');
 assert.equal(await revokeOAuth(owner,oauthGrant,1),'2');
 assert.equal(await revokeOAuth(owner,oauthGrant,1),'0',
   'Revocation may not acknowledge twice');
 assert.equal(await issue(owner,oauthGrant2,oauthScope,2),'3',
   'Fresh authenticated approval may rotate a revoked generation');
 // POSITIVE CROSS-PROTOCOL CONSISTENCY FIXTURE (not hosted signup).
 // The account was written via the canonical journal and the new owner-
 // bound native SAI grant was independently attested above.
 const linked=(await admin.query(
  'SELECT webid,activitypub_actor_uri,atproto_did,atproto_handle,'+
  'atproto_pds_url,atproto_repo_initialized FROM '+
  'paper_account_candidate.accounts WHERE account_id=$1',[owner.account]
 )).rows[0];
 assert.equal(linked.webid,owner.owner);
 assert.equal(linked.activitypub_actor_uri,owner.owner);
 assert.equal(linked.atproto_did,owner.did);
 assert.equal(linked.atproto_repo_initialized,true);
 assert.equal(linked.atproto_handle,owner.name+'.paper.example.org');
 assert.equal(linked.atproto_pds_url,'https://pds.paper.example.org');
 assert.equal(await confirm(attestor,owner),true);
 const repoPool=new Pool({connectionString:DSN,max:3,
  connectionTimeoutMillis:3000,query_timeout:6500,
  idleTimeoutMillis:2500,allowExitOnIdle:true});
 clients.push(repoPool);
 const {privateKey,publicKey}=crypto.generateKeyPairSync('ec',{
  namedCurve:'secp256k1'});
 const signing={
  publicKeyPem:publicKey.export({type:'spki',format:'pem'}).toString(),
  signer:async bytes=>crypto.sign('sha256',bytes,{
   key:privateKey,dsaEncoding:'ieee-p1363'})
 };
 const repo=createSignedRepoProofStore({pool:repoPool,fixtureOnly:true});
 const genesis=await repo.bootstrap({
  accountId:owner.owner,did:owner.did,...signing
 });
 assert.equal(genesis.verified,true);
 assert.equal(genesis.outboxStatus,'pending');
 // Projection ACK here is a disposable DB-only stand-in; in the hosted
 // path a real protected-Jena signed CID readback is mandatory.
 const ack=await admin.query(
  "UPDATE paper_atproto_repo_proof.rdf_projection_jobs SET "+
  "state='applied',lease_epoch=lease_epoch+1,"+
  "applied_at=clock_timestamp() WHERE account_id=$1 AND did=$2 "+
  "AND head_cid=$3 AND state='pending' RETURNING generation",
  [owner.owner,owner.did,genesis.commitCid]
 );
 assert.equal(ack.rowCount,1);
 const writer=createSignedSingleRecordWriter({
  pool:repoPool,fixtureOnly:true,
  authorize:async({accountId:account,did:actor,scope:permission})=>{
   if(account!==owner.owner||actor!==owner.did||
      permission!=='atproto:record-write')return false;
   const allowed=await repoPool.query(
    'SELECT paper_atproto_authority.verify_oauth_generation('+
    '$1,$2,$3,$4,$5,$6::bigint) AS ok',
    [owner.owner,app,app,oauthGrant2,sha(oauthScope),3]);
   return allowed.rows[0]?.ok===true;
  }
 });
 const path='app.bsky.feed.post/3jzm3xwpf342a';
 const body={$type:'app.bsky.feed.post',
  text:'Paper unified account signed repository acceptance',
  createdAt:'2026-11-21T00:00:00.000Z'};
 const signed=await writer.write({
  accountId:owner.owner,did:owner.did,
  expectedCommitCid:genesis.commitCid,expectedRev:genesis.rev,
  action:'create',path,record:body,...signing
 });
 assert.equal(signed.verified,true);
 assert.equal(signed.path,path);
 assert.equal(signed.generation,2);
 assert.notEqual(signed.commitCid,genesis.commitCid);
 const independent=await verifySignedSingleRecordSnapshot({
  did:owner.did,publicKeyPem:signing.publicKeyPem,
  carBytes:signed.carBytes
 });
 assert.equal(independent.commitCid,signed.commitCid);
 assert.equal(independent.recordCid,signed.recordCid);
 const outbox=(await repoPool.query(
  'SELECT kind,status,blocked_at FROM '+
  'paper_atproto_repo_proof.native_event_outbox '+
  'WHERE did=$1 AND commit_cid=$2',[owner.did,signed.commitCid]
 )).rows[0];
 assert.equal(outbox.kind,'at.commit.v1');
 assert.equal(outbox.status,'pending');
 assert.equal(outbox.blocked_at,null);
 await assert.rejects(writer.write({
  accountId:pending.owner,did:owner.did,
  expectedCommitCid:signed.commitCid,expectedRev:signed.rev,
  action:'update',path,record:{...body,text:'forged'},...signing
 }),e=>e?.code==='SINGLE_RECORD_WRITE_NOT_AUTHORIZED');
 console.log('PASS: canonical WebID=ActivityPub actor, managed DID/PDS, independently attested SAI, signed CAR/MST and durable native outbox positive fixture');

 await admin.query('UPDATE paper_account_candidate.signup_operations '+
  "SET enrollment_expires_at=clock_timestamp()-interval '1 second' "+
  'WHERE operation_id=$1',[owner.operation]);
 assert.equal(await issue(owner,crypto.randomBytes(24).toString('base64url'),
   oauthScope,3),'0','Expired owner session cannot mint another grant');
 assert.equal(await revokeOAuth(owner,oauthGrant2,3),'0',
   'Expired owner session cannot be replayed for revoke');
 await admin.query('UPDATE paper_account_candidate.signup_operations '+
  "SET enrollment_expires_at=clock_timestamp()+interval '2 minutes' "+
  'WHERE operation_id=$1',[owner.operation]);
 assert.equal(await revokeOAuth(owner,oauthGrant2,3),'4');
 await assert.rejects(writer.write({
  accountId:owner.owner,did:owner.did,
  expectedCommitCid:signed.commitCid,expectedRev:signed.rev,
  action:'update',path,
  record:{...body,text:'must never sign after revoke'},...signing
 }),e=>e?.code==='SINGLE_RECORD_WRITE_NOT_AUTHORIZED');
 assert.equal((await writer.verify({
  accountId:owner.owner,did:owner.did,
  publicKeyPem:signing.publicKeyPem
 })).commitCid,signed.commitCid);
 console.log('PASS: signed repository and native outbox unchanged after owner OAuth revoke');
 console.log('PASS: authentic enrollment journal scopes restricted PG OAuth issuance/revocation, permissions, replay and expiry');

 assert.equal(await api.verifyActiveGrant({
  owner:owner.owner,app,did:owner.did,grantUri:owner.grant,consentRevision:'1'
 }),true);
 assert.deepEqual(await api.revoke({
  owner:owner.owner,app,grantUri:owner.grant,expectedRevision:'1'
 }),{state:'blocked',revision:'2'});
 assert.equal(await confirm(attestor2,owner),false);
 assert.equal(await attest(attestor,owner),false);
 assert.equal(await begin(issuer,owner),false);
 assert.equal((await state(owner)).state,'blocked');
 assert.equal(await begin(issuer,pending),true);
 const still=await api.getConsent({owner:pending.owner,app});
 assert.equal(still.state,'pending');
 const competitor=createCanonicalAtprotoPgAuthority({pool:revoker2});
 const attempts=await Promise.allSettled([
  api.revoke({owner:pending.owner,app,grantUri:still.grantUri,expectedRevision:'1'}),
  competitor.revoke({owner:pending.owner,app,grantUri:still.grantUri,expectedRevision:'1'})
 ]);
 assert.equal(attempts.filter(x=>x.status==='fulfilled').length,1);
 assert.equal(attempts.filter(x=>x.status==='rejected'&&
  x.reason?.code==='ATPROTO_PG_AUTHORITY_STALE').length,1);
 await journalRecorded(pending);
 assert.equal(await attest(attestor,pending),false);
 assert.equal(await confirm(attestor,pending),false);
 assert.equal((await state(pending)).state,'blocked');
 console.log('PASS: real PG18 signup v1-v6, exact reservation/HMAC journal, native consent, owner revocation and six isolated roles; production=CLOSED');
}catch(e){originalError=e;throw e;}
finally{
 const failures=[];
 if(jenaWritten){
  try{await projectJena('DELETE DATA { '+nativeGraph(owner)+' }');}
  catch(e){failures.push(e)}
 }
 for(const c of clients.reverse())try{await c.end()}catch(e){failures.push(e)}
 if(created){
  for(const schema of schemas)try{await admin.query('DROP SCHEMA IF EXISTS '+schema+' CASCADE')}catch(e){failures.push(e)}
  for(const name of Object.values(names))try{await admin.query('DROP ROLE IF EXISTS '+ident(name))}catch(e){failures.push(e)}
  for(const name of cleanupRoles)try{await admin.query('DROP ROLE IF EXISTS '+ident(name))}catch(e){failures.push(e)}
 }
 try{await admin.end()}catch(e){failures.push(e)}
 // eslint-disable-next-line no-unsafe-finally -- surface incomplete cleanup after success
 if(failures.length&&!originalError)throw Error('Disposable bound-consent test cleanup failed');
}
