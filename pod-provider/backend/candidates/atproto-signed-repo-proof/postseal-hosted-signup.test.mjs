/**
 * NONACTIVATED real PostgreSQL18 new signup + pinned HTTPS signed PDS genesis
 * + protected Solid account/SAI fixture + atomic v4 completion acceptance.
 * This does not register production signup or create a live ATProto account.
 */
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import https from 'node:https';
import {execFileSync} from 'node:child_process';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {test} from 'node:test';
import {createRequire} from 'node:module';
import {fileURLToPath} from 'node:url';
import {Pool} from 'pg';
import {base58btc} from 'multiformats/bases/base58';
import {createSignedRepoProofStore} from './store.mjs';
import {createProviderManagedRepoAuthority} from './provider-authority.mjs';
import {createRdfProjectionRecovery} from './projection-recovery.mjs';
import {createReadOnlySyncXrpc} from './sync-xrpc-candidate.mjs';
import {createNewSignupCrossAuthority} from './new-signup-cross-authority.mjs';
import {createHostedSignupPdsAttestation} from './hosted-signup-pds-attestation.mjs';
import {createPostSealSignupCompletionEvidence} from './postseal-signup-completion-evidence.mjs';
import {createFixedOriginPdsHttpsRequester} from './fixed-origin-pds-https.mjs';

const require=createRequire(import.meta.url);
const {createCandidate}=require('../postgres-account-lifecycle.js');
const {createDisposableSignupCompletion}=
  require('../postgres-signup-atomic-completion.js');
const DSN=process.env.ATPROTO_REPO_PROOF_DSN||'';
if(process.env.NODE_ENV!=='test'||
   process.env.PAPER_ACCOUNTS_DISPOSABLE!=='confirmed'||
   process.env.ATPROTO_REPO_PROOF_DISPOSABLE!=='confirmed'||
   process.env.ATPROTO_PDS_ATTESTATION_DISPOSABLE!=='confirmed'||
   process.env.ATPROTO_PDS_EGRESS_TEST_DISPOSABLE!=='confirmed'||
   process.env.PAPER_ACCOUNT_COMPLETION_DISPOSABLE!=='confirmed'||
   !/^postgres(?:ql)?:\/\/[^@]+@127\.0\.0\.1:5548\/atproto_signed_repo_proof_test$/u.test(DSN)){
  throw Error('Hosted new-account bridge requires an exact disposable PG18 target');
}
const pool=new Pool({connectionString:DSN,max:6,
  connectionTimeoutMillis:3000,idleTimeoutMillis:3000,allowExitOnIdle:true});
const providerId='https://paper.example.org';
const appClientId='https://app.paper.example.org/client';
const appUri='https://app.paper.example.org/app';
const uuid=()=>crypto.randomUUID();
const opId=uuid(),accountId=uuid();
const webId=providerId+'/users/probed-new-user';
const did='did:plc:'+'u'.repeat(24);
const handle='probed-new-user.paper.example.org';
let pds;
const grant=webId+'/data/grants/pds';
const secret=crypto.randomBytes(32);
const hmac=(label,v)=>crypto.createHmac('sha256',secret)
  .update(label+'\0'+v).digest();
const scope={
  providerId,appClientId,hmacKeyVersion:1,
  idempotencyHmac:hmac('paper.signup.idempotency.v1','new-probed'),
  requestHmac:hmac('paper.signup.request.v1','new-probed'),
  accountId,operationId:opId,username:'probed_new_user'
};
const fail=(p,code)=>assert.rejects(p,e=>e?.code===code);

async function listen(server){
  await new Promise((ok,no)=>{server.once('error',no);server.listen(0,'127.0.0.1',ok);});
}
async function close(server){
  if(server)await new Promise((ok,no)=>server.close(e=>e?no(e):ok()));
}

test('one sealed new signup gets independently signed hosted PDS proof before PG18 atomic ready',async t=>{
  let server=null,cleanupError=null,tlsDir=null;
  const oldEnv=process.env.NODE_ENV;
  try{
    const pre=await pool.query(
      "SELECT count(*)::int AS n FROM pg_catalog.pg_tables WHERE schemaname IN "+
      "('paper_account_candidate','paper_atproto_repo_proof','paper_atproto_authority')"
    );
    assert.equal(pre.rows[0].n,0,'new-account test must start with empty disposable state');
    for(const sql of [
      '../../sql/paper-account-postgres-candidate-v1.sql',
      '../../sql/paper-account-postgres-candidate-v2-signup-ledger.sql',
      '../../sql/paper-account-postgres-candidate-v3-evidence-seal.sql',
      '../../sql/paper-account-postgres-candidate-v4-atomic-completion.sql',
      './schema.sql',
      '../../sql/paper-atproto-canonical-authority-v1.sql'
    ]){
      await pool.query(await fs.readFile(fileURLToPath(new URL(sql,import.meta.url)),'utf8'));
    }
    // A disposable CA trusted ONLY by this requester's explicit TLS option.
    // Normal TLS certificate validation and hostname checking remain on.
    tlsDir=await fs.mkdtemp(join(tmpdir(),'paper-signup-pds-tls-'));
    const keyPath=join(tlsDir,'key.pem');
    const certPath=join(tlsDir,'cert.pem');
    execFileSync('openssl',['req','-x509','-newkey','rsa:2048','-nodes',
      '-days','1','-keyout',keyPath,'-out',certPath,
      '-subj','/CN=pds.paper.example.org',
      '-addext','subjectAltName=DNS:pds.paper.example.org'],
      {stdio:'ignore',timeout:12000});
    const keyPem=await fs.readFile(keyPath,'utf8');
    const certPem=await fs.readFile(certPath,'utf8');
    let corruptCar=false,wrongLatest=false,redirectOnce=false,oversized=false;
    let httpXrpc=null;
    let requests=0;
    server=https.createServer({key:keyPem,cert:certPem},(req,res)=>{
      requests++;
      if(redirectOnce){
        res.writeHead(302,{location:'http://169.254.169.254/latest'});
        res.end();return;
      }
      if(oversized){
        res.writeHead(200,{'content-type':'application/vnd.ipld.car',
          'content-length':'300000'});
        res.end();return;
      }
      if(corruptCar&&req.url.includes('.getRepo?')){
        res.writeHead(200,{'content-type':'application/vnd.ipld.car'});
        res.end(Buffer.from('not a signed CAR'));return;
      }
      if(wrongLatest&&req.url.includes('.getLatestCommit?')){
        res.writeHead(200,{'content-type':'application/json'});
        res.end(JSON.stringify({cid:'bafyre'+'b'.repeat(53),
          rev:'2222222222222'}));return;
      }
      if(!httpXrpc){res.writeHead(503);res.end();return;}
      void httpXrpc.handle(req,res);
    });
    await listen(server);
    pds='https://pds.paper.example.org:'+server.address().port;

    const model=createCandidate({pool,fixtureOnly:true});
    assert.equal((await model.reserveSignup(scope)).state,'reserved');
    assert.equal((await model.markSignupMayHaveSideEffects(scope)).state,
      'reconciliation_required');
    assert.equal((await model.change({
      providerId,accountId,operationId:uuid(),expectedGeneration:1,
      kind:'bind_unified_identity',webId,activityPubActorId:webId,
      atprotoDid:did,atprotoHandle:handle,atprotoPdsUrl:pds,
      repoInitialized:true
    })).generation,2);
    const {privateKey,publicKey}=crypto.generateKeyPairSync('ec',{
      namedCurve:'secp256k1'
    });
    const pem=publicKey.export({type:'spki',format:'pem'}).toString();
    const point=publicKey.export({type:'spki',format:'der'}).subarray(-65);
    const compressed=crypto.ECDH.convertKey(point,'secp256k1',
      undefined,undefined,'compressed');
    const publicKeyMultibase=base58btc.encode(Buffer.concat([
      Buffer.from([0xe7,0x01]),compressed
    ]));
    const signing={publicKeyPem:pem,
      signer:async bytes=>crypto.sign('sha256',bytes,{
        key:privateKey,dsaEncoding:'ieee-p1363'
      })
    };
    const store=createSignedRepoProofStore({pool,fixtureOnly:true});
    const signed=await store.bootstrap({accountId:webId,did,...signing});
    assert.equal(signed.verified,true);
    const ack=await pool.query(
      "UPDATE paper_atproto_repo_proof.rdf_projection_jobs SET state='applied',"+
      'lease_epoch=1,applied_at=clock_timestamp() '+
      'WHERE account_id=$1 AND did=$2 RETURNING lease_epoch',[webId,did]
    );
    assert.equal(ack.rowCount,1);
    let binding={
      canonicalAccountId:webId,webId,activityPubActorId:webId,
      atprotoDid:did,atprotoHandle:handle,atprotoPdsUrl:pds,
      atprotoSource:'local',atprotoManaged:true,status:'active',
      atSigningKeyRef:'key://signing',atRotationKeyRef:'key://rotation',
      repoInitialized:true,repoRootCid:signed.rootCid,
      repoRev:signed.rev,repoProjectionFence:'1'
    };
    const solidCall=async(action,params)=>{
      if(action==='auth.account.findByWebId'){
        assert.equal(params.webId,webId);
        return {'@id':webId,disabled:false};
      }
      if(action==='identitybindings.getByCanonicalAccountId'){
        assert.equal(params.canonicalAccountId,webId);
        return {...binding};
      }
      if(action==='auth.awaitBootstrapComplete'){
        assert.equal(params.webId,webId);
        return {webId,complete:true};
      }
      throw Error('Unexpected Solid provider method '+action);
    };
    const repoAuthority=createProviderManagedRepoAuthority({
      store,resolveBinding:async()=>({...binding}),
      resolveCommitKey:async()=>({
        did,keyId:did+'#atproto',publicKeyMultibase
      }),
      resolveDelegatedIdentity:async()=>({
        resolvedHandleDid:did,
        didDocument:{
          id:did,alsoKnownAs:['at://'+handle],
          verificationMethod:[{
            id:did+'#atproto',controller:did,type:'Multikey',
            publicKeyMultibase
          }],
          service:[{
            id:'#atproto_pds',type:'AtprotoPersonalDataServer',
            serviceEndpoint:pds
          }]
        }
      }),
      signCommit:async()=>{throw Error('Read-only account completion must not sign');}
    });
    const projection=createRdfProjectionRecovery({
      pool,fixtureOnly:true,
      verifyNativeEvidence:async()=>store.verify({
        accountId:webId,did,publicKeyPem:pem
      }),
      authorize:async()=>true,
      readRdf:async()=>({...binding}),
      applyRdfFenced:async()=>{throw Error('Read-only completion must never write RDF');}
    });
    const cross=createNewSignupCrossAuthority({
      accountAuthority:model,repositoryAuthority:repoAuthority,
      projectionAuthority:projection,solidCall,fixtureOnly:true
    });
    const initial=await cross.verify(scope);
    assert.equal(initial.status,'evidence_only');
    assert.equal(initial.commitCid,signed.commitCid);
    const sealer=createCandidate({pool,fixtureOnly:true,
      verifyNewSignupEvidence:sc=>cross.verify(sc)});
    assert.equal((await sealer.sealSignupEvidence(scope)).state,'evidence_sealed');
    await fail(cross.verify(scope),'UNIFIED_SIGNUP_OPERATION_NOT_FENCED');

    const digest=crypto.createHash('sha256').update('pds-accepted-grant').digest();
    await pool.query(
      'INSERT INTO paper_atproto_authority.identities '+
      '(owner_webid,did,state,managed,revision,source_proof_sha256) '+
      "VALUES ($1,$2,'active',true,1,$3)",[webId,did,digest]
    );
    await pool.query(
      'INSERT INTO paper_atproto_authority.consents '+
      '(owner_webid,app_uri,grant_uri,state,revision,grant_proof_sha256) '+
      "VALUES ($1,$2,$3,'active',1,$4)",[webId,appUri,grant,digest]
    );

    let hosted={
      webId,activityPubActorId:webId,did,handle,pdsUrl:pds,
      atprotoManaged:true,atprotoSource:'local',status:'active'
    };
    httpXrpc=createReadOnlySyncXrpc({
      resolveHostedAccount:async({did:requested})=>
        requested===did?{...hosted}:null,
      repositoryAuthority:repoAuthority,projectionAuthority:projection,
      signedRepoStore:store,
      resolvePublicKey:async()=>pem,pdsOrigin:pds,fixtureOnly:true
    });
    const egressConfig={
      origin:pds,approvedAddresses:['127.0.0.1'],
      resolveAddresses:async hostname=>{
        assert.equal(hostname,'pds.paper.example.org');
        return [{address:'127.0.0.1',family:4}];
      },
      tlsCaForTest:certPem,fixtureOnly:true
    };
    const {requestPds}=createFixedOriginPdsHttpsRequester(egressConfig);
    const hostedProof=createHostedSignupPdsAttestation({
      repositoryAuthority:repoAuthority,projectionAuthority:projection,
      resolvePublicKey:async()=>pem,requestPds,fixtureOnly:true
    });
    const x={
      webId,did,handle,pdsOrigin:pds,
      commitCid:signed.commitCid,rootCid:signed.rootCid,
      rev:signed.rev,projectionFence:'1'
    };
    await t.test('signed XRPC CAR and live status independently prove hosted genesis',async()=>{
      const result=await hostedProof.verify(x);
      assert.equal(result.hostedPdsVerified,true);
      assert.equal(result.productionReady,false);
      assert(requests>=3);
    });
    await t.test('wrong latest commit and forged HTTP CAR never authorize completion',async()=>{
      wrongLatest=true;
      await fail(hostedProof.verify(x),'HOSTED_PDS_PROOF_LATEST_COMMIT_MISMATCH');
      wrongLatest=false;
      corruptCar=true;
      await fail(hostedProof.verify(x),'HOSTED_PDS_PROOF_SIGNED_CAR_INVALID');
      corruptCar=false;
    });
    await t.test('pinned TLS rejects untrusted certificates, mismatched hostnames and DNS rebinding',async()=>{
      const url='/xrpc/com.atproto.sync.getLatestCommit?did='+encodeURIComponent(did);
      const direct={expectedOrigin:pds,method:'GET',path:url,redirect:'manual'};
      const expectCode=async(adapter,code)=>
        assert.rejects(adapter.requestPds(direct),e=>e?.code===code);
      const untrusted=createFixedOriginPdsHttpsRequester({
        ...egressConfig,tlsCaForTest:undefined
      });
      await expectCode(untrusted,'PDS_EGRESS_CONNECTION_UNAVAILABLE');
      const wrongHostname=createFixedOriginPdsHttpsRequester({
        ...egressConfig,origin:'https://untrusted.paper.example.org:'+
          server.address().port,
        resolveAddresses:async()=>[{address:'127.0.0.1',family:4}]
      });
      await assert.rejects(
        wrongHostname.requestPds({...direct,
          expectedOrigin:'https://untrusted.paper.example.org:'+
            server.address().port}),e=>e?.code==='PDS_EGRESS_CONNECTION_UNAVAILABLE');
      const rebinding=createFixedOriginPdsHttpsRequester({
        ...egressConfig,
        resolveAddresses:async()=>[
          {address:'127.0.0.1',family:4},
          {address:'169.254.169.254',family:4}
        ]
      });
      await expectCode(rebinding,'PDS_EGRESS_ADDRESS_FORBIDDEN');
      await assert.rejects(requestPds({...direct,
        path:url+'&did='+encodeURIComponent(did)}),
        e=>e?.code==='PDS_EGRESS_PATH_INVALID');
      await assert.rejects(requestPds({...direct,
        expectedOrigin:'https://attacker.example.org'}),
        e=>e?.code==='PDS_EGRESS_REQUEST_INVALID');
      // Disposable fixture authority never leaks into production, even if
      // a requester was constructed before the environment changed.
      const old=process.env.NODE_ENV;
      try{
        process.env.NODE_ENV='production';
        await expectCode({requestPds:()=>requestPds(direct)},
          'PDS_EGRESS_DISPOSABLE_NOT_RELEASED');
        assert.throws(()=>createFixedOriginPdsHttpsRequester(egressConfig),
          e=>e?.code==='PDS_EGRESS_DISPOSABLE_NOT_RELEASED');
        assert.throws(()=>createFixedOriginPdsHttpsRequester({
          origin:'https://pds.paper.example.org',
          approvedAddresses:['127.0.0.1']
        }),e=>e?.code==='PDS_EGRESS_ADDRESS_FORBIDDEN');
      }finally{process.env.NODE_ENV=old;}
    });
    await t.test('redirect and oversized response fail without contacting another destination',async()=>{
      const before=requests;
      redirectOnce=true;
      await fail(hostedProof.verify(x),'HOSTED_PDS_PROOF_HTTP_UNAVAILABLE');
      redirectOnce=false;
      assert.equal(requests,before+1,'only the approved TLS origin was contacted');
      oversized=true;
      await fail(hostedProof.verify(x),'PDS_EGRESS_BODY_TOO_LARGE');
      oversized=false;
    });
    await t.test('moved or inactive PDS cannot pass hosted proof',async()=>{
      hosted={...hosted,status:'suspended'};
      await fail(hostedProof.verify(x),'HOSTED_PDS_PROOF_HTTP_UNAVAILABLE');
      hosted={...hosted,status:'active'};
      binding={...binding,atprotoPdsUrl:'https://moved.example.org'};
      await assert.rejects(hostedProof.verify(x));
      binding={...binding,atprotoPdsUrl:pds};
    });
    const providerVerifier=createPostSealSignupCompletionEvidence({
      accountAuthority:model,repositoryAuthority:repoAuthority,
      projectionAuthority:projection,hostedPdsAttestation:hostedProof,
      solidCall,pool,approvedProviderId:providerId,
      approvedAppClientId:appClientId,approvedAppUri:appUri,
      fixtureOnly:true
    });
    await fail(providerVerifier.verify({...scope,
      appClientId:'https://other.example.org/app'}),'SIGNUP_POSTSEAL_SCOPE_INVALID');
    const fresh=await providerVerifier.verify(scope);
    assert.equal(fresh.hostedPdsVerified,true);
    assert.equal(fresh.accountId,accountId);
    assert.equal(fresh.projectionFence,'1');
    const completion=createDisposableSignupCompletion({
      pool,fixtureOnly:true,
      verifyCurrent:args=>providerVerifier.verify(args)
    });
    const ready=await completion.complete(scope);
    assert.equal(ready.state,'ready');
    assert.equal(ready.releaseAuthorized,false);
    assert.equal(ready.canAuthenticate,false);
    const rows=await pool.query(
      'SELECT a.state AS account_state,s.state AS signup_state,'+
      's.completion_consent_revision FROM paper_account_candidate.accounts a '+
      'JOIN paper_account_candidate.signup_operations s '+
      'ON s.account_id=a.account_id WHERE a.account_id=$1',[accountId]
    );
    assert.equal(rows.rows[0].account_state,'ready');
    assert.equal(rows.rows[0].signup_state,'ready');
    assert.equal(String(rows.rows[0].completion_consent_revision),'1');
    assert.equal((await completion.complete(scope)).replay,true);
    await t.test('production cannot activate already constructed PDS bridge',async()=>{
      const old=process.env.NODE_ENV;
      try{
        process.env.NODE_ENV='production';
        await fail(hostedProof.verify(x),'HOSTED_PDS_PROOF_NOT_RELEASED');
        await fail(providerVerifier.verify(scope),'SIGNUP_POSTSEAL_PROOF_NOT_RELEASED');
        await fail(completion.complete(scope),'SIGNUP_COMPLETION_NOT_RELEASED');
      }finally{process.env.NODE_ENV=old;}
    });
    console.log('HOSTED_NEW_SIGNUP_PG18_PROOF '+JSON.stringify({
      realSignedGenesis:true,liveHttpsXrpc:true,tlsHostnameVerified:true,
      dnsPinned:true,noRedirect:true,
      currentSolidAndPgConsent:true,corruptCarRejected:true,
      hostedPdsMoveRejected:true,atomicCompletionReady:true,
      accountGeneration:ready.generation,
      productionAuthorization:false
    }));
  }finally{
    process.env.NODE_ENV=oldEnv;
    await close(server);
    if(tlsDir)await fs.rm(tlsDir,{recursive:true,force:true});
    for(const schema of ['paper_account_candidate','paper_atproto_repo_proof',
      'paper_atproto_authority']){
      try{await pool.query('DROP SCHEMA IF EXISTS '+schema+' CASCADE');}
      catch(e){cleanupError=e;}
    }
    for(const role of ['paper_atproto_authority_reader',
      'paper_atproto_authority_revoker','paper_atproto_authority_importer']){
      try{await pool.query('DROP ROLE IF EXISTS '+role);}
      catch(e){cleanupError=e;}
    }
    await pool.end();
    if(cleanupError)throw cleanupError;
  }
});
