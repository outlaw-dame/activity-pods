/**
 * NONACTIVATED actual PG18 least-privilege signed writer + upstream MST.
 * Uses independent LOGIN credentials and real PostgreSQL GRANT/REVOKE,
 * native event outbox, signed blocks and canonical revocation. No mocks
 * for SQL, role membership, FOR UPDATE or SECURITY DEFINER functions.
 */
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import {test} from 'node:test';
import {fileURLToPath,pathToFileURL} from 'node:url';
import {Pool} from 'pg';
import {createSignedRepoProofStore} from './store.mjs';
import {createReferenceMstWriter} from './reference-mst-writer.mjs';
import {createCanonicalRecordWriteConsentFence} from './pg-record-write-consent-fence.mjs';
import {assertRestrictedRepoWriterLogin} from './pg-restricted-writer-login.mjs';

const DSN=process.env.ATPROTO_REPO_PROOF_DSN||'';
const REF=process.env.ATPROTO_REFERENCE_REPO_ENTRY||'';
if(process.env.ATPROTO_REPO_PROOF_DISPOSABLE!=='confirmed'||
   process.env.ATPROTO_REPO_WRITER_ROLE_TEST_DISPOSABLE!=='confirmed'||
   process.env.NODE_ENV!=='test'||
   !/^postgres(?:ql)?:\/\/paper_probe:probe_local_only@127\.0\.0\.1:5548\/atproto_signed_repo_proof_test$/u.test(DSN)||
   !REF.startsWith('/')){
  throw Error('Restricted repository role proof requires exact disposable PG18 and maintained MST');
}
const reference=await import(pathToFileURL(REF).href);
const admin=new Pool({connectionString:DSN,max:3,
  connectionTimeoutMillis:3000,allowExitOnIdle:true});
const roleSuffix=crypto.randomBytes(7).toString('hex');
const writerLogin='paper_repo_writer_'+roleSuffix;
const genericLogin='paper_repo_generic_'+roleSuffix;
const revokerLogin='paper_repo_revoker_'+roleSuffix;
const names=[writerLogin,genericLogin,revokerLogin];
const secret=new Map(names.map(n=>[n,crypto.randomBytes(27).toString('hex')]));
const ident=n=>{
  if(!/^[a-z_][a-z0-9_]{0,62}$/u.test(n))throw Error('unsafe SQL role');
  return '"'+n+'"';
};
const rolePool=n=>{
  const u=new URL(DSN);
  u.username=n;u.password=secret.get(n);
  return new Pool({connectionString:u.toString(),max:2,
    connectionTimeoutMillis:3000,query_timeout:6000,
    idleTimeoutMillis:3000,allowExitOnIdle:true});
};
const accountId='https://paper.example.org/users/restricted-writer';
const did='did:plc:'+'r'.repeat(24);
const app='https://paper.example.org/apps/restricted';
const grant=accountId+'/data/grants/atproto';
const path='app.bsky.feed.post/3jzm3xwpf342a';
const record={
  $type:'app.bsky.feed.post',text:'Restricted PG writer signed post',
  createdAt:'2026-11-14T00:00:00.000Z'
};
const digest=t=>crypto.createHash('sha256').update(t).digest();
const forbidden=(p,code='42501')=>assert.rejects(p,e=>e?.code===code);
async function sql(path){
  return fs.readFile(fileURLToPath(new URL(path,import.meta.url)),'utf8');
}

test('restricted PG18 signed writer cannot forge applied RDF, ack outbox or regrant identity',async()=>{
  let writerPool,genericPool,revokerPool,cleanErr=null;
  let schemaMade=false;
  try{
    const present=await admin.query(
      "SELECT count(*)::int AS n FROM pg_catalog.pg_tables "+
      "WHERE schemaname IN ('paper_atproto_repo_proof','paper_atproto_authority')"
    );
    assert.equal(present.rows[0].n,0,
      'restricted role test must start on a clean disposable database');
    await admin.query(await sql('./schema.sql'));
    await admin.query(await sql('./single-record-mutation.sql'));
    await admin.query(await sql('../../sql/paper-atproto-canonical-authority-v1.sql'));
    await admin.query(await sql('./pg-restricted-writer-roles.sql'));
    schemaMade=true;
    for(const name of names){
      await admin.query('CREATE ROLE '+ident(name)+
        " LOGIN NOSUPERUSER NOCREATEROLE NOCREATEDB NOREPLICATION NOBYPASSRLS "+
        "PASSWORD '"+secret.get(name)+"'");
    }
    await admin.query('GRANT paper_atproto_repo_writer TO '+
      ident(writerLogin)+' WITH INHERIT TRUE,SET FALSE,ADMIN FALSE');
    await admin.query('GRANT paper_atproto_authority_revoker TO '+
      ident(revokerLogin)+' WITH INHERIT TRUE,SET FALSE,ADMIN FALSE');
    writerPool=rolePool(writerLogin);
    genericPool=rolePool(genericLogin);
    revokerPool=rolePool(revokerLogin);
    const admitted=await assertRestrictedRepoWriterLogin(writerPool);
    assert.equal(admitted.restricted,true);
    assert.equal(admitted.mayMarkProjectionApplied,false);
    assert.equal(admitted.mayRegrant,false);
    await forbidden(assertRestrictedRepoWriterLogin(admin),
      'RESTRICTED_REPO_WRITER_LOGIN_REQUIRED');
    await forbidden(assertRestrictedRepoWriterLogin(genericPool),
      'RESTRICTED_REPO_WRITER_LOGIN_REQUIRED');

    const {privateKey,publicKey}=crypto.generateKeyPairSync('ec',{
      namedCurve:'secp256k1'
    });
    const signing={publicKeyPem:publicKey.export({type:'spki',format:'pem'}).toString(),
      signer:async bytes=>crypto.sign('sha256',bytes,{
        key:privateKey,dsaEncoding:'ieee-p1363'
      })
    };
    const genesis=createSignedRepoProofStore({pool:admin,fixtureOnly:true});
    const first=await genesis.bootstrap({accountId,did,...signing});
    assert.equal(first.verified,true);
    await admin.query(
      "UPDATE paper_atproto_repo_proof.rdf_projection_jobs SET state='applied',"+
      'lease_epoch=1,applied_at=clock_timestamp() '+
      'WHERE account_id=$1 AND did=$2',[accountId,did]
    );
    await admin.query(
      'INSERT INTO paper_atproto_authority.identities '+
      '(owner_webid,did,state,managed,revision,source_proof_sha256) '+
      "VALUES ($1,$2,'active',true,1,$3)",[accountId,did,digest(accountId)]
    );
    await admin.query(
      'INSERT INTO paper_atproto_authority.consents '+
      '(owner_webid,app_uri,grant_uri,state,revision,grant_proof_sha256) '+
      "VALUES ($1,$2,$3,'active',1,$4)",[accountId,app,grant,digest(grant)]
    );

    await forbidden(genericPool.query(
      'SELECT 1 FROM paper_atproto_repo_proof.repos LIMIT 1'
    ));
    await forbidden(genericPool.query(
      'SELECT 1 FROM paper_atproto_authority.consents LIMIT 1'
    ));
    await forbidden(writerPool.query(
      "UPDATE paper_atproto_authority.consents SET state='active' "+
      'WHERE owner_webid=$1',[accountId]
    ));
    await forbidden(writerPool.query(
      'INSERT INTO paper_atproto_authority.identities '+
      '(owner_webid,did,state,managed,revision,source_proof_sha256) '+
      "VALUES($1,$2,'active',true,1,$3)",
      ['https://paper.example.org/users/forged',
        'did:plc:'+'f'.repeat(24),digest('forged')]
    ));
    await forbidden(writerPool.query(
      "SELECT * FROM paper_atproto_authority.block_consent($1,$2,$3,1::bigint)",
      [accountId,app,grant]
    ));
    await forbidden(writerPool.query(
      "UPDATE paper_atproto_repo_proof.rdf_projection_jobs SET state='applied' "+
      'WHERE account_id=$1',[accountId]
    ));
    await forbidden(writerPool.query(
      "UPDATE paper_atproto_repo_proof.native_event_outbox SET status='delivered' "+
      'WHERE did=$1',[did]
    ));
    await forbidden(writerPool.query(
      "UPDATE paper_atproto_repo_proof.blocks SET block=$1 WHERE did=$2",
      [Buffer.from('bad'),did]
    ));
    await forbidden(writerPool.query(
      'INSERT INTO paper_atproto_repo_proof.repos '+
      '(account_id,did,rev,head_cid,root_cid) VALUES($1,$2,$3,$4,$5)',
      ['https://paper.example.org/users/forged',
        'did:plc:'+'f'.repeat(24),first.rev,first.commitCid,first.rootCid]
    ));
    await forbidden(writerPool.query(
      'CREATE TABLE paper_atproto_repo_proof.compromised(flag integer)'
    ));
    await forbidden(writerPool.query('SET ROLE paper_atproto_repo_writer'));
    await forbidden(writerPool.query('SET ROLE paper_atproto_authority_reader'));
    await forbidden(genericPool.query(
      'SELECT * FROM paper_atproto_repo_proof.reset_after_signed_commit('+
      '$1,$2,$3,$4,$5,$6,$7,$8,$9,$10)',
      [accountId,did,first.commitCid,first.rootCid,first.rev,2,
       first.commitCid,first.rootCid,first.rev,1]
    ));

    let currentConsent='1';
    const fence=createCanonicalRecordWriteConsentFence({
      appUri:app,grantUri:grant,consentRevision:currentConsent,
      restrictedCredential:true
    });
    const writer=createReferenceMstWriter({
      pool:writerPool,reference,fixtureOnly:true,
      restrictedProjectionTransition:true,
      authorize:async ({accountId:owner,did:subject})=>{
        if(owner!==accountId||subject!==did)return false;
        const r=await writerPool.query(
          'SELECT c.state,c.revision::text AS revision FROM '+
          'paper_atproto_authority.consents AS c '+
          'WHERE c.owner_webid=$1 AND c.app_uri=$2',
          [owner,app]
        );
        return r.rowCount===1&&r.rows[0].state==='active'&&
          r.rows[0].revision===currentConsent;
      },
      lockCanonicalConsent:fence
    });
    const result=await writer.write({
      accountId,did,...signing,action:'create',path,record,
      expectedCommitCid:first.commitCid,expectedRev:first.rev
    });
    assert.equal(result.generation,2);
    const checked=await writer.verify({
      accountId,did,path,publicKeyPem:signing.publicKeyPem
    });
    assert.equal(checked.commitCid,result.commitCid);
    assert.equal(checked.recordCid,result.recordCid);
    const projection=await writerPool.query(
      'SELECT head_cid,rev,state,generation,lease_epoch FROM '+
      'paper_atproto_repo_proof.rdf_projection_jobs WHERE account_id=$1',
      [accountId]
    );
    assert.equal(projection.rows[0].head_cid,result.commitCid);
    assert.equal(projection.rows[0].state,'pending');
    assert.equal(Number(projection.rows[0].generation),2);
    assert.equal(Number(projection.rows[0].lease_epoch),1);
    const outbox=await writerPool.query(
      'SELECT status FROM paper_atproto_repo_proof.native_event_outbox '+
      'WHERE did=$1 AND commit_cid=$2',[did,result.commitCid]
    );
    assert.equal(outbox.rows[0].status,'pending');

    // A duplicate reset, missing preceding signed generation or a fake
    // signed-head must never mutate the projection after this write.
    const retry=await writerPool.query(
      'SELECT * FROM paper_atproto_repo_proof.reset_after_signed_commit('+
      '$1,$2,$3,$4,$5,$6,$7,$8,$9,$10)',
      [accountId,did,result.commitCid,result.rootCid,result.rev,2,
        first.commitCid,first.rootCid,first.rev,1]
    );
    assert.equal(retry.rowCount,0);
    await forbidden(writerPool.query(
      "UPDATE paper_atproto_repo_proof.rdf_projection_jobs SET state='applied' "+
      'WHERE account_id=$1',[accountId]
    ));

    // Provider projection worker (not the signed repo writer) is the only
    // party allowed to mark the independently validated Jena state applied.
    const acknowledged=await admin.query(
      "UPDATE paper_atproto_repo_proof.rdf_projection_jobs SET state='applied',"+
      'lease_epoch=lease_epoch+1,applied_at=clock_timestamp() '+
      'WHERE account_id=$1 AND did=$2 AND head_cid=$3 AND state=$4 '+
      'RETURNING generation',
      [accountId,did,result.commitCid,'pending']
    );
    assert.equal(acknowledged.rowCount,1);

    // Exactly one of two independently authenticated SQL writers can win
    // a revocation update. No signed write may proceed after that update.
    const revoke=await revokerPool.query(
      'SELECT new_revision::text AS revision,new_state AS state FROM '+
      'paper_atproto_authority.block_consent($1,$2,$3,$4::bigint)',
      [accountId,app,grant,1]
    );
    assert.equal(revoke.rows[0].state,'blocked');
    currentConsent='2';
    await assert.rejects(writer.write({
      accountId,did,...signing,action:'update',path,
      record:{...record,text:'should be denied'},
      expectedCommitCid:result.commitCid,expectedRev:result.rev
    }),e=>['REFERENCE_MST_NOT_AUTHORIZED','WRITE_CONSENT_NOT_CURRENT',
      'REFERENCE_MST_CANONICAL_CONSENT_DENIED'].includes(e?.code));
    assert.equal((await writer.verify({
      accountId,did,path,publicKeyPem:signing.publicKeyPem
    })).commitCid,result.commitCid,'revocation cannot mutate signed history');

    const idle=(await admin.query(
      "SELECT count(*)::int AS n FROM pg_stat_activity "+
      "WHERE datname=current_database() AND state='idle in transaction'"
    )).rows[0].n;
    assert.equal(idle,0);
    console.log('RESTRICTED_REPO_WRITER_PG18_PROOF '+JSON.stringify({
      roleAdmission:true,realIndependentLogin:true,
      canonicalIdentityDenied:true,canonicalConsentUpdateDenied:true,
      noProjectionAppliedWrite:true,noOutboxAckWrite:true,
      realSignedReferenceMst:true,outboxPending:true,
      projectionCasDefiner:true,revocationDenied:true,
      noReplayAfterPending:true,idleTransactions:idle
    }));
  }finally{
    for(const p of [writerPool,genericPool,revokerPool]){
      if(p)try{await p.end();}catch(e){cleanErr=e;}
    }
    if(schemaMade){
      for(const schema of ['paper_atproto_repo_proof','paper_atproto_authority']){
        try{await admin.query('DROP SCHEMA IF EXISTS '+schema+' CASCADE');}
        catch(e){cleanErr=e;}
      }
    }
    for(const name of names){
      try{await admin.query('DROP ROLE IF EXISTS '+ident(name));}
      catch(e){cleanErr=e;}
    }
    for(const name of ['paper_atproto_repo_writer',
      'paper_atproto_authority_revoker','paper_atproto_authority_reader',
      'paper_atproto_authority_importer']){
      try{await admin.query('DROP ROLE IF EXISTS '+ident(name));}
      catch(e){cleanErr=e;}
    }
    await admin.end();
    if(cleanErr)throw cleanErr;
  }
});
