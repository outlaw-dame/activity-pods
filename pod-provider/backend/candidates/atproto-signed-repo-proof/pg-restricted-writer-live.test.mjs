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
const oauthRevokerLogin='paper_oauth_revoker_'+roleSuffix;
const names=[writerLogin,genericLogin,revokerLogin,oauthRevokerLogin];
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
const oauthClientId='https://paper-client.example.org/reader';
const oauthGrantId='o'.repeat(32);
const oauthScope='atproto repo:app.bsky.feed.post?action=create';
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
  let writerPool,genericPool,revokerPool,oauthRevokerPool,cleanErr=null;
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
    schemaMade=true;
    await admin.query(await sql('../../sql/paper-atproto-canonical-authority-v2-owner-consent.sql'));
    await admin.query(await sql('../../sql/paper-atproto-canonical-authority-v4-oauth-generations.sql'));
    await admin.query(await sql('./pg-restricted-writer-roles.sql'));
    await admin.query(await sql('../../sql/paper-atproto-canonical-authority-v6-repo-writer-oauth-lock.sql'));
    for(const name of names){
      await admin.query('CREATE ROLE '+ident(name)+
        " LOGIN NOSUPERUSER NOCREATEROLE NOCREATEDB NOREPLICATION NOBYPASSRLS "+
        "PASSWORD '"+secret.get(name)+"'");
    }
    await admin.query('GRANT paper_atproto_repo_writer TO '+
      ident(writerLogin)+' WITH INHERIT TRUE,SET FALSE,ADMIN FALSE');
    await admin.query('GRANT paper_atproto_authority_revoker TO '+
      ident(revokerLogin)+' WITH INHERIT TRUE,SET FALSE,ADMIN FALSE');
    await admin.query('GRANT paper_oauth_epoch_revoker TO '+
      ident(oauthRevokerLogin)+' WITH INHERIT TRUE,SET FALSE,ADMIN FALSE');
    writerPool=rolePool(writerLogin);
    genericPool=rolePool(genericLogin);
    revokerPool=rolePool(revokerLogin);
    oauthRevokerPool=rolePool(oauthRevokerLogin);
    const admitted=await assertRestrictedRepoWriterLogin(writerPool);
    assert.equal(admitted.restricted,true);
    assert.equal(admitted.mayMarkProjectionApplied,false);
    assert.equal(admitted.mayRegrant,false);
    await forbidden(assertRestrictedRepoWriterLogin(admin),
      'RESTRICTED_REPO_WRITER_LOGIN_REQUIRED');
    await forbidden(assertRestrictedRepoWriterLogin(genericPool),
      'RESTRICTED_REPO_WRITER_LOGIN_REQUIRED');

    // A role with all required grants is STILL unsafe if any extra
    // table/column mutation or SET ROLE delegation leaks into the login.
    for(const permission of [
      'UPDATE (lease_until) ON paper_atproto_repo_proof.rdf_projection_jobs',
      'INSERT (delivered_at) ON paper_atproto_repo_proof.native_event_outbox',
      'DELETE ON paper_atproto_repo_proof.blocks',
      'TRUNCATE ON paper_atproto_repo_proof.blocks',
      'UPDATE (revision) ON paper_atproto_authority.consents'
    ]){
      await admin.query('GRANT '+permission+' TO '+ident(writerLogin));
      try{
        await forbidden(assertRestrictedRepoWriterLogin(writerPool),
          'RESTRICTED_REPO_WRITER_LOGIN_REQUIRED');
      }finally{
        await admin.query('REVOKE '+permission+' FROM '+ident(writerLogin));
      }
      assert.equal((await assertRestrictedRepoWriterLogin(writerPool)).restricted,true);
    }
    const extraRole='paper_repo_extra_'+roleSuffix;
    await admin.query('CREATE ROLE '+ident(extraRole)+
      ' NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION');
    try{
      await admin.query('GRANT '+ident(extraRole)+' TO '+ident(writerLogin)+
        ' WITH INHERIT FALSE,SET TRUE,ADMIN FALSE');
      try{
        await forbidden(assertRestrictedRepoWriterLogin(writerPool),
          'RESTRICTED_REPO_WRITER_LOGIN_REQUIRED');
      }finally{
        await admin.query('REVOKE '+ident(extraRole)+' FROM '+ident(writerLogin));
      }
    }finally{
      await admin.query('DROP ROLE '+ident(extraRole));
    }
    assert.equal((await assertRestrictedRepoWriterLogin(writerPool)).restricted,true);

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
      '(owner_webid,app_uri,grant_uri,state,revision,grant_proof_sha256,'+
      'activation_operation,activation_request_sha256,activation_native_readback_at) '+
      "VALUES ($1,$2,$3,'active',1,$4,$5,$4,clock_timestamp())",
      [accountId,app,grant,digest(grant),crypto.randomUUID()]
    );
    const pgIssued=await admin.query(
      'SELECT paper_atproto_authority.issue_oauth_generation('+
      '$1,$2,$3,$4,$5,0::bigint,1::bigint) AS revision',
      [accountId,app,oauthClientId,oauthGrantId,digest(oauthScope)]
    );
    assert.equal(pgIssued.rows[0].revision,'1');

    await forbidden(genericPool.query(
      'SELECT 1 FROM paper_atproto_repo_proof.repos LIMIT 1'
    ));
    await forbidden(genericPool.query(
      'SELECT 1 FROM paper_atproto_authority.consents LIMIT 1'
    ));
    await forbidden(writerPool.query(
      'SELECT * FROM paper_atproto_authority.oauth_generations'
    ));
    await forbidden(writerPool.query(
      'SELECT paper_atproto_authority.revoke_oauth_generation($1,$2,$3,$4)',
      [accountId,oauthClientId,oauthGrantId,1]
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
      restrictedCredential:true,
      oauthEpoch:{clientId:oauthClientId,grantId:oauthGrantId,
        scope:oauthScope,revision:'1'}
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

    // Real signed repository writer holds the PG OAuth epoch lock in
    // the SAME transaction as signed MST, repo head, outbox and projection.
    const oauthLockedWriter=await writerPool.connect();
    let oauthCommitDone=false,oauthRevoked=false,oauthRevocation;
    try{
      await oauthLockedWriter.query('BEGIN');
      const locked=await oauthLockedWriter.query(
        'SELECT paper_atproto_authority.lock_oauth_generation_for_write('+
        '$1,$2,$3,$4,$5,$6::bigint) AS allowed',
        [accountId,app,oauthClientId,oauthGrantId,digest(oauthScope),1]
      );
      assert.equal(locked.rows[0].allowed,true);
      oauthRevocation=oauthRevokerPool.query(
        'SELECT paper_atproto_authority.revoke_oauth_generation('+
        '$1,$2,$3,$4::bigint) AS revision',
        [accountId,oauthClientId,oauthGrantId,1]
      ).then(r=>{oauthRevoked=true;return r;});
      await new Promise(ok=>setTimeout(ok,125));
      assert.equal(oauthRevoked,false,
        'OAuth revocation must wait for the in-flight signed writer');
      await oauthLockedWriter.query('COMMIT');oauthCommitDone=true;
    }finally{
      if(!oauthCommitDone)await oauthLockedWriter.query('ROLLBACK').catch(()=>{});
      oauthLockedWriter.release(!oauthCommitDone);
    }
    assert.equal((await oauthRevocation).rows[0].revision,'2');
    await assert.rejects(writer.write({
      accountId,did,...signing,action:'update',path,
      record:{...record,text:'OAuth-revoked must never commit'},
      expectedCommitCid:result.commitCid,expectedRev:result.rev
    }),e=>e?.code==='WRITE_OAUTH_EPOCH_NOT_CURRENT');
    assert.equal((await writer.verify({
      accountId,did,path,publicKeyPem:signing.publicKeyPem
    })).commitCid,result.commitCid,
    'OAuth revocation cannot mutate the signed head or outbox');

    // Exactly one of two independently authenticated SQL writers can win
    // a revocation update. No signed write may proceed after that update.
    // Deterministic real-connection revocation race. Holding the consent
    // lock inside the same PG transaction MUST serialize a separately
    // authenticated revoker, even though the writer has no direct UPDATE
    // privilege on the consent table.
    const lockedWriter=await writerPool.connect();
    let commitDone=false,revocationFinished=false,revoking;
    try{
      await lockedWriter.query('BEGIN');
      const claimed=await lockedWriter.query(
        'SELECT paper_atproto_authority.lock_writer_consent('+
        '$1,$2,$3,$4,$5::bigint) AS allowed',
        [accountId,did,app,grant,'1']
      );
      assert.equal(claimed.rows[0].allowed,true);
      revoking=revokerPool.query(
        'SELECT new_revision::text AS revision,new_state AS state FROM '+
        'paper_atproto_authority.block_consent($1,$2,$3,$4::bigint)',
        [accountId,app,grant,1]
      ).then(r=>{revocationFinished=true;return r;});
      await new Promise(ok=>setTimeout(ok,125));
      assert.equal(revocationFinished,false,
        'canonical revocation must wait for in-flight trusted writer lock');
      await lockedWriter.query('COMMIT');
      commitDone=true;
    }finally{
      if(!commitDone)await lockedWriter.query('ROLLBACK').catch(()=>{});
      lockedWriter.release(!commitDone);
    }
    const revoke=await revoking;
    assert.equal(revoke.rowCount,1);
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
      unexpectedGrantRefusal:true,unexpectedSetRoleRefusal:true,
      canonicalIdentityDenied:true,canonicalConsentUpdateDenied:true,
      noProjectionAppliedWrite:true,noOutboxAckWrite:true,
      realSignedReferenceMst:true,outboxPending:true,
      projectionCasDefiner:true,revocationDenied:true,
      consentRevocationSerialized:true,
      oauthEpochLockedInSignedCommit:true,
      oauthRevocationSerialized:true,
      signedWriteDeniedAfterOAuthRevoke:true,
      noReplayAfterPending:true,idleTransactions:idle
    }));
  }finally{
    for(const p of [writerPool,genericPool,revokerPool,oauthRevokerPool]){
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
      'paper_oauth_epoch_signer','paper_oauth_epoch_reader',
      'paper_oauth_epoch_revoker','paper_oauth_epoch_issuer',
      'paper_atproto_consent_issuer','paper_atproto_consent_attestor',
      'paper_atproto_authority_revoker','paper_atproto_authority_reader',
      'paper_atproto_authority_importer']){
      try{await admin.query('DROP ROLE IF EXISTS '+ident(name));}
      catch(e){cleanErr=e;}
    }
    await admin.end();
  }
  if(cleanErr)throw cleanErr;
});
