import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import { test } from 'node:test';
import { fileURLToPath,pathToFileURL } from 'node:url';
import { CID } from 'multiformats/cid';
import { Pool } from 'pg';
import { createSignedRepoProofStore } from './store.mjs';
import { createReferenceMstWriter } from './reference-mst-writer.mjs';
import { createReferenceMstCarExporter } from './reference-mst-car-export.mjs';
import { cid, checkRecord, decodeCanonical } from './signed-single-record.mjs';

const DSN=process.env.ATPROTO_REPO_PROOF_DSN||'';
const LIB=process.env.ATPROTO_REFERENCE_REPO_ENTRY||'';
if(process.env.ATPROTO_REPO_PROOF_DISPOSABLE!=='confirmed' ||
   !/^postgres(?:ql)?:\/\/[^@]+@127\.0\.0\.1:5548\/atproto_signed_repo_proof_test$/u.test(DSN) ||
   !LIB.startsWith('/'))throw Error('Full CAR proof only runs on pinned reference plus disposable PG18');
const reference=await import(pathToFileURL(LIB).href);
const pool=new Pool({connectionString:DSN,max:5,connectionTimeoutMillis:3000,
  idleTimeoutMillis:3000,allowExitOnIdle:true});
const accountId='https://paper.example.org/users/car-export';
const did='did:plc:'+'c'.repeat(24);
const ALPHABET='234567abcdefghijklmnopqrstuvwxyz';
function pathFor(i){
  let x=i,rkey='';
  for(let j=0;j<4;j++){rkey=ALPHABET[x%32]+rkey;x=Math.floor(x/32);}
  return 'app.bsky.feed.post/3jzm3xwpf'+rkey;
}
const rec=i=>({$type:'app.bsky.feed.post',
  text:'Signed complete CAR post '+i,
  createdAt:'2026-11-13T00:00:00.000Z'});
const rejects=(promise,code)=>assert.rejects(promise,e=>{
  assert.equal(e?.code,code,'expected '+code+', received '+e?.code);
  return true;
});
test('bounded full signed multi-record export with exact PG/Jena head + complete CAR',async t=>{
  const original=process.env.NODE_ENV;
  try{
    assert.equal((await pool.query(
      "SELECT count(*)::int AS n FROM pg_catalog.pg_tables WHERE schemaname='paper_atproto_repo_proof'"
    )).rows[0].n,0);
    await pool.query(await fs.readFile(
      fileURLToPath(new URL('./schema.sql',import.meta.url)),'utf8'));
    await pool.query(await fs.readFile(
      fileURLToPath(new URL('./single-record-mutation.sql',import.meta.url)),'utf8'));
    const {privateKey,publicKey}=crypto.generateKeyPairSync('ec',{namedCurve:'secp256k1'});
    const keys={publicKeyPem:publicKey.export({format:'pem',type:'spki'}).toString(),
      signer:async bytes=>crypto.sign('sha256',bytes,{
        key:privateKey,dsaEncoding:'ieee-p1363'
      })};
    const genesis=createSignedRepoProofStore({pool,fixtureOnly:true});
    const writer=createReferenceMstWriter({
      pool,reference,fixtureOnly:true,authorize:async()=>true
    });
    let grant=true,authCalls=0,mutateDuringAuth=false;
    const exporter=createReferenceMstCarExporter({
      pool,reference,fixtureOnly:true,
      verifySignedHead:args=>writer.verify(args),
      authorize:async ({accountId:owner,did:repoDid,scope})=>{
        assert.equal(owner,accountId);
        assert.equal(repoDid,did);
        assert.equal(scope,'atproto:repo-export');
        authCalls++;
        if(mutateDuringAuth && authCalls%2===0){
          await pool.query(
            "UPDATE paper_atproto_repo_proof.rdf_projection_jobs SET state='pending',"+
            "applied_at=NULL WHERE account_id=$1 AND did=$2",
            [accountId,did]
          );
        }
        return grant;
      }
    });
    let head=await genesis.bootstrap({accountId,did,...keys});
    const project=async()=>{
      const r=await pool.query(
        "UPDATE paper_atproto_repo_proof.rdf_projection_jobs SET state='applied',"+
        'lease_epoch=lease_epoch+1,applied_at=clock_timestamp() '+
        "WHERE account_id=$1 AND did=$2 AND state='pending' AND head_cid=$3 "+
        'RETURNING generation',[accountId,did,head.commitCid]
      );
      assert.equal(r.rowCount,1);
    };
    await project();
    const records=new Map();
    async function write(action,i){
      const path=pathFor(i);
      const record=action==='delete'?null:rec(i);
      head=await writer.write({
        accountId,did,...keys,action,path,record,
        expectedCommitCid:head.commitCid,expectedRev:head.rev
      });
      if(record===null)records.delete(path);
      else records.set(path,(await cid(checkRecord(record,path))).toString());
      return head;
    }
    await t.test('genesis export includes a valid signed commit and one empty MST',async()=>{
      const x=await exporter.exportSnapshot({accountId,did,publicKeyPem:keys.publicKeyPem});
      assert.equal(x.verified,true);
      assert.equal(x.releaseAuthorized,false);
      assert.equal(x.blockCount,2);
      assert.equal(x.recordCount,0);
      const official=await reference.readCarWithRoot(x.carBytes);
      assert.equal(official.root.toString(),head.commitCid);
      assert.equal(official.blocks.size,2);
    });
    await t.test('multi-record CAR contains all reachable nodes and record bytes, no leftovers',async()=>{
      for(let i=0;i<28;i++){await write('create',i);await project();}
      await write('update',12);await project();
      for(const i of [2,9,22]){await write('delete',i);await project();}
      const x=await exporter.exportSnapshot({accountId,did,publicKeyPem:keys.publicKeyPem});
      assert.equal(x.recordCount,25);
      assert.equal(x.commitCid,head.commitCid);
      assert.equal(x.rootCid,head.rootCid);
      assert.equal(x.generation,head.generation);
      assert(x.blockCount>x.recordCount+1,'multilevel MST must include additional node blocks');
      assert(x.carBytes.length<2_000_000);
      const parsed=await reference.readCarWithRoot(x.carBytes);
      assert.equal(parsed.root.toString(),head.commitCid);
      assert.equal(parsed.blocks.size,x.blockCount,'CAR contains no duplicate or unreachable blocks');
      const signed=reference.parseObjByDef(
        parsed.blocks.get(parsed.root),parsed.root,reference.def.commit
      ).obj;
      assert.equal(signed.did,did);
      assert.equal(signed.data.toString(),head.rootCid);
      assert.equal(signed.rev,head.rev);
      const memory=new reference.MemoryBlockstore(parsed.blocks);
      const tree=reference.MST.load(memory,signed.data);
      const leaves=await tree.list(100);
      assert.equal(leaves.length,records.size);
      for(const leaf of leaves){
        const wanted=records.get(leaf.key);
        assert.equal(leaf.value.toString(),wanted);
        const raw=parsed.blocks.get(leaf.value);
        assert(raw,'CAR includes each referenced record');
        assert.equal(decodeCanonical(raw).$type,'app.bsky.feed.post');
      }
      await rejects(exporter.exportSnapshot({
        accountId,did,publicKeyPem:keys.publicKeyPem,maxBytes:1024
      }),'REFERENCE_CAR_TOO_LARGE');
      assert(authCalls>=4);
    });
    await t.test('unprojected new head can never be returned as a successful export',async()=>{
      await write('create',61);
      await rejects(exporter.exportSnapshot({
        accountId,did,publicKeyPem:keys.publicKeyPem
      }),'REFERENCE_CAR_PROJECTION_NOT_APPLIED');
      await project();
    });
    await t.test('corrupt a nonfirst record: complete export catches it even if head is signed',async()=>{
      const path=pathFor(13);
      const pointer=records.get(path);
      const old=(await pool.query(
        'SELECT block FROM paper_atproto_repo_proof.blocks WHERE did=$1 AND cid=$2',
        [did,pointer]
      )).rows[0].block;
      await pool.query(
        'UPDATE paper_atproto_repo_proof.blocks SET block=$3 WHERE did=$1 AND cid=$2',
        [did,pointer,Buffer.from('corrupt')]
      );
      try{
        await rejects(exporter.exportSnapshot({
          accountId,did,publicKeyPem:keys.publicKeyPem
        }),'REFERENCE_CAR_BLOCK_INVALID');
      }finally{
        await pool.query(
          'UPDATE paper_atproto_repo_proof.blocks SET block=$3 WHERE did=$1 AND cid=$2',
          [did,pointer,old]
        );
      }
    });
    await t.test('SAI revocation and head/intent drift during export are denied',async()=>{
      grant=false;
      await rejects(exporter.exportSnapshot({
        accountId,did,publicKeyPem:keys.publicKeyPem
      }),'REFERENCE_CAR_NOT_AUTHORIZED');
      grant=true;
      mutateDuringAuth=true;
      // The callback flips the exact projection state to pending on the
      // second check, after all blocks were inspected. Last readback refuses.
      authCalls=0;
      await rejects(exporter.exportSnapshot({
        accountId,did,publicKeyPem:keys.publicKeyPem
      }),'REFERENCE_CAR_PROJECTION_NOT_APPLIED');
      mutateDuringAuth=false;
      await project();
      assert.equal((await exporter.exportSnapshot({
        accountId,did,publicKeyPem:keys.publicKeyPem
      })).recordCount,26);
    });
    await t.test('public access cannot toggle the deliberately closed production gate',async()=>{
      const closed=createReferenceMstCarExporter({
        pool,reference,verifySignedHead:writer.verify,authorize:async()=>true
      });
      await rejects(closed.exportSnapshot({}),'REFERENCE_CAR_EXPORT_NOT_RELEASED');
      process.env.NODE_ENV='production';
      await rejects(exporter.exportSnapshot({
        accountId,did,publicKeyPem:keys.publicKeyPem
      }),'REFERENCE_CAR_EXPORT_NOT_RELEASED');
      process.env.NODE_ENV='test';
    });
  }finally{
    if(original===undefined)delete process.env.NODE_ENV;
    else process.env.NODE_ENV=original;
    try{await pool.query('DROP SCHEMA IF EXISTS paper_atproto_repo_proof CASCADE');}
    finally{await pool.end();}
  }
});
