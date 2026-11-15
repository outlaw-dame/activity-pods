/**
 * Dedicated signed-dataset-claim issuer. It has no worker SQL credential,
 * no provider bearer and no Fuseki administrator password.
 */
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {Pool} from 'pg';
import {makeAccountReservationAuthority,
  assertRestrictedAccountProofLogin} from './account-reservation-authority.mjs';
import {issueBoundDatasetClaim} from './account-reservation-issuer.mjs';
import {server,readRequest,respond,exact,refuse,checkFixtureEnv}
  from './account-coordinator-http.mjs';

const KEYS=[
 'NODE_ENV','ATPROTO_REPO_PROOF_DISPOSABLE','ATPROTO_FUSEKI_ISOLATION_DISPOSABLE',
 'FUSEKI_ISOLATION_URL','APODS_ACCOUNT_RESERVATION_DISPOSABLE',
 'APODS_DATASET_CLAIM_ISSUER_DISPOSABLE','APODS_ACCOUNT_COORDINATOR_DISPOSABLE',
 'ACCOUNT_ISSUER_DSN','ACCOUNT_ISSUER_SIGNING_PEM_B64',
 'ACCOUNT_COORDINATOR_ISSUER_KEY'
];
checkFixtureEnv('issuer',KEYS);
const url=new URL(process.env.ACCOUNT_ISSUER_DSN);
assert.equal(url.hostname,'127.0.0.1');
assert.equal(url.port,'5548');
assert.equal(url.pathname,'/atproto_signed_repo_proof_test');
assert.equal(url.username,'paper_account_issuer_login');
const key=crypto.createPrivateKey({
  key:Buffer.from(process.env.ACCOUNT_ISSUER_SIGNING_PEM_B64,'base64'),
  format:'pem',type:'pkcs8'
});
assert.equal(key.asymmetricKeyType,'ed25519');
const issuerSecret=process.env.ACCOUNT_COORDINATOR_ISSUER_KEY;
const {parseSecret}=await import('../../services/utils/atproto-account-coordinator-client.js').then(m=>m.default);
parseSecret(issuerSecret);
const pool=new Pool({connectionString:url.toString(),max:3,
  connectionTimeoutMillis:3000,query_timeout:5000,
  idleTimeoutMillis:2000,allowExitOnIdle:true});
await assertRestrictedAccountProofLogin(pool,'issuer');
const authority=makeAccountReservationAuthority({
  workerPool:{query(){throw Error('Issuer cannot mutate reservation ledger');}},
  issuerPool:pool
});
const requestKeys=['version','fence','dataset','issuedAtMs','nonce'];
const listener=await server({port:3045,handler:async(req,res)=>{
  const body=await readRequest(req,{domain:'issuer',
    secret:issuerSecret,route:'/v1/issue',keys:requestKeys});
  if(body.version!==1||!Number.isSafeInteger(body.issuedAtMs)||
     Math.abs(Date.now()-body.issuedAtMs)>30000||
     !/^[0-9a-f-]{36}$/u.test(body.nonce)||
     !exact(body.fence,['appClientId','idempotencyKey','reservationId','fenceToken']))refuse();
  const ticket=await issueBoundDatasetClaim({
    authority,privateKey:key,fence:body.fence,dataset:body.dataset
  });
  respond(res,200,{ticket},{secret:issuerSecret,domain:'issuer-response'});
}});
process.stdout.write('ACCOUNT_CLAIM_ISSUER_READY\n');
for(const signal of ['SIGTERM','SIGINT']){
  process.once(signal,()=>listener.close(()=>pool.end().finally(()=>process.exit(0))));
}
