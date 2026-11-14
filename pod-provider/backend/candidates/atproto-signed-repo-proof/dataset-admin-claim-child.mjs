/**
 * NONACTIVATED disposable dataset-administration child process.
 * Only this process receives the Fuseki admin credential. The issuer
 * signs account reservations with an independent Ed25519 key, and only
 * the issuer's PUBLIC key reaches this worker.
 */
import {Pool} from 'pg';
import {createDisposableDatasetAdmin,
  makeDisposableDatasetAdminHttpServer} from './dataset-admin-claim-service.mjs';

if(process.env.NODE_ENV!=='test'||
   process.env.ATPROTO_FUSEKI_ISOLATION_DISPOSABLE!=='confirmed'||
   process.env.ATPROTO_REPO_PROOF_DISPOSABLE!=='confirmed'||
   process.env.FUSEKI_ISOLATION_URL!=='http://127.0.0.1:3041'||
   process.env.DATASET_ADMIN_AGENT_DSN?.startsWith(
     'postgres://paper_dataset_admin_login:')!==true||
   process.env.DATASET_ADMIN_AGENT_DSN?.includes(
     '@127.0.0.1:5548/atproto_signed_repo_proof_test')!==true||
   !process.env.DATASET_ADMIN_ISSUER_PUBLIC_PEM||
   process.env.DATASET_ADMIN_FUSEKI_USER!=='admin'||
   process.env.DATASET_ADMIN_FUSEKI_PASSWORD!=='fixture-admin-only'||
   process.env.DATASET_ADMIN_SIGNER_PRIVATE_KEY){
 throw Error('Disposable dataset administrator release gate is closed');
}
const pool=new Pool({
  connectionString:process.env.DATASET_ADMIN_AGENT_DSN,
  max:2,connectionTimeoutMillis:2500,query_timeout:5000,
  idleTimeoutMillis:1000,allowExitOnIdle:true
});
let server=null;
try{
 const admin=await createDisposableDatasetAdmin({
  pool,origin:process.env.FUSEKI_ISOLATION_URL,
  adminUsername:process.env.DATASET_ADMIN_FUSEKI_USER,
  adminPassword:process.env.DATASET_ADMIN_FUSEKI_PASSWORD,
  publicKeyPem:Buffer.from(
    process.env.DATASET_ADMIN_ISSUER_PUBLIC_PEM,'base64').toString('utf8')
 });
 server=makeDisposableDatasetAdminHttpServer({admin});
 await new Promise((resolve,reject)=>{
   server.once('error',reject);
   server.listen(3042,'127.0.0.1',()=>{
     server.off('error',reject);resolve();
   });
 });
 process.stdout.write('DATASET_ADMIN_AGENT_READY\n');
 const shutdown=async()=>{
  try{await new Promise(resolve=>server.close(resolve));}finally{
   await pool.end().catch(()=>{});
  }
 };
 process.once('SIGTERM',()=>{shutdown().catch(()=>{});});
 process.once('SIGINT',()=>{shutdown().catch(()=>{});});
}catch(error){
 if(server?.listening)await new Promise(resolve=>server.close(resolve));
 await pool.end().catch(()=>{});
 // Never log admin password, signed claim or connection string.
 process.stderr.write('DATASET_ADMIN_AGENT_FAILED\n');
 process.exitCode=1;
}
