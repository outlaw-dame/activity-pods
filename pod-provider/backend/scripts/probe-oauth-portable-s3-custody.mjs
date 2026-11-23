#!/usr/bin/env node
/**
 * READ-ONLY external operator tool for Backblaze B2 / Storj S3 custody
 * inventory; never creates or changes buckets/objects or authorizes
 * credential issuance or production signup.
 *
 * Uses two independent input sources: a pre-provisioned local S3 reader
 * profile and an out-of-band pinned version/digest from the custodian.
 * Separate human administration is verified OFFLINE, never guessed from
 * distinct profile names or S3 API key values.
 */
import {createRequire} from 'node:module';
import path from 'node:path';
import {validatePortableS3Endpoint,inspectPortableS3ObjectLock} from
 '../candidates/oauth-portable-s3-custody-readonly.mjs';

const env=process.env;
function refuse(code='PORTABLE_WORM_OPERATOR_CONFIG_UNSAFE'){
  const e=new Error('Independent portable S3 custody not verified');
  e.code=code;throw e;
}
async function main(){
  if(env.PAPER_PORTABLE_WORM_OPERATOR_CONFIRM!=='read-only-verified'||
     !path.isAbsolute(env.PAPER_WORM_SDK_ROOT||'')||
     !/^[A-Za-z0-9_.-]{1,128}$/u.test(env.PAPER_PORTABLE_WORM_READER_PROFILE||'')||
     !/^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/u.test(env.PAPER_PORTABLE_WORM_BUCKET||'')||
     env.AWS_ENDPOINT_URL||env.AWS_ENDPOINT_URL_S3||
     env.AWS_CA_BUNDLE||env.NODE_EXTRA_CA_CERTS||
     env.NODE_TLS_REJECT_UNAUTHORIZED==='0')
    refuse();
  validatePortableS3Endpoint(env.PAPER_PORTABLE_WORM_PROVIDER,
    env.PAPER_PORTABLE_WORM_ENDPOINT);
  const phase=env.PAPER_PORTABLE_WORM_PHASE;
  if(phase!=='preflight'&&phase!=='receipt')refuse();
  const fields=['PAPER_PORTABLE_WORM_RECEIPT_KEY',
    'PAPER_PORTABLE_WORM_RECEIPT_VERSION',
    'PAPER_PORTABLE_WORM_RECEIPT_SHA256'];
  if((phase==='receipt'&&fields.some(x=>!env[x]))||
     (phase==='preflight'&&fields.some(x=>env[x])))refuse();
  let s3,providers;
  const require=createRequire(path.join(env.PAPER_WORM_SDK_ROOT,'package.json'));
  try{
    const dependencies=['@aws-sdk/client-s3','@aws-sdk/credential-providers'];
    for(const dep of dependencies)
      if(require(dep+'/package.json').version!=='3.1174.0')refuse();
    // These SDKs are installed only in the isolated read-only operator's
    // directory; do not force them into Paper's production dependency graph.
    s3=require(dependencies[0]);
    providers=require(dependencies[1]);
  }catch{refuse()}
  const host=new URL(env.PAPER_PORTABLE_WORM_ENDPOINT).hostname;
  const region=env.PAPER_PORTABLE_WORM_PROVIDER==='storj'?
    'us-east-1':host.split('.')[1];
  // Explicit HTTPS origin, no implicit endpoint discovery and no SDK retry
  // on ambiguous provider errors.
  const client=new s3.S3Client({
    endpoint:env.PAPER_PORTABLE_WORM_ENDPOINT,
    region,forcePathStyle:true,maxAttempts:1,
    credentials:providers.fromIni({profile:env.PAPER_PORTABLE_WORM_READER_PROFILE})
  });
  try{
    const result=await inspectPortableS3ObjectLock({
      provider:env.PAPER_PORTABLE_WORM_PROVIDER,
      endpoint:env.PAPER_PORTABLE_WORM_ENDPOINT,
      reader:client,commands:s3,
      bucket:env.PAPER_PORTABLE_WORM_BUCKET,
      sample:phase==='receipt'?{
        key:env.PAPER_PORTABLE_WORM_RECEIPT_KEY,
        versionId:env.PAPER_PORTABLE_WORM_RECEIPT_VERSION,
        sha256:env.PAPER_PORTABLE_WORM_RECEIPT_SHA256
      }:null
    });
    process.stdout.write(JSON.stringify({
      schema:'paper.portable-s3.worm-observation.v1',
      provider:result.provider,phase,observedAt:new Date().toISOString(),
      configurationObserved:result.configurationObserved,
      receiptVerified:result.receiptVerified,
      retentionDays:result.retentionDays,
      operatorIndependenceVerified:false,
      conditionalCreateOnlyVerified:false,latestHeadVerified:false,
      releaseAccepted:false
    })+'\n');
  }finally{client.destroy()}
}
main().catch(error=>{
  // Do not print SDK errors, credentials, arbitrary endpoints or response
  // headers. Logs are safe for security review without leaking secrets.
  process.stderr.write('REFUSED: '+(typeof error?.code==='string'&&
    error.code.startsWith('PORTABLE_WORM_')?error.code:
    'PORTABLE_WORM_REMOTE_UNAVAILABLE')+'\n');
  process.exitCode=1;
});
