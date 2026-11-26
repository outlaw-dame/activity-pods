#!/usr/bin/env node
/**
 * Operator-invoked real S3 COMPLIANCE negative test. PRE-FLIGHT IS READ ONLY.
 * Hostile phase sends one exact-VersionId DELETE and one attempt to shorten
 * that version's retention; no unversioned deletion or retry is ever allowed.
 *
 * Both operations require a disposable bucket, prior receipt evidence,
 * separate reader/adversary local profiles, and exact operator challenge
 * authorization. Never place credentials in CLI arguments, GitHub, or logs.
 */
import path from 'node:path';
import {createRequire} from 'node:module';
import {validatePortableS3Endpoint} from
 '../candidates/oauth-portable-s3-custody-readonly.mjs';
import {probeDisposableS3HostileObjectLock} from
 '../candidates/oauth-portable-s3-hostile-lock-probe.mjs';

const env=process.env;
const PROFILE=/^[A-Za-z0-9_.-]{1,128}$/u;
function refuse(code='PORTABLE_WORM_HOSTILE_CONFIG_UNSAFE'){
 const e=new Error('Independent Object Lock hostile proof refused');
 e.code=code;throw e;
}
function config(){
 const phase=env.PAPER_PORTABLE_WORM_HOSTILE_PHASE;
 if(!['preflight','hostile'].includes(phase)||
    !path.isAbsolute(env.PAPER_WORM_SDK_ROOT||'')||
    !PROFILE.test(env.PAPER_PORTABLE_WORM_READER_PROFILE||'')||
    !['path','virtual-host',''].includes(
      env.PAPER_PORTABLE_WORM_URL_STYLE||'')||
    env.AWS_ENDPOINT_URL||env.AWS_ENDPOINT_URL_S3||
    env.AWS_CA_BUNDLE||env.NODE_EXTRA_CA_CERTS||
    env.NODE_TLS_REJECT_UNAUTHORIZED==='0')
  refuse();
 const hostile=phase==='hostile';
 if((hostile&&(
     env.PAPER_PORTABLE_WORM_OPERATOR_CONFIRM!==
       'hostile-locked-version-approved'||
     env.PAPER_PORTABLE_WORM_HOSTILE_DISPOSABLE!=='confirmed'||
     !PROFILE.test(env.PAPER_PORTABLE_WORM_ADVERSARY_PROFILE||'')||
     env.PAPER_PORTABLE_WORM_ADVERSARY_PROFILE===
       env.PAPER_PORTABLE_WORM_READER_PROFILE||
     env.PAPER_PORTABLE_WORM_ADVERSARY_PROFILE===
       env.PAPER_PORTABLE_WORM_WRITER_PROFILE||
     !/^hostile-locked-version:[a-f0-9]{64}$/u.test(
       env.PAPER_PORTABLE_WORM_HOSTILE_ACK||'')))||
    (!hostile&&(
     env.PAPER_PORTABLE_WORM_OPERATOR_CONFIRM!=='read-only-verified'||
     env.PAPER_PORTABLE_WORM_HOSTILE_ACK||
     env.PAPER_PORTABLE_WORM_ADVERSARY_PROFILE||
     env.PAPER_PORTABLE_WORM_HOSTILE_DISPOSABLE)))
   refuse('PORTABLE_WORM_HOSTILE_OPERATOR_APPROVAL_REQUIRED');
 const custom=env.PAPER_PORTABLE_WORM_PROVIDER==='custom-s3';
 const approvedEndpoint=custom?env.PAPER_PORTABLE_WORM_APPROVED_ENDPOINT:null;
 validatePortableS3Endpoint(env.PAPER_PORTABLE_WORM_PROVIDER,
  env.PAPER_PORTABLE_WORM_ENDPOINT,approvedEndpoint);
 const host=new URL(env.PAPER_PORTABLE_WORM_ENDPOINT).hostname;
 const region=custom?env.PAPER_PORTABLE_WORM_REGION:
  env.PAPER_PORTABLE_WORM_PROVIDER==='storj'?'us-east-1':host.split('.')[1];
 if(typeof region!=='string'||!/^[a-z0-9-]{2,32}$/u.test(region))
  refuse();
 return {phase,region,approvedEndpoint};
}
async function main(){
 const {phase,region,approvedEndpoint}=config();
 let s3,provider;
 try{
  const req=createRequire(path.join(env.PAPER_WORM_SDK_ROOT,'package.json'));
  for(const name of ['@aws-sdk/client-s3','@aws-sdk/credential-providers'])
   if(req(name+'/package.json').version!=='3.1174.0')refuse();
  s3=req('@aws-sdk/client-s3');
  provider=req('@aws-sdk/credential-providers');
 }catch{refuse()}
 const options={region,endpoint:env.PAPER_PORTABLE_WORM_ENDPOINT,
  forcePathStyle:(env.PAPER_PORTABLE_WORM_URL_STYLE||'path')==='path',
  maxAttempts:1};
 const reader=new s3.S3Client({...options,credentials:provider.fromIni({
  profile:env.PAPER_PORTABLE_WORM_READER_PROFILE
 })});
 const adversary=phase==='hostile'?new s3.S3Client({
  ...options,credentials:provider.fromIni({
   profile:env.PAPER_PORTABLE_WORM_ADVERSARY_PROFILE
  })
 }):null;
 try{
  const result=await probeDisposableS3HostileObjectLock({
   provider:env.PAPER_PORTABLE_WORM_PROVIDER,
   endpoint:env.PAPER_PORTABLE_WORM_ENDPOINT,approvedEndpoint,
   bucket:env.PAPER_PORTABLE_WORM_BUCKET,reader,adversary,commands:s3,
   sample:{
    key:env.PAPER_PORTABLE_WORM_RECEIPT_KEY,
    versionId:env.PAPER_PORTABLE_WORM_RECEIPT_VERSION,
    sha256:env.PAPER_PORTABLE_WORM_RECEIPT_SHA256
   },phase,explicitApproval:phase==='hostile'?
    env.PAPER_PORTABLE_WORM_HOSTILE_ACK:null
  });
  process.stdout.write(JSON.stringify(result)+'\n');
 }finally{reader.destroy();adversary?.destroy()}
}
main().catch(error=>{
 const code=typeof error?.code==='string'&&
  error.code.startsWith('PORTABLE_WORM_')?
  error.code:'PORTABLE_WORM_HOSTILE_REMOTE_UNAVAILABLE';
 process.stderr.write('REFUSED: '+code+'\n');
 process.exitCode=1;
});
