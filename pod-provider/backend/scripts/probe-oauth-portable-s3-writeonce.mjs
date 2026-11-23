#!/usr/bin/env node
/**
 * NONACTIVATED OPERATOR ONLY: one-time, permanently retained, synthetic
 * COMPLIANCE Object Lock receipt race. Not a production auth endpoint.
 *
 * This intentionally leaves ONE Object Lock version in a disposable bucket
 * for at least the configured COMPLIANCE retention. There is no cleanup path.
 *
 * Never place provider S3 credentials, signing keys or real owner IDs in CI.
 */
import path from 'node:path';
import {createRequire} from 'node:module';
import {validatePortableS3Endpoint} from
 '../candidates/oauth-portable-s3-custody-readonly.mjs';
import {probeDisposableS3ConditionalCreate} from
 '../candidates/oauth-portable-s3-writeonce-probe.mjs';

const env=process.env;
function refuse(code='PORTABLE_WORM_WRITE_CONFIGURATION_UNSAFE'){
  const error=new Error('Disposable S3 write-once qualification refused');
  error.code=code;throw error;
}
function regionAndEndpoint(){
  if(env.PAPER_PORTABLE_WORM_OPERATOR_CONFIRM!=='disposable-write-approved'||
     env.PAPER_PORTABLE_WORM_WRITE_DISPOSABLE!=='confirmed'||
     typeof env.PAPER_PORTABLE_WORM_ENDPOINT!=='string'||
     !path.isAbsolute(env.PAPER_WORM_SDK_ROOT||'')||
     !/^[A-Za-z0-9_.-]{1,128}$/u.test(env.PAPER_PORTABLE_WORM_READER_PROFILE||'')||
     !/^[A-Za-z0-9_.-]{1,128}$/u.test(env.PAPER_PORTABLE_WORM_WRITER_PROFILE||'')||
     env.PAPER_PORTABLE_WORM_WRITER_PROFILE===env.PAPER_PORTABLE_WORM_READER_PROFILE||
     env.PAPER_PORTABLE_WORM_WRITE_ACK!==
       'permanently-retain:'+env.PAPER_PORTABLE_WORM_BUCKET||
     env.AWS_ENDPOINT_URL||env.AWS_ENDPOINT_URL_S3||env.AWS_CA_BUNDLE||
     env.NODE_EXTRA_CA_CERTS||env.NODE_TLS_REJECT_UNAUTHORIZED==='0')
    refuse();
  const custom=env.PAPER_PORTABLE_WORM_PROVIDER==='custom-s3';
  const approvedEndpoint=custom?env.PAPER_PORTABLE_WORM_APPROVED_ENDPOINT:null;
  validatePortableS3Endpoint(env.PAPER_PORTABLE_WORM_PROVIDER,
    env.PAPER_PORTABLE_WORM_ENDPOINT,approvedEndpoint);
  const style=env.PAPER_PORTABLE_WORM_URL_STYLE||'path';
  if(style!=='path'&&style!=='virtual-host')refuse();
  const hostname=new URL(env.PAPER_PORTABLE_WORM_ENDPOINT).hostname;
  const region=custom?env.PAPER_PORTABLE_WORM_REGION:
    env.PAPER_PORTABLE_WORM_PROVIDER==='storj'?'us-east-1':
      hostname.split('.')[1];
  if(typeof region!=='string'||!/^[a-z0-9-]{2,32}$/u.test(region))
    refuse();
  return {region,approvedEndpoint,style};
}
async function run(){
  const {region,approvedEndpoint,style}=regionAndEndpoint();
  // No external connection occurs until all safety settings validate.
  let s3,profiles;
  try{
    const require=createRequire(path.join(env.PAPER_WORM_SDK_ROOT,'package.json'));
    const pkgs=['@aws-sdk/client-s3','@aws-sdk/credential-providers'];
    for(const pkg of pkgs)
      if(require(pkg+'/package.json').version!=='3.1174.0')refuse();
    s3=require(pkgs[0]);
    profiles=require(pkgs[1]);
  }catch{refuse()}
  const opts={
    region,endpoint:env.PAPER_PORTABLE_WORM_ENDPOINT,
    forcePathStyle:style==='path',maxAttempts:1
  };
  const writer=new s3.S3Client({...opts,credentials:profiles.fromIni({
    profile:env.PAPER_PORTABLE_WORM_WRITER_PROFILE
  })});
  const reader=new s3.S3Client({...opts,credentials:profiles.fromIni({
    profile:env.PAPER_PORTABLE_WORM_READER_PROFILE
  })});
  try{
    const result=await probeDisposableS3ConditionalCreate({
      provider:env.PAPER_PORTABLE_WORM_PROVIDER,
      endpoint:env.PAPER_PORTABLE_WORM_ENDPOINT,approvedEndpoint,
      bucket:env.PAPER_PORTABLE_WORM_BUCKET,writer,reader,
      commands:s3,explicitBucketApproval:env.PAPER_PORTABLE_WORM_WRITE_ACK
    });
    // Only synthetic object metadata and nonactivating boolean flags.
    process.stdout.write(JSON.stringify(result)+'\n');
  }finally{
    writer.destroy();
    reader.destroy();
  }
}
run().catch(error=>{
  const code=typeof error?.code==='string'&&
    error.code.startsWith('PORTABLE_WORM_')?
    error.code:'PORTABLE_WORM_REMOTE_UNAVAILABLE';
  // No S3 exception bodies, credentials, account IDs, headers or URLs.
  process.stderr.write('REFUSED: '+code+'\n');
  process.exitCode=1;
});
