'use strict';
// NONACTIVATED isolated PG18 proof; native bcrypt strings are synthetic shapes.
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const {Pool}=require('pg');
if(process.env.CI!=='true'||process.env.NODE_ENV!=='test'||
   process.env.PAPER_CREDENTIAL_NATIVE_DISPOSABLE!=='confirmed'||
   process.env.PAPER_CREDENTIAL_PG_DISPOSABLE!=='confirmed')
  throw Error('Native credential proof not released');
const options={host:process.env.PGHOST,port:Number(process.env.PGPORT),
  database:process.env.PGDATABASE,user:process.env.PGUSER,
  password:process.env.PGPASSWORD,max:2,connectionTimeoutMillis:2500};
const admin=new Pool(options),secondary=[];
const owner='https://paper.example.org/claimtest-12345678';
const op='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const wrong='bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const old='$2b$12$'+'a'.repeat(53),next='$2b$12$'+'b'.repeat(53);
const third='$2b$12$'+'c'.repeat(53);
const q=(pool,text,values=[])=>pool.query(text,values);
async function denied(run,label){
  await assert.rejects(run,e=>e?.code==='42501',
    'Unauthorized operation must fail with PG insufficient-privilege: '+label);
}
function login(role,member,password){
  const pool=new Pool({...options,user:role,password});
  secondary.push(pool);return pool;
}
async function main(){
  try{
    for(const name of ['paper-local-native-auth.sql',
      'paper-credential-epoch-authority-v1.sql',
      'paper-credential-epoch-authority-v2-certified-head.sql',
      'paper-credential-epoch-authority-v3-native-bcrypt.sql'])
      await q(admin,fs.readFileSync(path.resolve(__dirname,'../sql',name),'utf8'));
    await q(admin,"INSERT INTO paper_private_auth.accounts(id,data) VALUES($1,$2::jsonb)",[
      '11111111-1111-4111-8111-111111111111',JSON.stringify({
        username:'claimtest-12345678',webId:owner,
        signupReservationId:'22222222-2222-4222-8222-222222222222',
        hashedPassword:old,preferredLocale:'en',
        email:'tracked@example.test',resetPasswordToken:'prior-reset-capability'
      })
    ]);
    assert.equal((await q(admin,"SELECT paper_credential_epoch.enroll_owner($1) AS ok",[owner])).rows[0].ok,true);
    const identities=[
      ['paper_native_runtime_ci','paper_private_auth_runtime','fixture_runtime'],
      ['paper_native_writer_ci','paper_credential_native_writer','fixture_writer'],
      ['paper_native_attestor_ci','paper_credential_native_attestor','fixture_attestor'],
      ['paper_native_sealer_ci','paper_credential_native_sealer','fixture_sealer'],
      ['paper_native_coordinator_ci','paper_credential_coordinator','fixture_coord']
    ];
    for(const [role,member,password] of identities){
      await q(admin,"CREATE ROLE "+role+" LOGIN PASSWORD '"+password+"'");
      await q(admin,"GRANT "+member+" TO "+role+" WITH INHERIT TRUE, SET FALSE, ADMIN FALSE");
    }
    const [runtime,writer,attestor,sealer,coord]=identities.map(x=>login(...x));
    // Legacy users lack an irreversible unified-owner classification.
    // The new native trigger must not break their existing account flows.
    const legacy='https://paper.example.org/legacy-owner';
    await q(admin,"INSERT INTO paper_private_auth.accounts(id,data) VALUES($1,$2::jsonb)",[
      '33333333-3333-4333-8333-333333333333',
      JSON.stringify({username:'legacy-owner',webId:legacy,
        hashedPassword:old,email:'legacy@example.test'})
    ]);
    await q(runtime,"UPDATE paper_private_auth.accounts SET data=jsonb_set(jsonb_set(jsonb_set(data,'{hashedPassword}',to_jsonb($2::text)),'{resetPasswordToken}',to_jsonb($3::text)),'{email}',to_jsonb($4::text)) WHERE data->>'webId'=$1",
      [legacy,next,'legacy-reset','legacy-updated@example.test']);
    const legacyRow=(await q(admin,"SELECT data FROM paper_private_auth.accounts WHERE data->>'webId'=$1",[legacy])).rows[0]?.data;
    assert.equal(legacyRow.hashedPassword,next);
    assert.equal(legacyRow.resetPasswordToken,'legacy-reset');
    assert.equal(legacyRow.email,'legacy-updated@example.test');
    await q(runtime,"DELETE FROM paper_private_auth.accounts WHERE data->>'webId'=$1",[legacy]);

    // Simulate a physical restore with an outdated/missing local marker
    // while the canonical PG owner ledger still retains the unified owner.
    // This intentionally bypasses triggers ONLY as the disposable CI
    // superuser; the normal restricted role must never be able to do so.
    const rewound='https://paper.example.org/claimtest-recovery12';
    const reservation='44444444-4444-4444-8444-444444444444';
    const accountId='55555555-5555-4555-8555-555555555555';
    await q(admin,'INSERT INTO paper_private_auth.accounts(id,data) VALUES($1,$2::jsonb)',[
      accountId,JSON.stringify({username:'claimtest-recovery12',webId:rewound,
        signupReservationId:reservation,hashedPassword:old,preferredLocale:'en'})
    ]);
    assert.equal((await q(admin,
      'SELECT paper_credential_epoch.enroll_owner($1) AS ok',
      [rewound])).rows[0].ok,true);
    async function restoreMarker(removed) {
      const connection=await admin.connect();
      try {
        await connection.query('BEGIN');
        await connection.query("SET LOCAL session_replication_role='replica'");
        if(removed){
          await connection.query(
            "UPDATE paper_private_auth.accounts SET data=data-'signupReservationId' WHERE id=$1",
            [accountId]);
        }else{
          await connection.query(
            "UPDATE paper_private_auth.accounts SET data=jsonb_set(data,'{signupReservationId}',to_jsonb($2::text)) WHERE id=$1",
            [accountId,reservation]);
        }
        await connection.query('COMMIT');
      }catch(error){
        await connection.query('ROLLBACK');
        throw error;
      }finally{connection.release();}
    }
    await restoreMarker(true);
    assert.equal((await q(admin,"SELECT data ? 'signupReservationId' AS present FROM paper_private_auth.accounts WHERE id=$1",[accountId])).rows[0].present,false);
    const candidateWrites=[
      ['UPDATE paper_private_auth.accounts SET data=jsonb_set(data,\'{preferredLocale}\',to_jsonb($2::text)) WHERE id=$1',[accountId,'fr'],'profile mutation after marker rewind'],
      ["UPDATE paper_private_auth.accounts SET data=jsonb_set(data,'{hashedPassword}',to_jsonb($2::text)) WHERE id=$1",[accountId,next],'password mutation after marker rewind'],
      ["UPDATE paper_private_auth.accounts SET data=jsonb_set(data,'{webId}',to_jsonb($2::text)) WHERE id=$1",[accountId,legacy],'WebID identity reassignment after marker rewind'],
      ["UPDATE paper_private_auth.accounts SET data=jsonb_set(data,'{username}',to_jsonb($2::text)) WHERE id=$1",[accountId,'legacy-owner'],'username identity reassignment after marker rewind']
    ];
    for(const [statement,parameters,label] of candidateWrites)
      await denied(()=>q(runtime,statement,parameters),label);
    await denied(()=>q(runtime,
      'DELETE FROM paper_private_auth.accounts WHERE id=$1',[accountId]),
      'canonical owner deletion after marker rewind');
    // As an additional defense, even the SQL table owner must pass the
    // BEFORE UPDATE trigger on the row ID; privileges cannot skip it.
    await denied(()=>q(admin,
      'UPDATE paper_private_auth.accounts SET id=$2 WHERE id=$1',
      [accountId,'66666666-6666-4666-8666-666666666666']),
      'tracked native account primary key replacement');
    await restoreMarker(false);
    await q(runtime,"UPDATE paper_private_auth.accounts SET data=jsonb_set(data,'{preferredLocale}',to_jsonb($2::text)) WHERE id=$1",[accountId,'fr']);
    assert.equal((await q(admin,
      "SELECT data->>'preferredLocale' AS locale FROM paper_private_auth.accounts WHERE id=$1",
      [accountId])).rows[0].locale,'fr');
    assert.equal((await q(admin,
      'SELECT mode,state,epoch FROM paper_credential_epoch.read_owner($1)',
      [rewound])).rows[0].state,'active');

    await q(runtime,"UPDATE paper_private_auth.accounts SET data=jsonb_set(data,'{preferredLocale}',to_jsonb($2::text)) WHERE data->>'webId'=$1",[owner,'fr']);
    assert.equal((await q(admin,"SELECT data->>'preferredLocale' AS locale FROM paper_private_auth.accounts WHERE data->>'webId'=$1",[owner])).rows[0].locale,'fr');
    await denied(()=>q(runtime,"UPDATE paper_private_auth.accounts SET data=jsonb_set(data,'{hashedPassword}',to_jsonb($2::text)) WHERE data->>'webId'=$1",[owner,next]),'direct bcrypt update');
    await denied(()=>q(runtime,"UPDATE paper_private_auth.accounts SET data=data-'hashedPassword' WHERE data->>'webId'=$1",[owner]),'bcrypt removal');
    await denied(()=>q(runtime,"UPDATE paper_private_auth.accounts SET data=jsonb_set(data,'{resetPasswordToken}',to_jsonb($2::text)) WHERE data->>'webId'=$1",[owner,'attacker-token']),'reset-token issuance');
    await denied(()=>q(runtime,"UPDATE paper_private_auth.accounts SET data=data-'resetPasswordToken' WHERE data->>'webId'=$1",[owner]),'uncoordinated token revocation');
    await denied(()=>q(runtime,"UPDATE paper_private_auth.accounts SET data=jsonb_set(data,'{email}',to_jsonb($2::text)) WHERE data->>'webId'=$1",[owner,'attacker@example.test']),'recovery-email substitution');
    await denied(()=>q(runtime,"UPDATE paper_private_auth.accounts SET data=jsonb_set(data,'{deletedAt}',to_jsonb($2::text)) WHERE data->>'webId'=$1",[owner,'2026-11-23T00:00:00Z']),'unapproved tombstone');

    await denied(()=>q(runtime,"DELETE FROM paper_private_auth.accounts WHERE data->>'webId'=$1",[owner]),'unified owner delete');
    await denied(()=>q(runtime,"UPDATE paper_private_auth.accounts SET data=data-'signupReservationId' WHERE data->>'webId'=$1",[owner]),'enrollment removal');
    await denied(()=>q(runtime,"SELECT paper_credential_epoch.begin_change($1,$2,1)",[owner,op]),'coordinator from account role');
    await denied(()=>q(runtime,"SELECT * FROM paper_credential_epoch.native_writes"),'audit read');
    await denied(()=>q(writer,"SELECT data FROM paper_private_auth.accounts"),'writer full account read');
    await denied(()=>q(writer,"SELECT paper_credential_epoch.seal_verified_native($1,$2,2,decode(repeat('aa',32),'hex'))",[owner,op]),'writer seal');
    await denied(()=>q(attestor,"SELECT * FROM paper_credential_epoch.native_writes"),'attestor audit enumeration');
    await denied(()=>q(sealer,"UPDATE paper_credential_epoch.owners SET epoch=1 WHERE webid=$1",[owner]),'sealer table update');
    const initial=await q(coord,"SELECT previous_epoch::text,following_epoch::text FROM paper_credential_epoch.begin_change($1,$2,1)",[owner,op]);
    assert.equal(initial.rows[0].previous_epoch,'1');
    assert.equal(initial.rows[0].following_epoch,'2');
    const state=async()=>(await q(admin,"SELECT state,epoch,digest FROM paper_credential_epoch.read_certified($1)",[owner])).rows[0];
    assert.equal((await state()).state,'pending');
    const write=async(p,e,hash)=>(await q(writer,"SELECT paper_credential_epoch.write_native_bcrypt($1,$2,$3,$4) AS receipt",[owner,p,e,hash])).rows[0].receipt;
    assert.equal(await write(wrong,2,next),null);
    assert.equal(await write(op,3,next),null);
    assert.equal(await write(op,2,'plaintext'),null);
    assert.equal(await write(op,2,'$2b$31$'+'d'.repeat(53)),null);
    assert.equal(await write(op,2,'$2b$09$'+'d'.repeat(53)),null);
    assert.equal(await write(op,2,old),null);
    assert.equal((await q(admin,"SELECT count(*)::int AS n FROM paper_credential_epoch.native_writes")).rows[0].n,0);
    const client=await writer.connect();
    try{
      await client.query('BEGIN');
      const r=await client.query("SELECT paper_credential_epoch.write_native_bcrypt($1,$2,$3,$4) AS receipt",[owner,op,2,next]);
      assert.equal(Buffer.isBuffer(r.rows[0].receipt),true);
      await client.query('ROLLBACK');
    }finally{client.release();}
    assert.equal((await q(admin,"SELECT count(*)::int AS n FROM paper_credential_epoch.native_writes")).rows[0].n,0);
    assert.equal((await state()).state,'pending');
    const receipt=await write(op,2,next);
    assert.equal(Buffer.isBuffer(receipt),true);
    assert.equal(receipt.length,32);
    assert.equal((await q(admin,"SELECT data->>'hashedPassword' AS hash FROM paper_private_auth.accounts WHERE data->>'webId'=$1",[owner])).rows[0].hash,next);
    assert.equal((await q(admin,"SELECT data ? 'resetPasswordToken' AS token FROM paper_private_auth.accounts WHERE data->>'webId'=$1",[owner])).rows[0].token,false,
      'committed native password change must revoke old reset tokens');

    assert.equal((await state()).state,'pending');
    const confirm=async(p,d)=>(await q(attestor,"SELECT paper_credential_epoch.confirm_native_write($1,$2,2,$3::bytea) AS ok",[owner,p,d])).rows[0].ok;
    assert.equal(await confirm(op,receipt),true);
    assert.equal(await confirm(wrong,receipt),false);
    const seal=async(p,d)=>(await q(sealer,"SELECT paper_credential_epoch.seal_verified_native($1,$2,2,$3::bytea) AS ok",[owner,p,d])).rows[0].ok;
    assert.equal(await seal(op,Buffer.alloc(32,0xaa)),false);
    await denied(()=>q(coord,"SELECT paper_credential_epoch.seal_change($1,$2,2,$3::bytea)",[owner,op,receipt]),'generic digest-only seal');
    assert.equal((await state()).state,'pending');
    assert.equal(await seal(op,receipt),true);
    const fresh=await state();
    assert.equal(fresh.state,'active');assert.equal(fresh.epoch,'2');
    assert.equal(fresh.digest,receipt.toString('hex'));
    assert.equal(await seal(op,receipt),false);
    assert.equal(await write(op,2,third),null);
    assert.equal((await q(admin,"SELECT count(*)::int AS n FROM paper_credential_epoch.native_writes")).rows[0].n,1);
    assert.equal((await q(coord,"SELECT paper_credential_epoch.disable_owner($1) AS ok",[owner])).rows[0].ok,true);
    await denied(()=>q(runtime,"DELETE FROM paper_private_auth.accounts WHERE data->>'webId'=$1",[owner]),'disabled owner replacement');
    assert.equal((await q(admin,"SELECT paper_credential_epoch.enroll_owner($1) AS ok",[owner])).rows[0].ok,false);
    assert.equal((await state()).state,'disabled');
    assert.equal((await state()).epoch,'3');
    console.log('PASS: real PG18 native bcrypt guard, distinct restricted logins, rollback, receipt binding, replay and account replacement; NONACTIVATED');
  }finally{
    await Promise.allSettled(secondary.map(p=>p.end()));
    await admin.end();
  }
}
main().catch(e=>{console.error('Native credential proof failed:',e?.code||e?.name);process.exitCode=1;});
