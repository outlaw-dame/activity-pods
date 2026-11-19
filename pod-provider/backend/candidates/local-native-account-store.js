'use strict';

const { randomUUID } = require('node:crypto');
const { Pool } = require('pg');
const { localPodData } = require('./local-pod-data');
const table = 'paper_private_auth.accounts';
const prefix = 'urn:AuthAccount:';
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const rowToAccount = row => row && { ...row.data, '@id':prefix + row.id };

function accountId(uri) {
  if (typeof uri !== 'string' || !uri.startsWith(prefix) || !uuid.test(uri.slice(prefix.length))) {
    throw new Error('Invalid private account identifier');
  }
  return uri.slice(prefix.length);
}

function fields(object) {
  if (!object || Object.getPrototypeOf(object) !== Object.prototype || Object.keys(object).length > 64 ||
      Object.keys(object).some(key => !/^[A-Za-z][A-Za-z0-9_]{0,63}$/u.test(key) ||
        ['password','constructor','prototype'].includes(key)) || Buffer.byteLength(JSON.stringify(object)) > 65536) {
    throw new Error('Invalid private account fields');
  }
  return object;
}

function localNativeAccountStore(env = process.env) {
  if (!env.PAPER_LOCAL_NATIVE_AUTH_DSN) {
    if (env.PAPER_LOCAL_NATIVE_AUTH || env.SEMAPPS_AUTH_ACCOUNTS_DATASET === 'paper-private-auth') throw new Error('Missing private account connection');
    return undefined;
  }
  if (!localPodData(env) || env.PAPER_ACCOUNTS_DISPOSABLE !== 'confirmed' ||
      env.APODS_ACCOUNT_COORDINATOR_DISPOSABLE !== 'confirmed' ||
      env.PAPER_LOCAL_NATIVE_AUTH !== 'confirmed' || env.SEMAPPS_AUTH_ACCOUNTS_DATASET === 'paper-private-auth') throw new Error('Private account profile refused');
  let url;
  try { url = new URL(env.PAPER_LOCAL_NATIVE_AUTH_DSN); } catch { throw new Error('Invalid private account connection'); }
  if (url.protocol !== 'postgres:' || url.hostname !== '127.0.0.1' || url.port !== '5548' ||
      url.pathname !== '/atproto_signed_repo_proof_test' || url.username !== 'paper_native_account_login' ||
      !url.password || url.search || url.hash) throw new Error('Invalid private account connection');
  return {
    name:'LocalNativeAccountStore',
    serviceCreating(service, schema) {
      if (schema.name !== 'auth.account') return;
      if (schema.adapter?.dataset !== 'paper-private-auth' || schema.adapter?.type !== 'AuthAccount') {
        throw new Error('Private account adapter scope mismatch');
      }
      let pool;
      async function execute(sql, values) {
        try { return await pool.query(sql, values); }
        catch (error) {
          // Driver diagnostics can contain entire rows, including email and password hashes.
          if (error.code === '23505') throw new Error('Private account identity already exists');
          throw new Error('Private account operation unavailable');
        }
      }
      function lookup(query) {
        const keys = Object.keys(fields(query));
        const indexed = ['username','webId','email'].find(key => keys.includes(key));
        const values = [JSON.stringify(query)];
        let where = 'data @> $1::jsonb';
        if (indexed) {
          values.push(query[indexed]);
          where += indexed === 'email' ? " AND lower(data->>'email')=lower($2)" :
            " AND data->>'"+indexed+"'=$2";
        }
        return {where, values};
      }
      schema.adapter = {
        init() {
          pool = new Pool({connectionString:url.href, max:4, connectionTimeoutMillis:2500,
            statement_timeout:3500, query_timeout:4000, idleTimeoutMillis:5000});
          pool.on('error', () => service.logger.warn('Idle private account connection lost'));
        },
        async connect() {
          const result = await execute(`SELECT current_user=session_user AND r.rolcanlogin AND NOT
            (r.rolsuper OR r.rolcreatedb OR r.rolcreaterole OR r.rolreplication OR r.rolbypassrls)
            AND pg_has_role(current_user,'paper_private_auth_runtime','USAGE')
            AND (SELECT count(*) FROM pg_auth_members WHERE member=r.oid)=1
            AND NOT pg_has_role(current_user,'paper_private_auth_runtime','SET')
            AND NOT EXISTS (SELECT 1 FROM pg_auth_members WHERE member='paper_private_auth_runtime'::regrole)
            AND NOT EXISTS (SELECT 1 FROM pg_auth_members WHERE member=r.oid AND (admin_option OR NOT inherit_option))
            AND NOT has_schema_privilege('public','CREATE')
            AND NOT has_database_privilege(current_database(),'CREATE')
            AND NOT has_schema_privilege('paper_private_auth','CREATE')
            AND has_table_privilege('paper_private_auth.accounts','DELETE') AS ok
            FROM pg_roles r WHERE rolname=current_user`);
          if (result.rows[0]?.ok !== true) throw new Error('Private account database role refused');
        },
        disconnect() { return pool.end(); },
        beforeSaveTransformID(entity) { return entity; },
        afterRetrieveTransformID(entity) { return entity; },
        entityToObject(entity) { return entity; },
        async insert(entity) {
          const data = fields(entity);
          const result = await execute('INSERT INTO '+table+' (id,data) VALUES($1,$2) RETURNING id,data',
            [randomUUID(), JSON.stringify(data)]);
          return rowToAccount(result.rows[0]);
        },
        async findById(uri) {
          const result = await execute('SELECT id,data FROM '+table+' WHERE id=$1',[accountId(uri)]);
          return rowToAccount(result.rows[0]);
        },
        findByIds(ids) {
          return execute('SELECT id,data FROM '+table+' WHERE id=ANY($1::uuid[])',[ids.map(accountId)])
            .then(result => result.rows.map(rowToAccount));
        },
        async find({query = {}} = {}) {
          const {where, values} = lookup(query);
          const result = await execute('SELECT id,data FROM '+table+' WHERE '+where+' ORDER BY id',values);
          return result.rows.map(rowToAccount);
        },
        async count({query = {}} = {}) {
          const {where, values} = lookup(query);
          const result = await execute('SELECT count(*) AS n FROM '+table+' WHERE '+where,values);
          return Number(result.rows[0].n);
        },
        async updateById(uri, update) {
          const data = fields(update.$set);
          const unset = Object.keys(data).filter(key => data[key] == null);
          const result = await execute('UPDATE '+table+
            ' SET data=(data || $2::jsonb) - $3::text[] WHERE id=$1 RETURNING id,data',
          [accountId(uri), JSON.stringify(data), unset]);
          return rowToAccount(result.rows[0]);
        },
        async removeById(uri) {
          return (await execute('DELETE FROM '+table+' WHERE id=$1',[accountId(uri)])).rowCount;
        }
      };
    }
  };
}
module.exports = { localNativeAccountStore };
