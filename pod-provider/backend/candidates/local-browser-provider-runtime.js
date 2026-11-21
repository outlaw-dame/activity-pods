'use strict';

const fs = require('node:fs');
const crypto = require('node:crypto');
const { Pool } = require('pg');
const { createCandidate } = require('./postgres-account-lifecycle');
const { createLocalSignupApp } = require('./local-signup-app');
const { localNativeAccountStore } = require('./local-native-account-store');

const { resolvePlcDirectory } = require('../utils/atproto-plc-directory-policy');

const roles = {
  verifierPool: 'paper_browser_signup_verifier',
  redeemerPool: 'paper_browser_signup_redeemer',
  handoffPool: 'paper_enrollment_handoff',
  pool: 'paper_enrollment_runtime',
  binderPool: 'paper_enrollment_identity_binder'
};

function readConfiguration(filename) {
  const fd = fs.openSync(filename, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
  const bytes = Buffer.alloc(16385);
  try {
    const stat = fs.fstatSync(fd);
    if (!stat.isFile() || stat.uid !== process.getuid() || (stat.mode & 0o077) ||
        stat.size < 2 || stat.size >= bytes.length) throw Error();
    const length = fs.readSync(fd, bytes, 0, bytes.length, 0);
    if (length !== stat.size) throw Error();
    const config = JSON.parse(bytes.subarray(0, length).toString('utf8'));
    const keys = ['passwords', 'transactionKey', 'csrfKey', 'invitationPublicKey', 'appBearer'];
    if (Object.keys(config).sort().join() !== keys.sort().join() ||
        Object.keys(config.passwords).sort().join() !== Object.values(roles).sort().join()) throw Error();
    return config;
  } finally { bytes.fill(0); fs.closeSync(fd); }
}

function key(value) {
  const decoded = Buffer.from(value, 'base64url');
  if (decoded.length !== 32 || decoded.toString('base64url') !== value) throw Error();
  return decoded;
}

function createLocalBrowserRuntime(service, filename) {
  const pools = {};
  const providerId = 'https://paper.example.org';
  try {
    if (!localNativeAccountStore() || process.env.PAPER_BROWSER_ENROLLMENT_DISPOSABLE !== 'confirmed' ||
        process.env.SEMAPPS_HOME_URL !== providerId + '/' || process.env.SEMAPPS_FRONTEND_URL !== providerId + '/') throw Error();
    if (process.env.APODS_ATPROTO_ENABLE_PLC_SUBMISSION !== 'true' ||
        process.env.APODS_ATPROTO_REQUIRE_VERIFIED_REPO !== 'true' ||
        process.env.APODS_AUTO_PROVISION_ATPROTO_ON_SIGNUP === 'false' ||
        process.env.APODS_ATPROTO_HANDLE_DOMAIN !== 'paper.example.org' ||
        resolvePlcDirectory() !== 'http://127.0.0.1:2582' ||
        !process.env.ACTIVITYPODS_TOKEN || process.env.ACTIVITYPODS_TOKEN.length < 32 ||
        !process.env.APODS_ATPROTO_MANAGED_REPO_CAPABILITY || process.env.APODS_ATPROTO_MANAGED_REPO_CAPABILITY.length < 32 ||
        process.env.ACTIVITYPODS_TOKEN === process.env.APODS_ATPROTO_MANAGED_REPO_CAPABILITY) throw Error();
    const config = readConfiguration(filename);
    if (config.csrfKey === config.transactionKey ||
        typeof config.invitationPublicKey !== 'string' || !config.invitationPublicKey.startsWith('-----BEGIN PUBLIC KEY-----')) throw Error();
    const app = createLocalSignupApp();
    for (const [name, role] of Object.entries(roles)) {
      const password = config.passwords[role];
      if (typeof password !== 'string' || password.length < 16 || password.length > 256) throw Error();
      const pool = new Pool({ host: '127.0.0.1', port: 5548, database: 'atproto_signed_repo_proof_test',
        user: role + '_login', password, max: 2, connectionTimeoutMillis: 2500, statement_timeout: 4000,
        query_timeout: 5000, idleTimeoutMillis: 5000, allowExitOnIdle: true });
      pool.on('error', () => service.logger.warn('Idle local enrollment connection lost'));
      pools[name] = pool;
    }
    const { makeLocalBrowserSignupServices } = require('./provider-browser-enrollment-service');
    const services = makeLocalBrowserSignupServices({ ...pools, broker: service.broker, providerId, browserOrigin: providerId,
      appClientId: app.appUri, appUri: app.appUri, returnUri: app.returnUri, fixtureOnly: true,
      invitationPublicKey: crypto.createPublicKey(config.invitationPublicKey), appBearer: config.appBearer,
      transactionKey: key(config.transactionKey), csrfKey: key(config.csrfKey),
      lifecycle: createCandidate({ pool: pools.binderPool, fixtureOnly: true }) });
    services.signupApi.created.call(service);
    service.beginDisposableEnrollment = services.signupApi.methods.beginDisposableEnrollment;
    let admitted;
    const start = () => {
      admitted ??= Promise.all(Object.entries(roles).map(async ([name, role]) => {
          const result = await pools[name].query(`SELECT r.rolname=current_user AND current_user=session_user
            AND r.rolcanlogin AND NOT (r.rolsuper OR r.rolcreaterole OR r.rolcreatedb OR r.rolreplication OR r.rolbypassrls)
            AND (SELECT count(*) FROM pg_auth_members WHERE member=r.oid)=1
            AND EXISTS (SELECT 1 FROM pg_auth_members m JOIN pg_roles p ON p.oid=m.roleid
              WHERE m.member=r.oid AND p.rolname=$1 AND m.inherit_option AND NOT m.admin_option AND NOT m.set_option
              AND NOT (p.rolcanlogin OR p.rolsuper OR p.rolcreaterole OR p.rolcreatedb OR p.rolreplication OR p.rolbypassrls)
              AND NOT EXISTS (SELECT 1 FROM pg_auth_members WHERE member=p.oid))
            AND NOT has_database_privilege(current_database(),'CREATE') AND NOT has_schema_privilege('public','CREATE')
            AS ok FROM pg_roles r WHERE rolname=current_user`, [role]);
          if (result.rows[0]?.ok !== true) throw Error();
        })).catch(() => { throw new Error('Local enrollment database admission refused'); });
      return admitted;
    };
    service.broker.createService({ ...services.schema, async started() {
      await start();
      return services.schema.started.call(this);
    } });
    return { start,
      close() { return Promise.all(Object.values(pools).map(pool => pool.end())); }
    };
  } catch {
    // No pool connects until start() or an action uses it.
    for (const pool of Object.values(pools)) void pool.end();
    throw new Error('Local browser signup configuration refused');
  }
}
module.exports = { createLocalBrowserRuntime };
