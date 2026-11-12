'use strict';

// A NON-ACTIVATED PostgreSQL 18 acceptance proof. It tests actual LOGIN
// credentials and SQLSTATE 42501, not mocked role checks or SET ROLE from
// an administrator. No production DB, migrations or credentials are touched.
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { Client } from 'pg';

const DSN = process.env.ATPROTO_REPO_PROOF_DSN || '';
const expected = /^postgres(?:ql)?:\/\/[^@]+@127\.0\.0\.1:5548\/atproto_signed_repo_proof_test$/u;
if (process.env.NODE_ENV !== 'test' ||
    process.env.ATPROTO_REPO_PROOF_DISPOSABLE !== 'confirmed' ||
    !expected.test(DSN)) {
  throw Error('Private authority proof requires disposable local PostgreSQL 18');
}

const random = crypto.randomBytes(8).toString('hex');
const schema = 'paper_private_auth_' + random;
const writer = 'paper_auth_writer_' + random;
const ordinary = 'paper_general_' + random;
const writerSecret = crypto.randomBytes(32).toString('base64url');
const ordinarySecret = crypto.randomBytes(32).toString('base64url');
const identifier = name => {
  if (!/^[a-z_][a-z0-9_]{0,62}$/u.test(name)) {
    throw Error('Invalid internal PostgreSQL identifier');
  }
  return '"' + name + '"';
};
const sqlSchema = identifier(schema);
const authority = sqlSchema + '.canonical_consent';
const created = [];
const admin = new Client({
  connectionString: DSN, connectionTimeoutMillis: 3000,
  query_timeout: 5000
});
let ownerClient;
let ordinaryClient;

function asRoleConnection(user, password) {
  const url = new URL(DSN);
  url.username = user;
  url.password = password;
  return new Client({
    connectionString: url.toString(), connectionTimeoutMillis: 3000,
    query_timeout: 5000
  });
}
async function deny(client, sql, params = []) {
  await assert.rejects(
    client.query(sql, params),
    error => error.code === '42501',
    'An ordinary or underprivileged writer must be denied by PostgreSQL'
  );
}

async function main() {
  await admin.connect();
  try {
    // Secrets contain only unquoted base64url characters. They are not
    // printed, reused or loaded from a deployment environment.
    for (const [name, secret] of [
      [writer, writerSecret], [ordinary, ordinarySecret]
    ]) {
      assert(/^[A-Za-z0-9_-]{43}$/u.test(secret));
      await admin.query(
        'CREATE ROLE ' + identifier(name) +
        " LOGIN PASSWORD '" + secret + "'" +
        ' NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT' +
        ' NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 2'
      );
      created.push(name);
    }
    await admin.query('CREATE SCHEMA ' + sqlSchema);
    await admin.query('REVOKE ALL ON SCHEMA ' + sqlSchema + ' FROM PUBLIC');
    await admin.query('GRANT USAGE ON SCHEMA ' + sqlSchema +
      ' TO ' + identifier(writer) + ', ' + identifier(ordinary));
    await admin.query('CREATE TABLE ' + authority +
      " (owner_id text PRIMARY KEY, app_id text NOT NULL," +
      " revision bigint NOT NULL CHECK (revision > 0)," +
      " state text NOT NULL CHECK (state IN ('active','blocked')))");
    await admin.query('REVOKE ALL ON TABLE ' + authority + ' FROM PUBLIC');
    await admin.query('GRANT SELECT, INSERT, UPDATE ON ' + authority +
      ' TO ' + identifier(writer));
    // Deliberately grant no DELETE, TRUNCATE, REFERENCES or TRIGGER rights.
    // The ordinary service gets schema name resolution but no canonical
    // table permissions; this makes attempts distinguishable from 42P01.

    ownerClient = asRoleConnection(writer, writerSecret);
    ordinaryClient = asRoleConnection(ordinary, ordinarySecret);
    await Promise.all([ownerClient.connect(), ordinaryClient.connect()]);
    assert.equal((await ownerClient.query('SELECT current_user AS u')).rows[0].u, writer);
    assert.equal((await ordinaryClient.query('SELECT current_user AS u')).rows[0].u, ordinary);
    const ownerId = 'https://paper.example.test/alice';
    const appId = 'https://writer.example.test/app';
    await ownerClient.query(
      'INSERT INTO ' + authority +
      ' (owner_id,app_id,revision,state) VALUES ($1,$2,1,$3)',
      [ownerId, appId, 'active']
    );
    await deny(ordinaryClient, 'SELECT * FROM ' + authority + ' WHERE owner_id=$1', [ownerId]);
    await deny(ordinaryClient,
      'UPDATE ' + authority + " SET state='active',revision=99 WHERE owner_id=$1",
      [ownerId]);
    await deny(ordinaryClient,
      'INSERT INTO ' + authority + " VALUES ($1,$2,99,'active')",
      ['https://paper.example.test/attacker', appId]);
    await deny(ordinaryClient, 'DELETE FROM ' + authority + ' WHERE owner_id=$1', [ownerId]);
    await deny(ordinaryClient, 'TRUNCATE TABLE ' + authority);
    await deny(ordinaryClient,
      'CREATE TABLE ' + sqlSchema + '.unauthorized_copy (id text)');
    await deny(ordinaryClient, 'SET ROLE ' + identifier(writer));
    await deny(ownerClient, 'DELETE FROM ' + authority + ' WHERE owner_id=$1', [ownerId]);

    const blocked = await ownerClient.query(
      'UPDATE ' + authority +
      " SET state='blocked',revision=revision+1 WHERE owner_id=$1 RETURNING revision,state",
      [ownerId]
    );
    assert.equal(blocked.rowCount, 1);
    assert.equal(blocked.rows[0].state, 'blocked');
    assert.equal(blocked.rows[0].revision, '2');
    const actual = await admin.query('SELECT owner_id,app_id,revision,state FROM ' + authority);
    assert.equal(actual.rowCount, 1);
    assert.equal(actual.rows[0].owner_id, ownerId);
    assert.equal(actual.rows[0].app_id, appId);
    assert.equal(actual.rows[0].revision, '2');
    assert.equal(actual.rows[0].state, 'blocked');
    console.log(JSON.stringify({
      success: true, scope: 'non-activated-postgresql18-canonical-storage-isolation',
      independentLogins: 2, deniedUnauthorizedOperations: 7,
      deniedWriterDeletion: true, canonicalStateRetained: true
    }));
  } finally {
    // Terminate our own clients before removing test roles. Do not DROP
    // any external schema, database, role or key. Every name has a random,
    // validated per-run prefix; the known disposable DB was verified above.
    if (ordinaryClient) await ordinaryClient.end().catch(() => {});
    if (ownerClient) await ownerClient.end().catch(() => {});
    await admin.query('DROP SCHEMA IF EXISTS ' + sqlSchema + ' CASCADE');
    for (const name of created.reverse()) {
      await admin.query('DROP ROLE ' + identifier(name));
    }
    await admin.end();
  }
}
main().catch(error => {
  console.error('PG private authority proof failed:', error.code || error.name);
  process.exitCode = 1;
});
