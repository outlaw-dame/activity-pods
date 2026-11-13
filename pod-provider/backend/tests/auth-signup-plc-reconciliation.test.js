'use strict';
const fs = require('node:fs');
const path = require('node:path');
const { mustPreserveFailedSignup } = require('../utils/account-signup-rollback-policy');

describe('irreversible PLC signup rollback safety', () => {
  it('preserves recovery evidence in production regardless of submission toggle', () => {
    expect(mustPreserveFailedSignup({ NODE_ENV: 'production' })).toBe(true);
    expect(mustPreserveFailedSignup({
      NODE_ENV: 'production', APODS_ATPROTO_ENABLE_PLC_SUBMISSION: 'false'
    })).toBe(true);
  });

  it('preserves recovery evidence in staging with real PLC submissions', () => {
    expect(mustPreserveFailedSignup({
      NODE_ENV: 'test', APODS_ATPROTO_ENABLE_PLC_SUBMISSION: 'true'
    })).toBe(true);
    expect(mustPreserveFailedSignup({
      NODE_ENV: 'development', APODS_ATPROTO_ENABLE_PLC_SUBMISSION: 'true'
    })).toBe(true);
  });

  it('permits cleanup only in isolated fixture mode without PLC submission', () => {
    expect(mustPreserveFailedSignup({
      NODE_ENV: 'test', APODS_ATPROTO_ENABLE_PLC_SUBMISSION: 'false'
    })).toBe(false);
  });

  it('retains both inner and outer rollback barriers in the production signup source', () => {
    const source = fs.readFileSync(
      path.join(__dirname, '../services/core/auth.js'), 'utf8'
    );
    expect(source).toContain('if (!this._mustPreserveFailedSignup()) {');
    expect(source).toContain('if (webId && this._mustPreserveFailedSignup()) {');
    expect(source).toContain('if (this._mustPreserveFailedSignup()) {');
    expect(source).toContain('ACCOUNT_IDENTITY_RECONCILIATION_REQUIRED');
    expect(source).toContain('return mustPreserveFailedSignup();');
  });

  it('rejects production signup before a DB account, WebID, key or PLC operation', () => {
    const source = fs.readFileSync(
      path.join(__dirname, '../services/core/auth.js'), 'utf8'
    );
    const signup = source.indexOf('async signup(ctx) {');
    const pdsGate = source.indexOf("if (process.env.NODE_ENV === 'production')", signup);
    const accountWrite = source.indexOf("'auth.account.create'", signup);
    const webidWrite = source.indexOf("'webid.createWebId'", signup);
    expect(signup).toBeGreaterThan(-1);
    expect(pdsGate).toBeGreaterThan(signup);
    expect(accountWrite).toBeGreaterThan(pdsGate);
    expect(webidWrite).toBeGreaterThan(accountWrite);
    expect(source.slice(pdsGate, accountWrite)).toContain('ATPROTO_PDS_REPOSITORY_NOT_READY');
  });
});
