'use strict';
const fs = require('node:fs');
const path = require('node:path');
const { mustPreserveFailedSignup } = require('../utils/account-signup-rollback-policy');

const signupSource = () => fs.readFileSync(
  path.join(__dirname, '../services/core/auth.js'), 'utf8'
);

describe('irreversible PLC signup rollback safety', () => {
  it('preserves identity authority after production ATProto provisioning starts', () => {
    expect(mustPreserveFailedSignup({ NODE_ENV: 'production' })).toBe(true);
    expect(mustPreserveFailedSignup({
      NODE_ENV: 'production', APODS_ATPROTO_ENABLE_PLC_SUBMISSION: 'false'
    })).toBe(true);
  });
  it('preserves recovery evidence for enabled real PLC submissions in staging', () => {
    expect(mustPreserveFailedSignup({
      NODE_ENV: 'test', APODS_ATPROTO_ENABLE_PLC_SUBMISSION: 'true'
    })).toBe(true);
  });
  it('does not require reserving a mock-only local test account', () => {
    expect(mustPreserveFailedSignup({
      NODE_ENV: 'test', APODS_ATPROTO_ENABLE_PLC_SUBMISSION: 'false'
    })).toBe(false);
  });
  it('starts the irreversible-work guard before any asynchronous ATProto RPC', () => {
    const src=signupSource();
    const begin=src.indexOf('irreversibleIdentityStarted = mustPreserveFailedSignup();');
    const call=src.indexOf("atproto-provisioning.provisionForAccount",begin);
    const catchIndex=src.indexOf('if (irreversibleIdentityStarted) {',call);
    const remove=src.indexOf("'auth.account.remove'",catchIndex);
    expect(begin).toBeGreaterThan(-1);
    expect(call).toBeGreaterThan(begin);
    expect(catchIndex).toBeGreaterThan(call);
    expect(remove).toBeGreaterThan(catchIndex);
    expect(src.slice(catchIndex,remove)).toContain('ACCOUNT_IDENTITY_RECONCILIATION_REQUIRED');
  });
  it('runs cleanup once and refuses to release username after uncertain cleanup', () => {
    const src=signupSource();
    expect((src.match(/await this\._cleanupPartialAtprotoArtifacts\(ctx, webId\)/g)||[]).length)
      .toBe(1);
    expect(src).toContain('ACCOUNT_CLEANUP_UNCERTAIN');
    expect(src).toContain('if (failures.length > 0)');
  });
  it('does not regress the merged distributed registration-event context isolation', () => {
    const src=signupSource();
    expect(src).toContain('meta: { webId: null, dataset: null }');
    expect(src).toContain('Waiting for resource failed');
  });
});
