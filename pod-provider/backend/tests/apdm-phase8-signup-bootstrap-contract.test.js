'use strict';

const fs = require('fs');
const path = require('path');

// Phase 8 production prerequisites are merged: blocked/muted ActivityPub
// collection bootstrap carries owning actor context and warm backend restarts
// must not repeat the legacy O(accounts) compatibility walk.
const AUTH_SOURCE = fs.readFileSync(path.join(__dirname, '../services/core/auth.js'), 'utf8');
const API_SOURCE = fs.readFileSync(path.join(__dirname, '../services/api.js'), 'utf8');
const BLOCKED_SOURCE = fs.readFileSync(
  path.join(__dirname, '../services/activitypub-blocked-collection.service.js'),
  'utf8'
);
const MUTED_SOURCE = fs.readFileSync(
  path.join(__dirname, '../services/activitypub-muted-collection.service.js'),
  'utf8'
);
const PHASE8_COMPOSE = fs.readFileSync(path.join(__dirname, '../../docker-compose-phase8.yml'), 'utf8');

describe('APDM Phase 8 signup bootstrap contract', () => {
  test('ATProto opt-out gates only ATProto after Tier 1 key and ActivityPub provisioning', () => {
    const keyWait = AUTH_SOURCE.indexOf('await this._waitForKeyContainerWithTimeout(ctx, webId);');
    const activityPubProvision = AUTH_SOURCE.indexOf("activitypub-provisioning.provisionForAccount");
    const atprotoGate = AUTH_SOURCE.indexOf('if (this.settings.atproto.autoProvisionOnSignup)');
    const atprotoProvision = AUTH_SOURCE.indexOf("atproto-provisioning.provisionForAccount");

    expect(keyWait).toBeGreaterThan(-1);
    expect(activityPubProvision).toBeGreaterThan(keyWait);
    expect(atprotoGate).toBeGreaterThan(activityPubProvision);
    expect(atprotoProvision).toBeGreaterThan(atprotoGate);
  });

  test('one internal action owns the full production-equivalent local bootstrap barrier', () => {
    expect(AUTH_SOURCE).toContain('awaitBootstrapComplete: {');
    expect(AUTH_SOURCE).toContain("callBootstrapReadiness('auth-agent.waitForResourceCreation', { webId })");
    expect(AUTH_SOURCE).toContain("callBootstrapReadiness('agent-registry.waitForResourceCreation', { webId })");
    expect(AUTH_SOURCE).toContain("callBootstrapReadiness('auth-registry.waitForResourceCreation', { webId })");
    expect(AUTH_SOURCE).toContain("callBootstrapReadiness('data-registry.waitForResourceCreation', { webId })");
    expect(AUTH_SOURCE).toContain("callBootstrapReadiness('activitypub.actor.awaitCreateComplete'");
    expect(AUTH_SOURCE).toContain("callBootstrapReadiness('data-registry.awaitCreateComplete', { webId })");
    expect(AUTH_SOURCE).toContain("callBootstrapReadiness('type-indexes.awaitCreateComplete', { webId })");
  });

  test('independent readiness barriers converge concurrently without dropping checks', () => {
    expect(AUTH_SOURCE).toContain("await Promise.all([\n          callBootstrapReadiness('auth-agent.waitForResourceCreation', { webId })");
    expect(AUTH_SOURCE).toContain("await Promise.all([\n          callBootstrapReadiness('data-registry.awaitCreateComplete', { webId })");
  });

  test('normal signup uses the shared barrier while deferral is structurally non-production', () => {
    expect(AUTH_SOURCE).toContain("process.env.APODS_FORCE_COMPLETE_SIGNUP_BOOTSTRAP === 'true'");
    expect(AUTH_SOURCE).toContain("process.env.NODE_ENV !== 'production' && process.env.APODS_DEFER_COMPLETE_SIGNUP_BOOTSTRAP === 'true'");
    expect(AUTH_SOURCE).toContain('if (forceCompleteSignupBootstrap && deferCompleteSignupBootstrap) return res;');
    expect(AUTH_SOURCE).toContain("await ctx.call('auth.awaitBootstrapComplete', { webId: res.webId });");
  });

  test('forced benchmark retries only timeout-shaped readiness failures', () => {
    expect(AUTH_SOURCE).toContain('APODS_FORCE_COMPLETE_SIGNUP_BOOTSTRAP_ATTEMPTS');
    expect(AUTH_SOURCE).toContain('isRetryableBootstrapTimeout');
    expect(AUTH_SOURCE).toContain('!isRetryableBootstrapTimeout(error)');
    expect(AUTH_SOURCE).toContain('attempt >= forcedBootstrapReadinessAttempts');
    expect(AUTH_SOURCE).toContain('waiting for resource failed\\. no results after\\s+\\d+\\s+tries');
  });

  test('gateway keeps the production timeout default while allowing a benchmark override', () => {
    expect(API_SOURCE).toContain('process.env.APODS_HTTP_SERVER_TIMEOUT_MS || 300000');
  });

  test('Phase 8 warm restarts inherit durable one-time blocked and muted migrations', () => {
    for (const [source, marker] of [
      [BLOCKED_SOURCE, 'urn:activitypods:migration:blocked-collections-v1'],
      [MUTED_SOURCE, 'urn:activitypods:migration:muted-collections-v1']
    ]) {
      expect(source).toContain(marker);
      expect(source).toContain('SELECT ?completed');
      expect(source).toContain('FILTER(?completed = true)');
      expect(source).toContain('const migrationComplete = Array.isArray(markerRows) && markerRows.length > 0;');
    }
  });

  test('Phase 8 overlay defers but does not skip full local bootstrap', () => {
    expect(PHASE8_COMPOSE).toContain("APODS_AUTO_PROVISION_ATPROTO_ON_SIGNUP: 'false'");
    expect(PHASE8_COMPOSE).toContain("APODS_FORCE_COMPLETE_SIGNUP_BOOTSTRAP: 'true'");
    expect(PHASE8_COMPOSE).toContain("APODS_DEFER_COMPLETE_SIGNUP_BOOTSTRAP: 'true'");
    expect(PHASE8_COMPOSE).toContain("APODS_KEY_CONTAINER_WAIT_TIMEOUT_MS: '90000'");
    expect(PHASE8_COMPOSE).toContain("APODS_FORCE_COMPLETE_SIGNUP_BOOTSTRAP_ATTEMPTS: '3'");
    expect(PHASE8_COMPOSE).toContain("APDM_P8_SIGNUP_TIMEOUT_MS: '900000'");
    expect(PHASE8_COMPOSE).toContain("APODS_HTTP_SERVER_TIMEOUT_MS: '960000'");
    expect(PHASE8_COMPOSE).toContain("APDM_P8_PROVISION_BATCH_SIZE: '${APDM_P8_PROVISION_BATCH_SIZE:-24}'");
    expect(PHASE8_COMPOSE).toContain("APDM_P8_BOOTSTRAP_CONCURRENCY: '${APDM_P8_BOOTSTRAP_CONCURRENCY:-8}'");
  });
});
