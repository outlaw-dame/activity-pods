'use strict';

/**
 * Deny-first half of the Group/SAI bridge.
 *
 * A successful SAI mutation PRE-hook must first persist a pending marker in the
 * provider's settings dataset. This service deliberately has no "grant" action:
 * re-enabling Group reservations without a complete, serialized reconciliation
 * protocol would recreate the SAI/Fuseki race. A blocked row always denies.
 *
 * Disabled by default while the full SAI mutation surface is audited.
 */
const crypto = require('node:crypto');
const { MoleculerError } = require('moleculer').Errors;
const { assertLiveCollectiveConsent, parseApprovedApps } = require('./utils/collective-access-policy');

const NS = 'http://activitypods.org/ns/core#';
const PREFIX = 'urn:apods:collective-consent:';
const RIGHT = 'apods:CreateGroup';

function invalid() {
  return new MoleculerError('COLLECTIVE_INVALID_CONSENT_IDENTITY', 400,
    'COLLECTIVE_INVALID_CONSENT_IDENTITY');
}

function httpsUri(raw, fragment) {
  if (typeof raw !== 'string' || raw.length > 2048 || /[\u0000-\u0020\u007f\\]/u.test(raw)) throw invalid();
  let uri;
  try { uri = new URL(raw); } catch { throw invalid(); }
  if (uri.protocol !== 'https:' || uri.href !== raw || uri.username ||
      uri.password || uri.search || (!fragment && uri.hash)) throw invalid();
  return raw;
}

function subject(principal, app) {
  const person = httpsUri(principal, true);
  const client = httpsUri(app, false);
  const hash = crypto.createHash('sha256').update(JSON.stringify([person, client, RIGHT])).digest('hex');
  return '<' + PREFIX + hash + '>';
}

function stateQuery(principal, app) {
  const s = subject(principal, app);
  return 'PREFIX apods: <' + NS + '>\n' +
    'SELECT ?revision ?status WHERE { ' + s +
    ' apods:collectiveConsentRevision ?revision ; apods:collectiveConsentStatus ?status . } LIMIT 2';
}


const TOKEN = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;

const BOOTSTRAP_PURPOSE = 'provider.collective.consent.bootstrap.v1';
function assertBootstrapGrant(grant, secret, principal, app, now = Date.now()) {
  if (!secret || Buffer.byteLength(secret) < 32) {
    throw new MoleculerError('COLLECTIVE_BOOTSTRAP_DISABLED', 503, 'COLLECTIVE_BOOTSTRAP_DISABLED');
  }
  const valid = grant && grant.purpose === BOOTSTRAP_PURPOSE &&
    grant.principal === principal && grant.app === app &&
    Number.isSafeInteger(grant.issuedAt) && Number.isSafeInteger(grant.expiresAt) &&
    grant.issuedAt <= now + 10000 && grant.expiresAt >= now &&
    grant.expiresAt > grant.issuedAt && grant.expiresAt - grant.issuedAt <= 60000 &&
    typeof grant.mac === 'string' && /^[0-9a-f]{64}$/u.test(grant.mac);
  if (!valid) throw new MoleculerError('COLLECTIVE_BOOTSTRAP_UNAUTHORIZED', 403, 'COLLECTIVE_BOOTSTRAP_UNAUTHORIZED');
  const fields = [BOOTSTRAP_PURPOSE, principal, app, grant.issuedAt, grant.expiresAt];
  const mac = crypto.createHmac('sha256', secret).update(JSON.stringify(fields)).digest('hex');
  if (!crypto.timingSafeEqual(Buffer.from(grant.mac, 'ascii'), Buffer.from(mac, 'ascii'))) {
    throw new MoleculerError('COLLECTIVE_BOOTSTRAP_UNAUTHORIZED', 403, 'COLLECTIVE_BOOTSTRAP_UNAUTHORIZED');
  }
}
function bootstrapQuery(principal, app) {
  const s = subject(principal, app);
  // Only a virgin ledger can be bootstrapped. Any prior revoke, crashed
  // mutation or completed token makes it permanently ineligible.
  return 'PREFIX apods: <' + NS + '>\n' +
    'INSERT { ' + s + ' apods:collectiveConsentRevision "1" ; ' +
    'apods:collectiveConsentStatus "stable" . }\n' +
    'WHERE { FILTER NOT EXISTS { ' + s + ' ?existing ?value . } }';
}


function beginQuery(principal, app, token) {
  const s = subject(principal, app);
  const t = JSON.stringify(token);
  return 'PREFIX apods: <' + NS + '>\n' +
    'PREFIX xsd: <http://www.w3.org/2001/XMLSchema#>\n' +
    'DELETE { ' + s + ' apods:collectiveConsentRevision ?oldRevision ; ' +
    'apods:collectiveConsentStatus ?oldStatus . }\n' +
    'INSERT { ' + s + ' apods:collectiveConsentRevision ?nextRevision ; ' +
    'apods:collectiveConsentStatus "blocked" ; apods:collectivePendingMutation ' + t + ' . }\n' +
    'WHERE { OPTIONAL { ' + s + ' apods:collectiveConsentRevision ?oldRevision ; ' +
    'apods:collectiveConsentStatus ?oldStatus . } ' +
    'BIND(IF(BOUND(?oldRevision), xsd:integer(?oldRevision) + 1, 1) AS ?nextRevision) }';
}

function pendingQuery(principal, app, token) {
  const s = subject(principal, app);
  return 'PREFIX apods: <' + NS + '>\n' +
    'SELECT ?revision ?status WHERE { ' + s +
    ' apods:collectiveConsentRevision ?revision ; ' +
    'apods:collectiveConsentStatus ?status ; ' +
    'apods:collectivePendingMutation ' + JSON.stringify(token) + ' . } LIMIT 2';
}

function completeQuery(principal, app, token) {
  const s = subject(principal, app);
  const t = JSON.stringify(token);
  // Both operations run in one TDB2 SPARQL-update transaction. A completion
  // may only restore "stable" when no *other* mutation is still pending.
  // The durable completed-token marker lets us prove this exact invocation
  // committed even when other writers race. It must never imply SAI consent.
  return 'PREFIX apods: <' + NS + '>\n' +
    'DELETE { ' + s + ' apods:collectivePendingMutation ' + t + ' . }\n' +
    'INSERT { ' + s + ' apods:collectiveCompletedMutation ' + t + ' . }\n' +
    'WHERE { ' + s + ' apods:collectivePendingMutation ' + t + ' . };\n' +
    'DELETE { ' + s + ' apods:collectiveConsentStatus "blocked" . }\n' +
    'INSERT { ' + s + ' apods:collectiveConsentStatus "stable" . }\n' +
    'WHERE { ' + s + ' apods:collectiveCompletedMutation ' + t + ' ; ' +
    'apods:collectiveConsentStatus "blocked" . ' +
    'FILTER NOT EXISTS { ' + s + ' apods:collectivePendingMutation ?other . } }';
}

function completedQuery(principal, app, token) {
  const s = subject(principal, app);
  return 'PREFIX apods: <' + NS + '>\n' +
    'SELECT ?revision ?status WHERE { ' + s +
    ' apods:collectiveCompletedMutation ' + JSON.stringify(token) + ' ; ' +
    'apods:collectiveConsentRevision ?revision ; ' +
    'apods:collectiveConsentStatus ?status . ' +
    'FILTER NOT EXISTS { ' + s + ' apods:collectivePendingMutation ' +
    JSON.stringify(token) + ' . } } LIMIT 2';
}

function ensureRevision(rows, status) {
  if (!Array.isArray(rows) || rows.length !== 1 ||
      (status && readBinding(rows[0], 'status') !== status) ||
      !['blocked', 'stable'].includes(readBinding(rows[0], 'status')) ||
      !/^[1-9][0-9]*$/u.test(String(readBinding(rows[0], 'revision'))) ||
      !Number.isSafeInteger(Number(readBinding(rows[0], 'revision')))) {
    throw new MoleculerError('COLLECTIVE_CONSENT_FENCE_UNVERIFIED', 503,
      'COLLECTIVE_CONSENT_FENCE_UNVERIFIED');
  }
  return { status: readBinding(rows[0], 'status'), revision: Number(readBinding(rows[0], 'revision')) };
}

function readBinding(row, key) {
  const value = row?.[key];
  return typeof value === 'string' ? value : value?.value;
}

module.exports = {
  name: 'collective-consent-fence',
  settings: {
    enabled: process.env.PROVIDER_COLLECTIVES_CONSENT_BRIDGE_ENABLED === 'true',
    bootstrapEnabled: process.env.PROVIDER_COLLECTIVES_CONSENT_BOOTSTRAP_ENABLED === 'true',
    bootstrapSecret: process.env.PROVIDER_COLLECTIVES_BOOTSTRAP_SECRET || '',
    approvedApps: parseApprovedApps(process.env.PROVIDER_COLLECTIVES_APPROVED_APPS || '')
  },
  actions: {
    bootstrap: {
      params: {
        principal: 'string|min:1', app: 'string|min:1',
        grant: { type: 'object', strict: false }
      },
      async handler(ctx) {
        if (!this.settings.enabled || !this.settings.bootstrapEnabled ||
            process.env.PROVIDER_COLLECTIVES_API_ENABLED === 'true' ||
            process.env.PROVIDER_COLLECTIVES_RESERVATIONS_ENABLED === 'true') {
          throw new MoleculerError('COLLECTIVE_BOOTSTRAP_DISABLED', 503, 'COLLECTIVE_BOOTSTRAP_DISABLED');
        }
        const { principal, app } = ctx.params;
        subject(principal, app); // Strictly validate before crypto or storage.
        assertBootstrapGrant(ctx.params.grant, this.settings.bootstrapSecret, principal, app);
        await assertLiveCollectiveConsent(ctx, {
          principal, app, operation: 'reserve', approvedApps: this.settings.approvedApps
        });
        // No SELECT-then-INSERT race: this conditional update and all mutation
        // markers are in the same TDB2 settings dataset.
        await ctx.call('triplestore.update', {
          dataset: 'settings', webId: 'system', query: bootstrapQuery(principal, app)
        });
        const rows = await ctx.call('triplestore.query', {
          dataset: 'settings', webId: 'system', query: stateQuery(principal, app)
        });
        const state = ensureRevision(rows, 'stable');
        if (state.revision !== 1) {
          throw new MoleculerError('COLLECTIVE_BOOTSTRAP_CONFLICT', 409, 'COLLECTIVE_BOOTSTRAP_CONFLICT');
        }
        await assertLiveCollectiveConsent(ctx, {
          principal, app, operation: 'reserve', approvedApps: this.settings.approvedApps
        });
        return state;
      }
    },
    begin: {
      params: { principal: 'string|min:1', app: 'string|min:1' },
      async handler(ctx) {
        if (!this.settings.enabled) {
          throw new MoleculerError('COLLECTIVE_CONSENT_BRIDGE_DISABLED', 503,
            'COLLECTIVE_CONSENT_BRIDGE_DISABLED');
        }
        const { principal, app } = ctx.params;
        const token = crypto.randomUUID();
        await ctx.call('triplestore.update', {
          dataset: 'settings', webId: 'system',
          query: beginQuery(principal, app, token)
        });
        const rows = await ctx.call('triplestore.query', {
          dataset: 'settings', webId: 'system',
          query: pendingQuery(principal, app, token)
        });
        return { token, ...ensureRevision(rows, 'blocked') };
      }
    },
    finish: {
      params: { principal: 'string|min:1', app: 'string|min:1', token: 'string' },
      async handler(ctx) {
        if (!this.settings.enabled) {
          throw new MoleculerError('COLLECTIVE_CONSENT_BRIDGE_DISABLED', 503,
            'COLLECTIVE_CONSENT_BRIDGE_DISABLED');
        }
        const { principal, app, token } = ctx.params;
        if (!TOKEN.test(token)) throw new MoleculerError(
          'COLLECTIVE_INVALID_MUTATION_TOKEN', 400, 'COLLECTIVE_INVALID_MUTATION_TOKEN'
        );
        await ctx.call('triplestore.update', {
          dataset: 'settings', webId: 'system',
          query: completeQuery(principal, app, token)
        });
        const rows = await ctx.call('triplestore.query', {
          dataset: 'settings', webId: 'system',
          query: completedQuery(principal, app, token)
        });
        return ensureRevision(rows);
      }
    }
  }
};

module.exports.consentSubject = subject;
module.exports._test = { subject, stateQuery, beginQuery, completeQuery, pendingQuery, completedQuery, bootstrapQuery, assertBootstrapGrant };
