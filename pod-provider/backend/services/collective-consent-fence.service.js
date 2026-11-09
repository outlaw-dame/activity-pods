'use strict';

/**
 * Deny-first half of the Group/SAI bridge.
 *
 * A successful SAI mutation PRE-hook must first persist an invalidation in the
 * provider's settings dataset. This service deliberately has no "grant" action:
 * re-enabling Group reservations without a complete, serialized reconciliation
 * protocol would recreate the SAI/Fuseki race. A blocked row always denies.
 *
 * Disabled by default while the full SAI mutation surface is audited.
 */
const crypto = require('node:crypto');
const { MoleculerError } = require('moleculer').Errors;

const NS = 'http://activitypods.org/ns/core#';
const PREFIX = 'urn:apods:collective-consent:';
const RIGHT = 'apods:CreateGroup';

function invalid() {
  return new MoleculerError('COLLECTIVE_INVALID_CONSENT_IDENTITY', 400,
    'COLLECTIVE_INVALID_CONSENT_IDENTITY');
}

function httpsUri(raw, fragment) {
  if (typeof raw !== 'string' || raw.length > 2048 || /[\\u0000-\\u0020\\u007f\\\\]/u.test(raw)) throw invalid();
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

function invalidateQuery(principal, app) {
  const s = subject(principal, app);
  return 'PREFIX apods: <' + NS + '>\n' +
    'PREFIX xsd: <http://www.w3.org/2001/XMLSchema#>\n' +
    'DELETE { ' + s + ' apods:collectiveConsentRevision ?oldRevision ; ' +
    'apods:collectiveConsentStatus ?oldStatus . }\n' +
    'INSERT { ' + s + ' apods:collectiveConsentRevision ?nextRevision ; ' +
    'apods:collectiveConsentStatus "blocked" . }\n' +
    'WHERE { OPTIONAL { ' + s + ' apods:collectiveConsentRevision ?oldRevision ; ' +
    'apods:collectiveConsentStatus ?oldStatus . } ' +
    'BIND(IF(BOUND(?oldRevision), xsd:integer(?oldRevision) + 1, 1) AS ?nextRevision) }';
}

function stateQuery(principal, app) {
  const s = subject(principal, app);
  return 'PREFIX apods: <' + NS + '>\n' +
    'SELECT ?revision ?status WHERE { ' + s +
    ' apods:collectiveConsentRevision ?revision ; apods:collectiveConsentStatus ?status . } LIMIT 2';
}

function readBinding(row, key) {
  const value = row?.[key];
  return typeof value === 'string' ? value : value?.value;
}

module.exports = {
  name: 'collective-consent-fence',
  settings: {
    enabled: process.env.PROVIDER_COLLECTIVES_CONSENT_BRIDGE_ENABLED === 'true'
  },
  actions: {
    invalidate: {
      params: { principal: 'string|min:1', app: 'string|min:1' },
      async handler(ctx) {
        if (!this.settings.enabled) {
          throw new MoleculerError('COLLECTIVE_CONSENT_BRIDGE_DISABLED', 503,
            'COLLECTIVE_CONSENT_BRIDGE_DISABLED');
        }
        // No authorization decision may depend on a merely requested write.
        // Failure or an ambiguous response leaves the mutation aborted.
        await ctx.call('triplestore.update', {
          dataset: 'settings', webId: 'system',
          query: invalidateQuery(ctx.params.principal, ctx.params.app)
        });
        const rows = await ctx.call('triplestore.query', {
          dataset: 'settings', webId: 'system',
          query: stateQuery(ctx.params.principal, ctx.params.app)
        });
        if (!Array.isArray(rows) || rows.length !== 1 ||
            readBinding(rows[0], 'status') !== 'blocked' ||
            !/^[1-9][0-9]*$/u.test(String(readBinding(rows[0], 'revision'))) ||
            !Number.isSafeInteger(Number(readBinding(rows[0], 'revision')))) {
          throw new MoleculerError('COLLECTIVE_CONSENT_FENCE_UNVERIFIED', 503,
            'COLLECTIVE_CONSENT_FENCE_UNVERIFIED');
        }
        return { status: 'blocked', revision: Number(readBinding(rows[0], 'revision')) };
      }
    }
  }
};

module.exports._test = { subject, invalidateQuery, stateQuery };
