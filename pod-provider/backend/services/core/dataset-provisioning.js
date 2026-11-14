const { MoleculerError } = require('moleculer').Errors;
const urlJoin = require('url-join');
const fetch = require('node-fetch');
const CONFIG = require('../../config/config');
const { createDelegatedDisposableDataset } = require('../utils/atproto-dataset-admin-delegation');

const WEBACL_GRAPH = 'http://semapps.org/webacl';
const MIRROR_GRAPH = 'http://semapps.org/mirror';

module.exports = {
  name: 'dataset-provisioning',
  dependencies: ['triplestore'],
  actions: {
    ensureSecureDataset: {
      params: {
        dataset: 'string|min:1'
      },
      async handler(ctx) {
        const { dataset } = ctx.params;

        if (dataset.endsWith('Acl') || dataset.endsWith('Mirror')) {
          throw new MoleculerError(
            `Dataset name "${dataset}" is invalid for provisioning`,
            400,
            'INVALID_DATASET_NAME',
            { dataset }
          );
        }

        // The only delegated branch is an explicitly disposable provider
        // test. In particular, never issue a privileged admin request (or
        // return success for an already-existing dataset) before validating
        // the signed pre-account claim. The sidecar authenticates its Ed25519
        // signature and PostgreSQL reservation, not the caller's ctx.meta.
        // The ordinary backend has no issuer key or Fuseki admin secret.
        if (process.env.APODS_ATPROTO_DATASET_ADMIN_DELEGATION_DISPOSABLE === 'confirmed') {
          const delegated = await createDelegatedDisposableDataset({
            dataset,
            ticket: ctx.meta?.atprotoDatasetTicket
          });
          // The admin process may commit just before the call returns.
          // Keep the established SemApps readiness and WebACL/Mirror graph
          // initialization; do not create a second storage authority.
          await ctx.call('triplestore.dataset.waitForCreation', { dataset },
            { timeout: 5000 });
          await this.ensureSemappsNamedGraphs(ctx, dataset);
          return {
            dataset, created: !delegated.idempotent,
            strategy: delegated.strategy
          };
        }

        const exists = await ctx.call('triplestore.dataset.exist', { dataset });
        if (exists) {
          await this.ensureSemappsNamedGraphs(ctx, dataset);
          return { dataset, created: false, strategy: 'already_exists' };
        }

        try {
          // Prefer Fuseki admin creation to avoid known hangs in secure assembler creation.
          await this.createDatasetViaFusekiAdmin(dataset);
          await ctx.call('triplestore.dataset.waitForCreation', { dataset });
          await this.ensureSemappsNamedGraphs(ctx, dataset);

          return { dataset, created: true, strategy: 'fuseki_admin_tdb2' };
        } catch (adminErr) {
          throw new MoleculerError(`Dataset creation failed for "${dataset}"`, 500, 'DATASET_CREATE_FAILED', {
            dataset,
            reason: adminErr.message
          });
        }
      }
    }
  },
  methods: {
    isAssemblerUploadCompatibilityError(err) {
      const message = String(err?.message || '').toLowerCase();
      return (
        message.includes('error when creating secure dataset') ||
        message.includes('unsupported media type') ||
        message.includes('text/turtle') ||
        message.includes('assembler')
      );
    },

    async createDatasetViaFusekiAdmin(dataset) {
      const endpoint = urlJoin(CONFIG.SPARQL_ENDPOINT, '$/datasets');
      const auth = Buffer.from(`${CONFIG.JENA_USER}:${CONFIG.JENA_PASSWORD}`).toString('base64');
      const body = new URLSearchParams({ dbName: dataset, dbType: 'tdb2' }).toString();

      const response = await fetch(endpoint, {
        method: 'POST',
        headers: {
          Authorization: `Basic ${auth}`,
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        body
      });

      if (![200, 201, 204, 409].includes(response.status)) {
        const details = await response.text();
        throw new MoleculerError(
          `Fuseki admin dataset creation failed for "${dataset}"`,
          500,
          'DATASET_ADMIN_CREATE_FAILED',
          { dataset, status: response.status, details }
        );
      }
    },

    async ensureSemappsNamedGraphs(ctx, dataset) {
      const marker = `urn:semapps:dataset-bootstrap:${dataset}`;
      await ctx.call('triplestore.update', {
        dataset,
        webId: 'system',
        query: `
          INSERT DATA {
            GRAPH <${WEBACL_GRAPH}> {
              <${marker}> <urn:semapps:bootstrapAt> "${new Date().toISOString()}" .
            }
            GRAPH <${MIRROR_GRAPH}> {
              <${marker}> <urn:semapps:bootstrapAt> "${new Date().toISOString()}" .
            }
          }
        `
      });
    }
  }
};
