const crypto = require('crypto');
const urlJoin = require('url-join');
const { ControlledContainerMixin } = require('@semapps/ldp');
const { MIME_TYPES } = require('@semapps/mime-types');
const { MoleculerError } = require('moleculer').Errors;
const { assertUnfencedIdentityBindingMutation } = require('../utils/identitybinding-fence-policy');
const { buildIndexPageQuery, validCursor } = require('../utils/identitybinding-index-query');

const APODS = 'http://activitypods.org/ns/core#';

const BINDING_TYPE = 'apods:AtprotoIdentityBinding';
const INDEX_TYPE = 'apods:AtprotoIdentityBindingIndex';
const PREDICATES = {
  canonicalAccountId: `${APODS}canonicalAccountId`,
  webId: `${APODS}webId`,
  activityPubActorId: `${APODS}activityPubActorId`,
  activityPubHandle: `${APODS}activityPubHandle`,
  atprotoDid: `${APODS}atprotoDid`,
  atprotoHandle: `${APODS}atprotoHandle`,
  atprotoSource: `${APODS}atprotoSource`,
  atprotoManaged: `${APODS}atprotoManaged`,
  atprotoPdsUrl: `${APODS}atprotoPdsUrl`,
  atSigningKeyRef: `${APODS}atSigningKeyRef`,
  atRotationKeyRef: `${APODS}atRotationKeyRef`,
  status: `${APODS}status`,
  repoInitialized: `${APODS}repoInitialized`,
  repoRootCid: `${APODS}repoRootCid`,
  repoRev: `${APODS}repoRev`,
  createdAt: `${APODS}createdAt`,
  updatedAt: `${APODS}updatedAt`
};

module.exports = {
  name: 'identitybindings',
  mixins: [ControlledContainerMixin],
  settings: {
    path: '/identity-bindings',
    acceptedTypes: [BINDING_TYPE],
    readOnly: false,
    excludeFromMirror: true,
    activateTombstones: false,
    podProvider: true,
    newResourcesPermissions: {
      anon: {
        read: false
      },
      user: {
        read: false,
        write: false
      }
    }
  },
  actions: {
    getByCanonicalAccountId: {
      params: {
        canonicalAccountId: { type: 'string', min: 1 }
      },
      async handler(ctx) {
        const canonicalAccountId = String(ctx.params.canonicalAccountId).trim();
        const { resourceUri } = await this._resolveBindingLocation(canonicalAccountId, ctx);
        const resource = await this._getBindingResourceOrNull(resourceUri, ctx);
        return this._toDto(resource);
      }
    },

    upsert: {
      params: {
        canonicalAccountId: { type: 'string', min: 1 },
        webId: { type: 'string', min: 1 },
        activityPubActorId: { type: 'string', optional: true },
        activityPubHandle: { type: 'string', optional: true },
        atprotoDid: { type: 'string', optional: true },
        atprotoHandle: { type: 'string', optional: true },
        atprotoSource: { type: 'enum', values: ['local', 'external'], optional: true },
        atprotoManaged: { type: 'boolean', optional: true },
        atprotoPdsUrl: { type: 'string', optional: true },
        atSigningKeyRef: { type: 'string', optional: true },
        atRotationKeyRef: { type: 'string', optional: true },
        status: { type: 'string', optional: true },
        repoInitialized: { type: 'boolean', optional: true },
        repoRootCid: { type: 'string', optional: true },
        repoRev: { type: 'string', optional: true }
      },
      async handler(ctx) {
        const {
          canonicalAccountId,
          webId,
          activityPubActorId,
          activityPubHandle,
          atprotoDid,
          atprotoHandle,
          atprotoSource,
          atprotoManaged,
          atprotoPdsUrl,
          atSigningKeyRef,
          atRotationKeyRef,
          status,
          repoInitialized,
          repoRootCid,
          repoRev
        } = ctx.params;

        if (canonicalAccountId !== webId) {
          throw new MoleculerError(
            'canonicalAccountId must equal webId in the current implementation phase',
            400,
            'CANONICAL_ACCOUNT_ID_WEBID_MISMATCH'
          );
        }

        const now = new Date().toISOString();
        const { bindingWebId, slug, resourceUri } = await this._resolveBindingLocation(canonicalAccountId, ctx);
        const existing = await this._getBindingResourceOrNull(resourceUri, ctx);

        // Legacy full-resource PUT would discard the atomic RDF fence or
        // overwrite a newer signed repo projection. Do not mutate fenced
        // bindings through an unfenced method.
        this._assertUnfencedMutation(existing, 'upsert');

        const existingValue = key => (existing ? this._readField(existing, key) : null);
        const existingBoolean = key => this._coerceBoolean(existingValue(key));

        const resolvedAtprotoSource = atprotoSource || existingValue('atprotoSource') || 'local';

        const resolvedAtprotoManaged =
          typeof atprotoManaged === 'boolean'
            ? atprotoManaged
            : existingBoolean('atprotoManaged') ?? resolvedAtprotoSource !== 'external';

        const resolvedRepoInitialized =
          typeof repoInitialized === 'boolean' ? repoInitialized : existingBoolean('repoInitialized') ?? false;

        const resource = this._compactNulls({
          '@id': resourceUri,
          '@type': [BINDING_TYPE],
          [PREDICATES.canonicalAccountId]: canonicalAccountId,
          [PREDICATES.webId]: webId,
          [PREDICATES.activityPubActorId]: activityPubActorId || existingValue('activityPubActorId') || webId,
          [PREDICATES.activityPubHandle]: activityPubHandle || existingValue('activityPubHandle') || null,
          [PREDICATES.atprotoDid]: atprotoDid || existingValue('atprotoDid'),
          [PREDICATES.atprotoHandle]: atprotoHandle || existingValue('atprotoHandle'),
          [PREDICATES.atprotoSource]: resolvedAtprotoSource,
          [PREDICATES.atprotoManaged]: resolvedAtprotoManaged,
          [PREDICATES.atprotoPdsUrl]: atprotoPdsUrl || existingValue('atprotoPdsUrl') || null,
          [PREDICATES.atSigningKeyRef]: atSigningKeyRef || existingValue('atSigningKeyRef'),
          [PREDICATES.atRotationKeyRef]: atRotationKeyRef || existingValue('atRotationKeyRef'),
          [PREDICATES.status]: status || existingValue('status') || 'pending',
          [PREDICATES.repoInitialized]: resolvedRepoInitialized,
          [PREDICATES.repoRootCid]: repoRootCid || existingValue('repoRootCid') || null,
          [PREDICATES.repoRev]: repoRev || existingValue('repoRev') || null,
          [PREDICATES.createdAt]: existingValue('createdAt') || now,
          [PREDICATES.updatedAt]: now
        });

        if (existing) {
          await this.actions.put(
            {
              resourceUri,
              resource,
              contentType: MIME_TYPES.JSON,
              webId: 'system'
            },
            { parentCtx: ctx }
          );
        } else {
          await this.actions.post(
            {
              webId: bindingWebId,
              slug,
              resource,
              contentType: MIME_TYPES.JSON
            },
            { parentCtx: ctx }
          );
        }

        const saved = await this.actions.get(
          { resourceUri, webId: 'system', accept: MIME_TYPES.JSON },
          { parentCtx: ctx }
        );
        const dto = this._toDto(saved);
        await this._syncBindingIndex(ctx, dto);
        return dto;
      }
    },

    upsertRepoBootstrap: {
      params: {
        canonicalAccountId: { type: 'string', min: 1 },
        did: { type: 'string', min: 1 },
        handle: { type: 'string', min: 1 },
        repoInitialized: { type: 'boolean' },
        rootCid: { type: 'string', min: 1 },
        rev: { type: 'string', min: 1 }
      },
      async handler(ctx) {
        const existing = await ctx.call('identitybindings.getByCanonicalAccountId', {
          canonicalAccountId: ctx.params.canonicalAccountId
        });

        if (!existing) {
          throw new MoleculerError(
            'Cannot attach repo bootstrap to missing identity binding',
            404,
            'IDENTITY_BINDING_NOT_FOUND'
          );
        }

        if (existing.atprotoDid && existing.atprotoDid !== ctx.params.did) {
          throw new MoleculerError('Repo bootstrap DID mismatch', 400, 'ATPROTO_DID_MISMATCH');
        }

        if (existing.atprotoHandle && existing.atprotoHandle !== ctx.params.handle) {
          throw new MoleculerError('Repo bootstrap handle mismatch', 400, 'ATPROTO_HANDLE_MISMATCH');
        }

        return ctx.call(
          'identitybindings.upsert',
          {
            canonicalAccountId: existing.canonicalAccountId,
            webId: existing.webId,
            activityPubActorId: existing.activityPubActorId,
            activityPubHandle: existing.activityPubHandle,
            atprotoDid: existing.atprotoDid || ctx.params.did,
            atprotoHandle: existing.atprotoHandle || ctx.params.handle,
            atprotoSource: existing.atprotoSource,
            atprotoManaged: existing.atprotoManaged,
            atprotoPdsUrl: existing.atprotoPdsUrl,
            atSigningKeyRef: existing.atSigningKeyRef,
            atRotationKeyRef: existing.atRotationKeyRef,
            status: existing.status || 'active',
            repoInitialized: ctx.params.repoInitialized,
            repoRootCid: ctx.params.rootCid,
            repoRev: ctx.params.rev
          },
          { parentCtx: ctx }
        );
      }
    },

    getByDid: {
      params: {
        atprotoDid: { type: 'string', min: 1 }
      },
      async handler(ctx) {
        const atprotoDid = String(ctx.params.atprotoDid).trim();
        const binding = await this._findByDidWithSparql(ctx, atprotoDid);
        return binding;
      }
    },

    getByHandle: {
      params: {
        atprotoHandle: { type: 'string', min: 1 }
      },
      async handler(ctx) {
        const handle = String(ctx.params.atprotoHandle).trim().toLowerCase();
        const binding = await this._findByHandleWithSparql(ctx, handle);
        return binding;
      }
    },

    list: {
      params: {
        since: { type: 'string', optional: true },
        limit: { type: 'number', integer: true, positive: true, optional: true, convert: true }
      },
      async handler(ctx) {
        return this._listBindingsWithSparql(ctx, {
          since: ctx.params.since || null,
          limit: ctx.params.limit || 100
        });
      }
    },

    /**
     * Remove an identity binding (LDP resource + SPARQL index entry).
     * Idempotent: returns { removed:false } if no binding exists.
     * Used by signup rollback paths to avoid orphaned bindings on failure.
     */
    remove: {
      params: {
        canonicalAccountId: { type: 'string', min: 1 }
      },
      async handler(ctx) {
        const canonicalAccountId = String(ctx.params.canonicalAccountId).trim();
        const { resourceUri } = await this._resolveBindingLocation(canonicalAccountId, ctx);

        const exists = await ctx.call('ldp.resource.exist', { resourceUri, webId: 'system' });
        if (!exists) {
          // Still attempt index cleanup in case of partial state.
          await this._removeBindingIndex(ctx, canonicalAccountId).catch(() => {});
          return { removed: false, canonicalAccountId };
        }

        // Account deletion and signup rollback must not silently remove a
        // projected, fenced repository identity. Deletion needs coordinated
        // PG native-repo state transition and protected Jena CAS.
        const protectedBinding = await this._getBindingResourceOrNull(resourceUri, ctx);
        if (!protectedBinding) {
          throw new MoleculerError(
            'Identity binding disappeared between existence and guarded deletion checks',
            409,
            'IDENTITY_BINDING_MUTATION_RACE'
          );
        }
        this._assertUnfencedMutation(protectedBinding, 'remove');
        await this.actions.delete({ resourceUri, webId: 'system' }, { parentCtx: ctx });
        await this._removeBindingIndex(ctx, canonicalAccountId).catch(err => {
          // Index cleanup is best-effort; LDP resource is the source of truth.
          this.logger.warn(`[identitybindings] index cleanup failed for ${canonicalAccountId}: ${err.message}`);
        });
        return { removed: true, canonicalAccountId };
      }
    }
  },
  methods: {
    _assertUnfencedMutation(resource, operation) {
      try {
        assertUnfencedIdentityBindingMutation(resource, operation);
      } catch (error) {
        throw new MoleculerError(
          error.message,
          Number(error.status) || 409,
          error.code || 'IDENTITY_BINDING_MUTATION_INVALID'
        );
      }
    },

    async _resolveBindingLocation(canonicalAccountId, ctx) {
      const bindingWebId = canonicalAccountId;
      const containerUri = await this.actions.getContainerUri({ webId: bindingWebId }, { parentCtx: ctx });
      const slug = this._bindingSlug(canonicalAccountId);
      const resourceUri = urlJoin(containerUri, slug);
      return { bindingWebId, containerUri, slug, resourceUri };
    },

    async _getBindingResourceOrNull(resourceUri, ctx) {
      try {
        return await this.actions.get(
          { resourceUri, webId: 'system', accept: MIME_TYPES.JSON },
          { parentCtx: ctx }
        );
      } catch (error) {
        if (this._isNotFoundError(error)) return null;
        throw error;
      }
    },

    _isNotFoundError(error) {
      if (!error) return false;
      if (Number(error.code) === 404) return true;
      if (error.code !== undefined && error.code !== null) return false;
      return ['NOT_FOUND', 'RESOURCE_NOT_FOUND', 'LDP_RESOURCE_NOT_FOUND'].includes(error.type);
    },

    _bindingSlug(canonicalAccountId) {
      const digest = crypto.createHash('sha256').update(canonicalAccountId).digest('hex').slice(0, 24);
      return `atproto-${digest}`;
    },

    _bindingIndexUri(canonicalAccountId) {
      const digest = crypto.createHash('sha256').update(canonicalAccountId).digest('hex').slice(0, 24);
      return `urn:identitybindingindex:${digest}`;
    },

    _toDto(resource) {
      if (!resource) return null;

      const get = key => this._readField(resource, key);

      return {
        id: resource.id || resource['@id'],
        canonicalAccountId: get('canonicalAccountId') || null,
        webId: get('webId') || null,
        activityPubActorId: get('activityPubActorId') || get('webId') || null,
        activityPubHandle: get('activityPubHandle') || null,
        atprotoDid: get('atprotoDid') || null,
        atprotoHandle: get('atprotoHandle') || null,
        atprotoSource: get('atprotoSource') || 'local',
        atprotoManaged: this._coerceBoolean(get('atprotoManaged')) ?? true,
        atprotoPdsUrl: get('atprotoPdsUrl') || null,
        atSigningKeyRef: get('atSigningKeyRef') || null,
        atRotationKeyRef: get('atRotationKeyRef') || null,
        status: get('status') || null,
        repoInitialized: this._coerceBoolean(get('repoInitialized')) ?? false,
        repoRootCid: get('repoRootCid') || null,
        repoRev: get('repoRev') || null,
        createdAt: get('createdAt') || null,
        updatedAt: get('updatedAt') || null
      };
    },

    _readField(resource, key) {
      return this._unwrapFieldValue(resource[key] ?? resource[`apods:${key}`] ?? resource[PREDICATES[key]]);
    },

    _unwrapFieldValue(value) {
      if (Array.isArray(value)) {
        if (value.length === 0) return null;
        return this._unwrapFieldValue(value[0]);
      }

      if (value && typeof value === 'object') {
        if (Object.prototype.hasOwnProperty.call(value, '@value')) {
          return this._unwrapFieldValue(value['@value']);
        }
        if (Object.prototype.hasOwnProperty.call(value, 'value')) {
          return this._unwrapFieldValue(value.value);
        }
        if (Object.prototype.hasOwnProperty.call(value, '@id')) {
          return this._unwrapFieldValue(value['@id']);
        }
      }

      return value;
    },

    _coerceBoolean(value) {
      if (typeof value === 'boolean') return value;
      if (typeof value === 'string') {
        const normalized = value.trim().toLowerCase();
        if (normalized === 'true' || normalized === '1') return true;
        if (normalized === 'false' || normalized === '0') return false;
      }
      if (value === 1) return true;
      if (value === 0) return false;
      return null;
    },

    async _findByDidWithSparql(ctx, atprotoDid) {
      return this._findByIndexedFieldWithSparql(ctx, 'atprotoDid', String(atprotoDid).trim());
    },

    _sparqlLiteral(value) {
      if (value === null || value === undefined) return null;
      return JSON.stringify(String(value));
    },

    async _findByIndexedFieldWithSparql(ctx, field, expectedValue) {
      const predicates = {
        atprotoDid: 'atprotoDid',
        atprotoHandle: 'atprotoHandle'
      };
      const predicate = predicates[field];
      if (!predicate) throw new Error(`Unsupported identity index field: ${field}`);

      let rows;
      try {
        rows = await ctx.call('triplestore.query', {
          query: `
            PREFIX apods: <${APODS}>
            SELECT ?canonicalAccountId
            WHERE {
              ?binding apods:${predicate} ${this._sparqlLiteral(expectedValue)} ;
                       a ${INDEX_TYPE} ;
                       apods:canonicalAccountId ?canonicalAccountId .
            }
            LIMIT 1
          `,
          dataset: 'settings',
          webId: 'system'
        });
      } catch (err) {
        // A broken index is a bounded availability error, not permission to
        // enumerate every account and issue N+1 cross-Pod Moleculer calls.
        this.logger.warn('Selective identity index lookup unavailable', {
          field,
          error: err instanceof Error ? err.message : String(err)
        });
        throw new MoleculerError('Identity binding index unavailable', 503, 'IDENTITY_BINDING_INDEX_UNAVAILABLE');
      }

      const canonicalAccountId = this._readQueryBinding(rows?.[0], 'canonicalAccountId');
      if (!canonicalAccountId) return null;

      // The LDP binding is authoritative. Do not downgrade an infrastructure or
      // authorization failure here into an expensive population fallback.
      const binding = await ctx.call(
        'identitybindings.getByCanonicalAccountId',
        { canonicalAccountId },
        { parentCtx: ctx }
      );
      if (!binding) return null;

      const normalize = value => {
        const normalized = String(value || '').trim();
        return field === 'atprotoHandle' ? normalized.toLowerCase() : normalized;
      };
      if (normalize(binding[field]) !== normalize(expectedValue)) return null;
      return binding;
    },

    async _syncBindingIndex(ctx, binding) {
      if (!binding?.canonicalAccountId) return;

      const indexUri = this._bindingIndexUri(binding.canonicalAccountId);
      const triples = [
        `<${indexUri}> a ${INDEX_TYPE} ;`,
        `  apods:canonicalAccountId ${this._sparqlLiteral(binding.canonicalAccountId)} ;`,
        `  apods:webId ${this._sparqlLiteral(binding.webId || binding.canonicalAccountId)} ;`,
        `  apods:activityPubActorId ${this._sparqlLiteral(binding.activityPubActorId || binding.webId || binding.canonicalAccountId)} ;`,
        `  apods:repoInitialized ${this._sparqlLiteral(binding.repoInitialized ? 'true' : 'false')} ;`,
        `  apods:updatedAt ${this._sparqlLiteral(binding.updatedAt || new Date().toISOString())} ;`,
        `  apods:createdAt ${this._sparqlLiteral(binding.createdAt || new Date().toISOString())}`
      ];

      const optionalTriples = [
        ['activityPubHandle', binding.activityPubHandle],
        ['atprotoDid', binding.atprotoDid],
        ['atprotoHandle', binding.atprotoHandle],
        ['atprotoSource', binding.atprotoSource],
        ['atprotoManaged', typeof binding.atprotoManaged === 'boolean' ? String(binding.atprotoManaged) : null],
        ['atprotoPdsUrl', binding.atprotoPdsUrl],
        ['atSigningKeyRef', binding.atSigningKeyRef],
        ['atRotationKeyRef', binding.atRotationKeyRef],
        ['status', binding.status],
        ['repoRootCid', binding.repoRootCid],
        ['repoRev', binding.repoRev]
      ];

      for (const [predicate, value] of optionalTriples) {
        const literal = this._sparqlLiteral(value);
        if (literal) {
          triples.splice(triples.length - 1, 0, `  apods:${predicate} ${literal} ;`);
        }
      }

      const insertBody = `${triples.join('\n')}\n.`;

      await ctx.call('triplestore.update', {
        query: `
          PREFIX apods: <${APODS}>
          DELETE {
            <${indexUri}> ?p ?o .
          }
          INSERT {
${insertBody}
          }
          WHERE {
            OPTIONAL { <${indexUri}> ?p ?o . }
          }
        `,
        dataset: 'settings',
        webId: 'system'
      });
    },

    async _removeBindingIndex(ctx, canonicalAccountId) {
      if (!canonicalAccountId) return;
      const indexUri = this._bindingIndexUri(canonicalAccountId);
      await ctx.call('triplestore.update', {
        query: `
          DELETE { <${indexUri}> ?p ?o . }
          WHERE  { <${indexUri}> ?p ?o . }
        `,
        dataset: 'settings',
        webId: 'system'
      });
    },

    async _findByHandleWithSparql(ctx, atprotoHandle) {
      return this._findByIndexedFieldWithSparql(
        ctx,
        'atprotoHandle',
        String(atprotoHandle).trim().toLowerCase()
      );
    },

    _readQueryBinding(row, key) {
      const value = row?.[key];
      if (typeof value === 'string' || typeof value === 'boolean') return value;
      if (value && typeof value === 'object' && typeof value.value === 'string') {
        return value.value;
      }
      return null;
    },

    _compactNulls(objectValue) {
      return Object.fromEntries(
        Object.entries(objectValue).filter(([, value]) => value !== null && value !== undefined)
      );
    },

    _parseCursor(cursor) {
      if (!cursor) return null;

      try {
        if (typeof cursor !== 'string' || cursor.length > 4096 ||
            !/^[A-Za-z0-9_-]+$/u.test(cursor)) throw new Error('Invalid cursor encoding');
        const parsed = JSON.parse(Buffer.from(cursor, 'base64url').toString('utf8'));
        return validCursor(parsed);
      } catch (_err) {
        throw new MoleculerError('Invalid cursor', 400, 'INVALID_CURSOR');
      }
    },

    _encodeCursor(entry) {
      return Buffer.from(
        JSON.stringify({
          updatedAt: entry.updatedAt,
          canonicalAccountId: entry.canonicalAccountId
        }),
        'utf8'
      ).toString('base64url');
    },

    async _queryBindingsWithSparql(ctx, { cursor = null, limit = 101 } = {}) {
      const results = await ctx.call('triplestore.query', {
        query: buildIndexPageQuery({ cursor, limit }),
        dataset: 'settings',
        webId: 'system'
      });

      return (results || []).map(row => ({
        id: this._readQueryBinding(row, 'binding'),
        canonicalAccountId: this._readQueryBinding(row, 'canonicalAccountId'),
        webId: this._readQueryBinding(row, 'webId'),
        activityPubActorId:
          this._readQueryBinding(row, 'activityPubActorId') || this._readQueryBinding(row, 'webId') || null,
        activityPubHandle: this._readQueryBinding(row, 'activityPubHandle'),
        atprotoDid: this._readQueryBinding(row, 'atprotoDid'),
        atprotoHandle: this._readQueryBinding(row, 'atprotoHandle'),
        atprotoSource: this._readQueryBinding(row, 'atprotoSource') || 'local',
        atprotoManaged: this._coerceBoolean(this._readQueryBinding(row, 'atprotoManaged')) ?? true,
        atprotoPdsUrl: this._readQueryBinding(row, 'atprotoPdsUrl'),
        atSigningKeyRef: this._readQueryBinding(row, 'atSigningKeyRef'),
        atRotationKeyRef: this._readQueryBinding(row, 'atRotationKeyRef'),
        status: this._readQueryBinding(row, 'status'),
        repoInitialized: this._coerceBoolean(this._readQueryBinding(row, 'repoInitialized')) ?? false,
        repoRootCid: this._readQueryBinding(row, 'repoRootCid'),
        repoRev: this._readQueryBinding(row, 'repoRev'),
        createdAt: this._readQueryBinding(row, 'createdAt'),
        updatedAt: this._readQueryBinding(row, 'updatedAt')
      }));
    },

    async _listBindingsWithSparql(ctx, { since, limit }) {
      const safeLimit = Math.max(1, Math.min(Number(limit) || 100, 500));
      const cursor = this._parseCursor(since);
      let rows;
      try {
        // The expensive ordering and keyset filter run in Fuseki, not in
        // Node.js. Only one bounded query is issued per page.
        rows = await this._queryBindingsWithSparql(ctx, {
          cursor,
          limit: safeLimit + 1
        });
      } catch (err) {
        this.logger.warn('Identity binding page query unavailable', {
          error: err instanceof Error ? err.message : String(err)
        });
        throw new MoleculerError('Identity binding index unavailable', 503, 'IDENTITY_BINDING_INDEX_UNAVAILABLE');
      }

      // An index corruption or duplicate optional values must NOT silently
      // expand an unbounded fallback over every user's Pod.
      if (!Array.isArray(rows) || rows.length > safeLimit + 1 ||
          rows.some(b => !b.canonicalAccountId || !b.updatedAt)) {
        throw new MoleculerError('Identity binding index contains inconsistent results', 503,
          'IDENTITY_BINDING_INDEX_INCONSISTENT');
      }
      const items = rows.slice(0, safeLimit);
      const last = items[items.length - 1];

      return {
        items,
        nextCursor: last ? this._encodeCursor(last) : since || null
      };
    }
  }
};
