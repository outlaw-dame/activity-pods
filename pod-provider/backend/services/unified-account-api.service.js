const { assertUnifiedRequest } = require('../utils/unified-identity-policy');
const { Errors } = require('moleculer');
const { MoleculerError } = Errors;
const crypto = require('crypto');

module.exports = {
  name: 'unified-account-api',
  dependencies: ['api', 'provider-capabilities', 'unified-account'],

  async started() {
    await this.broker.call('api.addRoute', {
      route: {
        path: '/',
        authorization: false,
        authentication: false,
        bodyParsers: { json: { strict: false } },
        onBeforeCall(ctx, route, req) {
          ctx.meta.$headers = req.headers;
        },
        aliases: {
          'POST /api/accounts/create': 'unified-account-api.create'
        }
      },
      toBottom: false
    });

    this.logger.info('[UnifiedAccount] Route POST /api/accounts/create registered');
  },

  actions: {
    async create(ctx) {
      // This entry point requires an *actual* verified signed PDS repo,
      // durable PostgreSQL account ledger, and enforceable SAI authority.
      // The current candidates are deliberately nonactivated. Do not
      // allow a config toggle to turn fixture booleans into live accounts.
      if (process.env.NODE_ENV === 'production') {
        throw new MoleculerError(
          'Unified account release gate is closed until canonical PDS, PostgreSQL and SAI verification',
          503,
          'UNIFIED_ACCOUNT_RELEASE_GATE_CLOSED',
          { retryable: false }
        );
      }
      let provisioningGrant = null;
      let accountCreationStarted = false;

      try {
        const accountParams = this.normalizeAccountCreateParams(ctx.params || {});
        const headers = ctx.meta?.$headers || {};
        const appClientId = ctx.params?.appClientId;
        const idempotencyKey = headers['idempotency-key'] || headers['Idempotency-Key'] || ctx.params?.idempotencyKey;
        const requestedProtocols = this.requestedProtocolsFromAccountParams(accountParams);

        provisioningGrant = await ctx.call('provider-capabilities.reserveAccountProvisioning', {
          appClientId,
          authorization: headers.authorization || headers.Authorization || '',
          origin: headers.origin || headers.Origin || '',
          redirectUri: ctx.params?.redirectUri,
          idempotencyKey,
          requestFingerprint: this.fingerprintAccountCreateRequest({
            appClientId,
            redirectUri: ctx.params?.redirectUri,
            accountParams,
            requestedProtocols
          }),
          username: accountParams.username,
          email: accountParams.email,
          requestedProtocols,
          verification: ctx.params?.verification
        });

        if (provisioningGrant.idempotency?.replay === true) {
          ctx.meta.$statusCode = provisioningGrant.idempotency.statusCode || 201;
          return provisioningGrant.idempotency.response;
        }

        // The RPC can commit a WebID or PLC side effect and then time out.
        // From this point forward, no catch handler may mark the reservation
        // definitively failed or release it for a second identity creation.
        accountCreationStarted = true;
        ctx.meta.$statusCode = 201;
        const result = await ctx.call('unified-account.create', accountParams, {
          meta: {
            ...(ctx.meta || {}),
            accountProvisioning: provisioningGrant
          }
        });

        // An account may already be provisioned when this acknowledgment is
        // lost. Do not return 201 or release its idempotency reservation as
        // "failed": either action could cause a second DID on retry.
        try {
          const committed = await ctx.call('provider-capabilities.completeAccountProvisioning', {
            grant: provisioningGrant,
            response: result,
            statusCode: ctx.meta.$statusCode || 201
          });
          // A lost/expired reservation must never be interpreted as
          // successful durable completion. For opt-in idempotency, the
          // completed record must be visible to the authoritative store.
          if (provisioningGrant.idempotencyKey &&
              (committed?.ok !== true || committed.stored !== true)) {
            throw new Error('Account completion reservation was not persisted');
          }
        } catch (stateErr) {
          this.logger.error('[UnifiedAccount] Durable completion acknowledgement was not confirmed');
          throw new MoleculerError(
            'Account state requires reconciliation before a retry',
            503,
            'ACCOUNT_COMPLETION_UNCERTAIN',
            { retryable: false }
          );
        }

        return result;
      } catch (e) {
        if (accountCreationStarted) {
          // The underlying lifecycle may have succeeded before failing at
          // the transport layer. Keep the reservation in-progress until the
          // authoritative store reconciles WebID, AP, PLC and PDS.
          const uncertainType = e.type === 'ACCOUNT_COMPLETION_UNCERTAIN'
            ? e.type : 'ACCOUNT_PROVISIONING_UNCERTAIN';
          throw new MoleculerError(
            'Account provisioning outcome needs reconciliation before a retry',
            503,
            uncertainType,
            { retryable: false }
          );
        }
        if (provisioningGrant && provisioningGrant.idempotency?.replay !== true) {
          try {
            await ctx.call('provider-capabilities.failAccountProvisioning', {
              grant: provisioningGrant,
              reasonCode: e.type || 'provisioning_failed',
              message: e.message
            });
          } catch (stateErr) {
            this.logger.warn(`[UnifiedAccount] Failed to mark provisioning idempotency failure: ${stateErr.message}`);
          }
        }

        const statusCode = Number.isFinite(Number(e.code)) ? Number(e.code) : 500;
        throw new MoleculerError(
          e.message || 'Unable to create account',
          statusCode,
          e.type || 'UNIFIED_ACCOUNT_CREATE_FAILED',
          {
            phase: e.data?.phase,
            capabilityId: e.data?.capabilityId,
            reasonCode: e.data?.reasonCode,
            retryable: e.data?.retryable
          }
        );
      }
    }
  },

  methods: {
    normalizeAccountCreateParams(params) {
      const accountParams = { ...params };
      const protocols = params.protocols && typeof params.protocols === 'object' ? params.protocols : null;
      const requested = {
        ...accountParams,
        ...(protocols ? {
          solid: protocols.solid ?? accountParams.solid,
          activitypub: protocols.activitypub ?? accountParams.activitypub,
          atproto: protocols.atproto ?? accountParams.atproto
        } : {})
      };
      try {
        // The protocol overlay can shadow an existing identity or migration
        // claim in the original request. Reject the raw input before grant
        // reservation or idempotency state, then validate the normalized
        // effective protocol selection as well.
        assertUnifiedRequest(params);
        assertUnifiedRequest(requested);
      } catch (error) {
        throw new MoleculerError(error.message, 400, error.code);
      }

      if (protocols) {
        if (Object.prototype.hasOwnProperty.call(protocols, 'solid')) {
          accountParams.solid = {
            ...(accountParams.solid || {}),
            enabled: protocols.solid !== false
          };
        }

        if (Object.prototype.hasOwnProperty.call(protocols, 'activitypub')) {
          accountParams.activitypub = {
            ...(accountParams.activitypub || {}),
            enabled: protocols.activitypub !== false
          };
        }

        if (Object.prototype.hasOwnProperty.call(protocols, 'atproto')) {
          const atproto = protocols.atproto;
          const atprotoConfig = atproto && typeof atproto === 'object' ? atproto : { enabled: atproto === true };
          accountParams.atproto = {
            ...(accountParams.atproto || {}),
            enabled: atprotoConfig.enabled !== false,
            requestedHandle:
              atprotoConfig.handle || atprotoConfig.requestedHandle || accountParams.atproto?.requestedHandle,
            didMethod: this.normalizeDidMethod(atprotoConfig.didMethod || accountParams.atproto?.didMethod),
            force: atprotoConfig.force ?? accountParams.atproto?.force
          };
        }
      }

      if (accountParams.atproto?.didMethod) {
        accountParams.atproto = {
          ...accountParams.atproto,
          didMethod: this.normalizeDidMethod(accountParams.atproto.didMethod)
        };
      }

      delete accountParams.appClientId;
      delete accountParams.verification;
      delete accountParams.protocols;
      delete accountParams.acceptedTermsVersion;
      delete accountParams.redirectUri;
      delete accountParams.idempotencyKey;

      return accountParams;
    },

    normalizeDidMethod(value) {
      return value === 'did:plc' ? 'plc' : value;
    },

    requestedProtocolsFromAccountParams(params) {
      return {
        solid: params.solid?.enabled !== false,
        activitypub: params.activitypub?.enabled !== false,
        atproto: params.atproto?.enabled !== false
      };
    },

    fingerprintAccountCreateRequest(input) {
      return crypto
        .createHash('sha256')
        .update(
          this.stableStringify({
            appClientId: input.appClientId || null,
            redirectUri: input.redirectUri || null,
            account: input.accountParams,
            requestedProtocols: input.requestedProtocols
          })
        )
        .digest('hex');
    },

    stableStringify(value) {
      if (Array.isArray(value)) {
        return `[${value.map(item => this.stableStringify(item)).join(',')}]`;
      }

      if (value && typeof value === 'object') {
        return `{${Object.keys(value)
          .sort()
          .map(key => `${JSON.stringify(key)}:${this.stableStringify(value[key])}`)
          .join(',')}}`;
      }

      return JSON.stringify(value);
    }
  }
};
