const path = require('path');
const urlJoin = require('url-join');
const {
  Errors: { MoleculerError }
} = require('moleculer');
const { AuthLocalService } = require('@semapps/auth');
const CONFIG = require('../../config/config');
const transport = require('../../config/transport');
const { mustPreserveFailedSignup } = require('../../utils/account-signup-rollback-policy');
const { consumeCoordinatedSignup } = require('../utils/atproto-account-coordinator-client');

module.exports = {
  mixins: [AuthLocalService],
  dependencies: ['dataset-provisioning', 'activitypub-provisioning', 'atproto-provisioning'],
  settings: {
    baseUrl: CONFIG.BASE_URL,
    jwtPath: path.resolve(__dirname, '../../jwt'),
    accountsDataset: process.env.PAPER_LOCAL_NATIVE_AUTH === 'confirmed' ? 'paper-private-auth' : CONFIG.AUTH_ACCOUNTS_DATASET,
    reservedUsernames: CONFIG.AUTH_RESERVED_USER_NAMES,
    minPasswordLength: 8,
    minUsernameLength: 2,
    webIdSelection: ['nick', 'schema:knowsLanguage'],
    formUrl: CONFIG.FRONTEND_URL ? urlJoin(CONFIG.FRONTEND_URL, 'login') : undefined,
    podProvider: true,
    mail: {
      from: `${CONFIG.FROM_NAME} <${CONFIG.FROM_EMAIL}>`,
      transport,
      defaults: {
        locale: CONFIG.DEFAULT_LOCALE,
        frontUrl: CONFIG.FRONTEND_URL
      }
    },
    atproto: {
      autoProvisionOnSignup: process.env.APODS_AUTO_PROVISION_ATPROTO_ON_SIGNUP !== 'false',
      didMethod: process.env.APODS_ATPROTO_DID_METHOD || 'plc',
      keyContainerWaitTimeoutMs: Number(process.env.APODS_KEY_CONTAINER_WAIT_TIMEOUT_MS || 30_000)
    }
  },
  actions: {
    async signup(ctx) {
      // A new production account must be one verified WebID/AP + did:plc
      // identity with a real signed PDS repository. The current managed
      // repository service remains a non-activated fixture, and the legacy
      // ATProto env opt-out must NOT be an escape hatch to create a partial
      // account. Refuse before username registration, dataset, key, DID or
      // external PLC effects. Existing login/session/recovery is untouched.
      // Remove only with a reviewed, cryptographically verified production
      // PDS + durable PostgreSQL/SAI single-writer onboarding cutover.
      if (process.env.NODE_ENV === 'production') {
        throw new MoleculerError(
          'New accounts require verified signed PDS repository provisioning',
          503,
          'ATPROTO_PDS_REPOSITORY_NOT_READY',
          { retryable: false }
        );
      }

      // A signed dataset ticket is an operation-scoped bearer capability.
      // Never include it in rest: rest becomes account profile data,
      // WebID attributes and the auth.registered event payload.
      const { username, email, password, datasetAdminTicket,
        accountCoordinatorAdmission, ...rest } = ctx.params;
      // This is provider-owned enrollment state, never a profile input.
      if (Object.prototype.hasOwnProperty.call(rest, 'signupReservationId')) {
        throw new MoleculerError('Enrollment state is provider-owned',
          400, 'ACCOUNT_ENROLLMENT_INPUT_DENIED', { retryable: false });
      }
      const delegatedDatasetProof =
        process.env.APODS_ATPROTO_DATASET_ADMIN_DELEGATION_DISPOSABLE === 'confirmed';
      if ((datasetAdminTicket !== undefined ||
           accountCoordinatorAdmission !== undefined) && !delegatedDatasetProof) {
        throw new MoleculerError(
          'Signed dataset claim is unavailable outside disposable admission',
          503, 'ACCOUNT_DATASET_CLAIM_NOT_RELEASED', { retryable: false }
        );
      }
      if (delegatedDatasetProof &&
          (process.env.NODE_ENV !== 'test' ||
           process.env.APODS_ACCOUNT_RESERVATION_DISPOSABLE !== 'confirmed' ||
           process.env.APODS_ACCOUNT_COORDINATOR_DISPOSABLE !== 'confirmed' ||
           typeof username !== 'string' || !username ||
           !datasetAdminTicket || typeof datasetAdminTicket !== 'object' ||
           !accountCoordinatorAdmission || typeof accountCoordinatorAdmission !== 'object')) {
        throw new MoleculerError(
          'Durable pre-account reservation claim is required',
          503, 'ACCOUNT_RESERVATION_REQUIRED', { retryable: false }
        );
      }

      // Use the same configured base and join as SemApps webid.createWebId.
      // Catch a provider deployment mismatch before consuming the one-shot admission.
      if (delegatedDatasetProof && (!CONFIG.BASE_URL ||
          datasetAdminTicket.claim?.ownerWebid !== urlJoin(CONFIG.BASE_URL, username))) {
        throw new MoleculerError('Signed dataset owner does not match the provider WebID',
          403, 'ACCOUNT_DATASET_OWNER_MISMATCH', { retryable: false });
      }

      ctx.meta.skipObjectsWatcher = true;
      this.logger.info(`[Auth] signup start for ${username}`);

      if (username) {
        await ctx.call('username-moderation.assertSafe', {
          username,
          flow: 'signup',
          email: email || undefined
        });
        this.logger.info(`[Auth] signup moderation passed for ${username}`);

        if (delegatedDatasetProof) {
          // The signed dataset claim may be replayed for idempotent Jena
          // creation. Identity minting must NOT be idempotently re-entered:
          // consume an independent PG CAS before any dataset/account/WebID/
          // ActivityPub/PLC/PDS mutation. Unknown consume outcomes remain
          // fenced for operator reconciliation, never retried automatically.
          try {
            const admitted = await consumeCoordinatedSignup({
              ticket: datasetAdminTicket,
              admission: accountCoordinatorAdmission,
              dataset: String(username).trim().toLowerCase()
            });
            if (admitted?.admitted !== true) throw new Error('not admitted');
          } catch (error) {
            const conflict = error?.code === 'ACCOUNT_COORDINATOR_INVOCATION_ALREADY_CLAIMED';
            throw new MoleculerError(
              'Canonical signup invocation requires one-time PostgreSQL admission',
              conflict ? 409 : 503,
              conflict ? 'ACCOUNT_SIGNUP_ALREADY_CLAIMED' : 'ACCOUNT_SIGNUP_ADMISSION_UNCERTAIN',
              { retryable: false }
            );
          }
        }

        await ctx.call('dataset-provisioning.ensureSecureDataset', {
          dataset: String(username).trim().toLowerCase(),
          ...(delegatedDatasetProof ? { datasetAdminTicket } : {})
        });

        const datasetExists = await ctx.call('triplestore.dataset.exist', {
          dataset: String(username).trim().toLowerCase()
        });

        this.logger.info(`[Auth] dataset check for ${username}: ${datasetExists ? 'exists' : 'missing'}`);
      }

      let accountData = await ctx.call('auth.account.create', {
        username,
        email,
        password,
        ...this.pickAccountData(rest),
        // Persist the fence with the password, before a WebID or any external
        // identity effect exists. A failed signup must not become login-ready.
        ...(delegatedDatasetProof
          ? { signupReservationId: accountCoordinatorAdmission.reservationId } : {})
      });

      let webId = null;
      let irreversibleIdentityStarted = false;
      try {
        const profileData = { nick: accountData.username, email: accountData.email, ...rest };
        webId = await ctx.call('webid.createWebId', this.pickWebIdData(profileData), {
          meta: { isSignup: true }
        });

        accountData = await ctx.call('auth.account.attachWebId', { accountUri: accountData['@id'], webId });
        // Auth event handlers operate across the settings and per-Pod datasets.
        // Do not propagate the caller's current user/dataset routing metadata:
        // a nested signup call can have changed it (including on a remote cell).
        // Match SemApps' SSO registration contract. The event consumers derive
        // their storage authority from the actual WebID/accountData, not ctx.meta.
        ctx.emit(
          'auth.registered',
          { webId, profileData, accountData: { username: accountData.username, webId } },
          { meta: { webId: null, dataset: null } }
        );

        let activityPubProvisioning = null;
        let atprotoProvisioning = null;
        try {
          await this._waitForKeyContainerWithTimeout(ctx, webId);

          activityPubProvisioning = await ctx.call('activitypub-provisioning.provisionForAccount', {
            canonicalAccountId: webId,
            webId,
            username: accountData.username || username,
            profile: {
              displayName: rest?.name || accountData?.username || username,
              ...(rest?.summary ? { summary: rest.summary } : {})
            }
          });

          if (this.settings.atproto.autoProvisionOnSignup) {
            // This RPC may create keys, a DID genesis or a PDS record before
            // the transport reports an error. Preserve recovery materials if
            // the service is configured for real external side effects.
            irreversibleIdentityStarted = mustPreserveFailedSignup();
            atprotoProvisioning = await ctx.call('atproto-provisioning.provisionForAccount', {
              canonicalAccountId: webId,
              webId,
              requestedHandle: accountData.username || username,
              activityPubActorId: activityPubProvisioning?.actorId || webId,
              activityPubHandle: activityPubProvisioning?.handle || null,
              didMethod: this.settings.atproto.didMethod,
              profile: {
                displayName: rest?.name || accountData?.username || username,
                ...(rest?.summary ? { summary: rest.summary } : {})
              }
            });
          }
        } catch (e) {
          const provisioningStage = this.settings.atproto.autoProvisionOnSignup
            ? 'ActivityPub/ATProto provisioning'
            : 'ActivityPub provisioning';
          this.logger.error(`[Auth] ${provisioningStage} failed for ${webId}: ${e.message}`);
          // Cleanup is owned by the outer catch exactly once.
          throw new MoleculerError(
            `${provisioningStage} failed during signup: ${e.message}`,
            Number.isFinite(Number(e.code)) ? Number(e.code) : 500,
            e.type || 'ACCOUNT_PROVISIONING_FAILED'
          );
        }

        // Canonical completion and explicit owner consent occur later. Even an
        // internal caller must not receive (or transiently mint) a full JWT.
        const token = delegatedDatasetProof ? undefined
          : await ctx.call('auth.jwt.generateServerSignedToken', { payload: { webId } });

        return {
          ...(token === undefined ? {} : { token }),
          webId,
          newUser: true,
          ...(activityPubProvisioning
            ? { activityPubActorId: activityPubProvisioning.actorId, activityPubHandle: activityPubProvisioning.handle }
            : {}),
          ...(atprotoProvisioning
            ? {
                atprotoDid: atprotoProvisioning.did,
                atprotoHandle: atprotoProvisioning.handle,
                atprotoPdsUrl: atprotoProvisioning.atprotoPdsUrl || null,
                atprotoRepoInitialized: !!atprotoProvisioning.repoInitialized
              }
            : {})
        };
      } catch (e) {
        // Coordinated signup already consumed a durable reservation and created its signed
        // dataset before the native account was stored. Preserve that recovery binding.
        if (delegatedDatasetProof || irreversibleIdentityStarted) {
          this.logger.error('[Auth] Preserving failed signup account and signing records for identity reconciliation');
          throw new MoleculerError(
            'Account identity outcome requires reconciliation before retry',
            503,
            'ACCOUNT_IDENTITY_RECONCILIATION_REQUIRED',
            { retryable: false }
          );
        }
        if (webId) {
          try {
            await this._cleanupPartialAtprotoArtifacts(ctx, webId);
          } catch (_cleanupError) {
            // An unknown cleanup outcome is not permission to release a
            // username or mint an unrelated DID on a repeated request.
            throw new MoleculerError(
              'Account cleanup requires reconciliation before retry',
              503,
              'ACCOUNT_CLEANUP_UNCERTAIN',
              { retryable: false }
            );
          }
        }
        await ctx.call('auth.account.remove', { id: accountData['@id'] });
        throw e;
      }
    },

    /**
     * Authoritative full local Pod/bootstrap completion barrier.
     * No API route exposes this action. The normal production signup hook and
     * the Phase 8 fixture runner share it so deferred benchmark provisioning
     * cannot drift from production completeness semantics.
     */
    awaitBootstrapComplete: {
      params: {
        webId: { type: 'string' }
      },
      async handler(ctx) {
        const { webId } = ctx.params;
        const forceCompleteSignupBootstrap = process.env.APODS_FORCE_COMPLETE_SIGNUP_BOOTSTRAP === 'true';
        const forcedBootstrapReadinessAttempts = forceCompleteSignupBootstrap
          ? Math.max(1, Number(process.env.APODS_FORCE_COMPLETE_SIGNUP_BOOTSTRAP_ATTEMPTS || 1))
          : 1;

        const isRetryableBootstrapTimeout = error => {
          const message = String(error?.message || '');
          return /after\s+30s|still has not been created after\s+30s|timed out waiting|Waiting for resource failed\. No results after [0-9]+ tries\./i.test(message);
        };

        const callBootstrapReadiness = async (actionName, params) => {
          for (let attempt = 1; attempt <= forcedBootstrapReadinessAttempts; attempt += 1) {
            try {
              return await ctx.call(actionName, params);
            } catch (error) {
              if (
                !forceCompleteSignupBootstrap ||
                !isRetryableBootstrapTimeout(error) ||
                attempt >= forcedBootstrapReadinessAttempts
              ) {
                throw error;
              }
              this.logger.warn(
                `[Auth] Forced signup bootstrap readiness timed out for ${actionName} (${attempt}/${forcedBootstrapReadinessAttempts}); retrying same readiness condition for ${webId}`
              );
            }
          }
          return undefined;
        };

        await Promise.all([
          callBootstrapReadiness('auth-agent.waitForResourceCreation', { webId }),
          callBootstrapReadiness('agent-registry.waitForResourceCreation', { webId }),
          callBootstrapReadiness('auth-registry.waitForResourceCreation', { webId }),
          callBootstrapReadiness('data-registry.waitForResourceCreation', { webId }),
          callBootstrapReadiness('activitypub.actor.awaitCreateComplete', {
            actorUri: webId,
            additionalKeys: [
              'pim:storage',
              'pim:preferencesFile',
              'interop:hasAuthorizationAgent',
              'interop:hasRegistrySet',
              'solid:publicTypeIndex'
            ]
          })
        ]);

        await Promise.all([
          callBootstrapReadiness('data-registry.awaitCreateComplete', { webId }),
          callBootstrapReadiness('type-indexes.awaitCreateComplete', { webId })
        ]);

        return { webId, complete: true };
      }
    }
  },
  async started() {
    const { pathname: basePath } = new URL(this.settings.baseUrl);
    await this.broker.call('api.removeRoute', { name: 'auth-signup' });
    await this.broker.call('api.addRoute', {
      route: {
        name: 'auth-signup',
        path: `${basePath}/auth/signup`.replace(/\/+/g, '/'),
        aliases: { 'POST /': 'auth.signup' }
      },
      toBottom: false
    });
    this.logger.info('[Auth] /auth/signup route promoted above LDP catch-all');
  },
  methods: {
    async _waitForKeyContainerWithTimeout(ctx, webId) {
      const timeoutMs = Math.max(1_000, Number(this.settings.atproto.keyContainerWaitTimeoutMs) || 30_000);
      let timer;
      const timeoutPromise = new Promise((_, reject) => {
        timer = setTimeout(() => {
          reject(
            new MoleculerError(
              `Timed out waiting for key container for ${webId} after ${timeoutMs}ms`,
              504,
              'KEY_CONTAINER_WAIT_TIMEOUT'
            )
          );
        }, timeoutMs);
        if (typeof timer.unref === 'function') timer.unref();
      });
      try {
        await Promise.race([ctx.call('keys.container.waitForContainerCreation', { webId }), timeoutPromise]);
      } finally {
        if (timer) clearTimeout(timer);
      }
    },

    async _cleanupPartialAtprotoArtifacts(ctx, webId) {
      // Non-production fixture or a failure before irreversible ATProto work.
      // If either cleanup fails, leave the account reserved for reconciliation.
      const failures = [];
      try {
        await ctx.call('identitybindings.remove', { canonicalAccountId: webId });
      } catch (_err) {
        failures.push('identitybindings');
        this.logger.warn('[Auth] Partial identity-binding cleanup requires reconciliation');
      }
      try {
        await ctx.call('keys.deleteAllKeysForWebId', { webId });
      } catch (_err) {
        failures.push('keys');
        this.logger.warn('[Auth] Partial signing-key cleanup requires reconciliation');
      }
      if (failures.length > 0) {
        throw new MoleculerError(
          'Partial identity cleanup failed',
          503,
          'ACCOUNT_CLEANUP_UNCERTAIN',
          { retryable: false }
        );
      }
    }
  },
  hooks: {
    after: {
      async signup(ctx, res) {
        const forceCompleteSignupBootstrap = process.env.APODS_FORCE_COMPLETE_SIGNUP_BOOTSTRAP === 'true';
        const deferCompleteSignupBootstrap =
          process.env.NODE_ENV !== 'production' && process.env.APODS_DEFER_COMPLETE_SIGNUP_BOOTSTRAP === 'true';
        if (process.env.NODE_ENV !== 'production' && !forceCompleteSignupBootstrap) return res;

        // Deferral is structurally non-production and additionally requires the
        // explicit forced-completeness mode. Production always executes the
        // authoritative barrier in the request lifecycle even if a defer flag
        // is accidentally present in its environment.
        if (forceCompleteSignupBootstrap && deferCompleteSignupBootstrap) return res;

        const allowIncompleteSignupBootstrap =
          !forceCompleteSignupBootstrap &&
          (process.env.SEMAPPS_ALLOW_INCOMPLETE_SIGNUP_BOOTSTRAP === 'true' || process.env.NODE_ENV !== 'production');

        try {
          await ctx.call('auth.awaitBootstrapComplete', { webId: res.webId });
        } catch (e) {
          if (!allowIncompleteSignupBootstrap) throw e;
          this.logger.warn(`[Auth] Continuing signup with incomplete local bootstrap for ${res.webId}: ${e.message}`);
        }

        return res;
      }
    }
  }
};
