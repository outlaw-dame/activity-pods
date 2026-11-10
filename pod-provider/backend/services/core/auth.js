const path = require('path');
const urlJoin = require('url-join');
const {
  Errors: { MoleculerError }
} = require('moleculer');
const { AuthLocalService } = require('@semapps/auth');
const CONFIG = require('../../config/config');
const transport = require('../../config/transport');

module.exports = {
  mixins: [AuthLocalService],
  dependencies: ['dataset-provisioning', 'activitypub-provisioning', 'atproto-provisioning'],
  settings: {
    baseUrl: CONFIG.BASE_URL,
    jwtPath: path.resolve(__dirname, '../../jwt'),
    accountsDataset: CONFIG.AUTH_ACCOUNTS_DATASET,
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
      const { username, email, password, ...rest } = ctx.params;

      ctx.meta.skipObjectsWatcher = true;
      this.logger.info(`[Auth] signup start for ${username}`);

      if (username) {
        await ctx.call('username-moderation.assertSafe', {
          username,
          flow: 'signup',
          email: email || undefined
        });
        this.logger.info(`[Auth] signup moderation passed for ${username}`);

        await ctx.call('dataset-provisioning.ensureSecureDataset', {
          dataset: String(username).trim().toLowerCase()
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
        ...this.pickAccountData(rest)
      });

      let webId = null;
      try {
        const profileData = { nick: accountData.username, email: accountData.email, ...rest };
        webId = await ctx.call('webid.createWebId', this.pickWebIdData(profileData), {
          meta: { isSignup: true }
        });

        accountData = await ctx.call('auth.account.attachWebId', { accountUri: accountData['@id'], webId });
        ctx.emit('auth.registered', { webId, profileData, accountData });

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
          await this._cleanupPartialAtprotoArtifacts(ctx, webId);
          throw new MoleculerError(
            `${provisioningStage} failed during signup: ${e.message}`,
            Number.isFinite(Number(e.code)) ? Number(e.code) : 500,
            e.type || 'ACCOUNT_PROVISIONING_FAILED'
          );
        }

        const token = await ctx.call('auth.jwt.generateServerSignedToken', { payload: { webId } });

        return {
          token,
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
        if (webId) await this._cleanupPartialAtprotoArtifacts(ctx, webId).catch(() => {});
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
          return /after\s+30s|still has not been created after\s+30s|timed out waiting|waiting for resource failed\. no results after\s+\d+\s+tries/i.test(
            message
          );
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
      try {
        await ctx.call('identitybindings.remove', { canonicalAccountId: webId });
      } catch (err) {
        this.logger.warn(`[Auth] rollback: identitybindings.remove failed for ${webId}: ${err.message}`);
      }
      try {
        await ctx.call('keys.deleteAllKeysForWebId', { webId });
      } catch (err) {
        this.logger.warn(`[Auth] rollback: keys.deleteAllKeysForWebId failed for ${webId}: ${err.message}`);
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
