const { assertUnifiedRequest, assertUnifiedResult } = require('../utils/unified-identity-policy');
const { MoleculerError } = require('moleculer').Errors;

module.exports = {
  name: 'unified-account',

  settings: {
    defaults: {
      enableSolid: true,
      enableActivityPub: true,
      enableAtproto: true,
      atprotoDidMethod: 'plc'
    }
  },

  dependencies: [
    'provider-capabilities',
    'accounts',
    'webid-provisioning',
    'activitypub-provisioning',
    'atproto-provisioning',
    'identitybindings',
    'account-provisioning-state'
  ],

  actions: {
    create: {
      params: {
        username: 'string|min:1',
        email: { type: 'string', optional: true },
        password: 'string|min:8',
        profile: {
          type: 'object',
          props: {
            displayName: 'string|min:1',
            summary: { type: 'string', optional: true }
          }
        },
        solid: {
          type: 'object',
          optional: true,
          props: {
            enabled: { type: 'boolean', optional: true }
          }
        },
        activitypub: {
          type: 'object',
          optional: true,
          props: {
            enabled: { type: 'boolean', optional: true }
          }
        },
        atproto: {
          type: 'object',
          optional: true,
          props: {
            enabled: { type: 'boolean', optional: true },
            requestedHandle: { type: 'string', optional: true },
            didMethod: { type: 'enum', values: ['plc'], optional: true },
            force: { type: 'boolean', optional: true }
          }
        }
      },
      async handler(ctx) {
        const input = ctx.params;
        let requestedProtocols;
        try {
          requestedProtocols = assertUnifiedRequest(input);
        } catch (error) {
          throw new MoleculerError(error.message, 400, error.code);
        }

        await ctx.call('provider-capabilities.assertAccountProvisioningGrant', {
          grant: ctx.meta?.accountProvisioning || {},
          requestedProtocols
        });

        const enableSolid = requestedProtocols.solid;
        const enableActivityPub = requestedProtocols.activitypub;
        const enableAtproto = requestedProtocols.atproto;
        const atprotoDidMethod = 'plc';

        const warnings = [];
        const failedPhases = [];

        const provisioning = await ctx.call('account-provisioning-state.begin', {
          username: input.username
        });

        const provisioningId = provisioning.provisioningId;

        let canonical = null;
        let solid = null;
        let activitypub = null;
        let atproto = null;
        let currentPhase = 'canonical_account';

        try {
          currentPhase = 'canonical_account';
          await ctx.call('account-provisioning-state.markPhase', {
            provisioningId,
            phase: currentPhase,
            status: 'started'
          });

          canonical = await ctx.call('accounts.create', {
            username: input.username,
            email: input.email,
            password: input.password,
            profile: input.profile
          });

          await ctx.call('account-provisioning-state.markPhase', {
            provisioningId,
            phase: currentPhase,
            status: 'completed'
          });

          // The accounts adapter has already executed auth.signup. In the
          // real provider that one action provisions AP, did:plc, PDS state
          // and the Solid bootstrap. Do not submit another PLC operation.
          const signupEvidence = canonical.signupProvisioning || null;
          if (signupEvidence && signupEvidence.webId !== canonical.canonicalAccountId) {
            throw new MoleculerError('Signup returned inconsistent account identity', 503, 'UNIFIED_IDENTITY_INCOMPLETE');
          }
          if (process.env.NODE_ENV === 'production' && !signupEvidence) {
            throw new MoleculerError('Authoritative signup completion evidence is missing', 503, 'UNIFIED_IDENTITY_INCOMPLETE');
          }

          if (enableSolid) {
            currentPhase = 'webid';
            await ctx.call('account-provisioning-state.markPhase', {
              provisioningId,
              phase: currentPhase,
              status: 'started'
            });

            solid = await ctx.call('webid-provisioning.create', {
              canonicalAccountId: canonical.canonicalAccountId,
              username: input.username,
              profile: input.profile
            });

            await ctx.call('account-provisioning-state.markPhase', {
              provisioningId,
              phase: currentPhase,
              status: 'completed'
            });
          }

          if (!solid?.webId) {
            throw new MoleculerError('WebID provisioning did not return a webId', 500, 'WEBID_PROVISIONING_FAILED');
          }

          if (canonical.canonicalAccountId !== solid.webId) {
            throw new MoleculerError('Canonical account ID and WebID disagree', 503, 'UNIFIED_IDENTITY_INCOMPLETE');
          }

          if (enableActivityPub) {
            currentPhase = 'activitypub';
            await ctx.call('account-provisioning-state.markPhase', {
              provisioningId,
              phase: currentPhase,
              status: 'started'
            });

            activitypub = await ctx.call('activitypub-provisioning.provisionForAccount', {
              canonicalAccountId: canonical.canonicalAccountId,
              webId: solid.webId,
              username: input.username,
              profile: input.profile
            });

            await ctx.call('account-provisioning-state.markPhase', {
              provisioningId,
              phase: currentPhase,
              status: 'completed'
            });
          }

          if (enableAtproto) {
            currentPhase = 'atproto';
            await ctx.call('account-provisioning-state.markPhase', {
              provisioningId,
              phase: currentPhase,
              status: 'started'
            });

            if (signupEvidence) {
              // Use the DID returned by the authoritative signup path,
              // cross-checking its protected identity binding. A second
              // provisioning call can create duplicate keys or PLC operations.
              const binding = await ctx.call('identitybindings.getByCanonicalAccountId', {
                canonicalAccountId: canonical.canonicalAccountId
              });
              if (!binding || binding.webId !== solid.webId ||
                  binding.activityPubActorId !== activitypub?.actorId ||
                  binding.atprotoDid !== signupEvidence.did ||
                  binding.repoInitialized !== true ||
                  !binding.repoRootCid || !binding.repoRev ||
                  binding.atprotoSource === 'external' ||
                  binding.atprotoManaged === false ||
                  !binding.atSigningKeyRef || !binding.atRotationKeyRef ||
                  !binding.atprotoPdsUrl) {
                throw new MoleculerError('Persisted identity binding is incomplete or inconsistent', 503, 'UNIFIED_IDENTITY_INCOMPLETE');
              }
              atproto = {
                did: signupEvidence.did,
                handle: signupEvidence.atprotoHandle,
                repoInitialized: signupEvidence.repoInitialized === true,
                atprotoPdsUrl: binding.atprotoPdsUrl
              };
            } else {
              // Only the isolated legacy test fixture may need provisioning
              // after the stubbed accounts.create action. Production NEVER
              // takes this path.
              if (process.env.NODE_ENV === 'production') {
                throw new MoleculerError('Signup did not complete AT Protocol provisioning', 503, 'UNIFIED_IDENTITY_INCOMPLETE');
              }
              atproto = await ctx.call('atproto-provisioning.provisionForAccount', {
                canonicalAccountId: canonical.canonicalAccountId,
                webId: solid.webId,
                requestedHandle: input.atproto?.requestedHandle || input.username,
                activityPubActorId: activitypub?.actorId || solid.webId,
                activityPubHandle: activitypub?.handle || null,
                didMethod: atprotoDidMethod,
                profile: input.profile,
                force: input.atproto?.force ?? false
              });
            }

            try {
              assertUnifiedResult({
                webId: solid.webId, actorId: activitypub?.actorId,
                did: atproto?.did, repoInitialized: atproto?.repoInitialized
              });
            } catch (error) {
              throw new MoleculerError(error.message, 503, error.code);
            }

            await ctx.call('account-provisioning-state.markPhase', {
              provisioningId,
              phase: currentPhase,
              status: 'completed'
            });
          }

          await ctx.call('account-provisioning-state.finalize', {
            provisioningId,
            state: 'completed'
          });

          return {
            canonicalAccountId: canonical.canonicalAccountId,
            webId: solid.webId,
            activitypub: activitypub
              ? {
                  actorId: activitypub.actorId,
                  handle: activitypub.handle,
                  inbox: activitypub.inbox,
                  outbox: activitypub.outbox
                }
              : null,
            atproto: atproto
              ? {
                  did: atproto.did,
                  handle: atproto.handle,
                  repoInitialized: !!atproto.repoInitialized,
                  atprotoPdsUrl: atproto.atprotoPdsUrl || null
                }
              : null,
            solid: {
              webId: solid.webId,
              podBaseUrl: solid.podBaseUrl
            },
            provisioning: {
              state: 'completed',
              warnings: warnings.length > 0 ? warnings : undefined
            },
            createdAt: canonical.createdAt || new Date().toISOString()
          };
        } catch (e) {
          failedPhases.push(currentPhase);

          try {
            await ctx.call('account-provisioning-state.markPhase', {
              provisioningId,
              phase: currentPhase,
              status: 'failed',
              detail: e.message
            });

            await ctx.call('account-provisioning-state.finalize', {
              provisioningId,
              state: 'failed'
            });
          } catch (stateErr) {
            this.logger.warn(
              `Failed to update provisioning state after error in phase "${currentPhase}": ${stateErr.message}`
            );
          }

          const statusCode = Number.isFinite(Number(e.code)) ? Number(e.code) : 500;

          throw new MoleculerError(
            `Unified account provisioning failed during phase "${currentPhase}": ${e.message}`,
            statusCode,
            e.type || 'UNIFIED_ACCOUNT_PROVISIONING_FAILED',
            { phase: currentPhase }
          );
        }
      }
    }
  },

  methods: {
    requestedProtocolsFromInput(input) {
      return {
        solid: true,
        activitypub: true,
        atproto: true
      };
    }
  }
};
