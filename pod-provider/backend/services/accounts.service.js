const { MoleculerError } = require('moleculer').Errors;

module.exports = {
  name: 'accounts',
  dependencies: ['auth'],
  actions: {
    create: {
      params: {
        username: 'string|min:1',
        email: { type: 'string', optional: true },
        password: 'string|min:8',
        datasetAdminTicket: { type: 'object', optional: true, strict: false },
        accountCoordinatorAdmission: { type: 'object', optional: true, strict: false },
        profile: {
          type: 'object',
          props: {
            displayName: 'string|min:1',
            summary: { type: 'string', optional: true }
          }
        }
      },
      async handler(ctx) {
        const { username, email, password, profile,
          datasetAdminTicket, accountCoordinatorAdmission } = ctx.params;
        if ((datasetAdminTicket !== undefined || accountCoordinatorAdmission !== undefined) &&
            (process.env.NODE_ENV !== 'test' ||
             process.env.APODS_ACCOUNT_COORDINATOR_DISPOSABLE !== 'confirmed' ||
             process.env.APODS_ATPROTO_DATASET_ADMIN_DELEGATION_DISPOSABLE !== 'confirmed')) {
          throw new MoleculerError('Dataset ticket is unavailable outside authenticated fixture',
            503,'ACCOUNT_COORDINATOR_NOT_RELEASED',{retryable:false});
        }

        const existing = await ctx.call('auth.account.findByUsername', { username });
        if (existing) {
          throw new MoleculerError('An account already exists for this username', 409, 'ACCOUNT_ALREADY_EXISTS');
        }

        const signupPayload = {
          username,
          password,
          name: profile.displayName
        };

        if (email) signupPayload.email = email;
        if (profile.summary) signupPayload.summary = profile.summary;
        if (datasetAdminTicket) {
          if (!accountCoordinatorAdmission || typeof accountCoordinatorAdmission !== 'object') {
            throw new MoleculerError('Single-use signup admission is required',
              503,'ACCOUNT_COORDINATOR_ADMISSION_REQUIRED',{retryable:false});
          }
          signupPayload.datasetAdminTicket = datasetAdminTicket;
          signupPayload.accountCoordinatorAdmission = accountCoordinatorAdmission;
        }

        const signupResult = await ctx.call('auth.signup', signupPayload);
        if (!signupResult?.webId) {
          throw new MoleculerError('Account signup failed to return a webId', 500, 'ACCOUNT_CREATE_FAILED');
        }

        const account = await ctx.call('auth.account.findByWebId', { webId: signupResult.webId });

        return {
          canonicalAccountId: signupResult.webId,
          username,
          email: email || account?.email || null,
          createdAt: account?.createdAt || new Date().toISOString(),
          status: account?.disabled ? 'disabled' : 'active',
          // auth.signup already runs the authoritative WebID/AP/AT lifecycle.
          // Retain its non-secret completion evidence for the unified facade;
          // never pass its login token to this provisioning API.
          signupProvisioning: {
            webId: signupResult.webId,
            actorId: signupResult.activityPubActorId || null,
            activityPubHandle: signupResult.activityPubHandle || null,
            did: signupResult.atprotoDid || null,
            atprotoHandle: signupResult.atprotoHandle || null,
            atprotoPdsUrl: signupResult.atprotoPdsUrl || null,
            repoInitialized: signupResult.atprotoRepoInitialized === true
          }
        };
      }
    }
  }
};
