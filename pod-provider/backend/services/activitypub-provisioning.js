const { MoleculerError } = require('moleculer').Errors;

function boundedPositiveInteger(name, fallback, maximum) {
  const raw = process.env[name];
  const value = raw === undefined ? fallback : Number(raw);
  if (!Number.isSafeInteger(value) || value < 1 || value > maximum) {
    throw new Error(`${name} must be an integer between 1 and ${maximum}`);
  }
  return value;
}

module.exports = {
  name: 'activitypub-provisioning',
  dependencies: ['activitypub', 'auth.account'],
  settings: {
    actorReadinessDelayMs: boundedPositiveInteger('APODS_ACTIVITYPUB_PROVISIONING_DELAY_MS', 1000, 10_000),
    actorReadinessMaxTries: boundedPositiveInteger('APODS_ACTIVITYPUB_PROVISIONING_MAX_TRIES', 60, 300)
  },
  actions: {
    provisionForAccount: {
      params: {
        canonicalAccountId: 'string|min:1',
        webId: 'string|min:1',
        username: 'string|min:1',
        profile: { type: 'object', optional: true }
      },
      async handler(ctx) {
        const { canonicalAccountId, webId, username } = ctx.params;

        if (canonicalAccountId !== webId) {
          throw new MoleculerError(
            'Current provisioning path requires canonicalAccountId to equal webId',
            400,
            'CANONICAL_ACCOUNT_ID_WEBID_MISMATCH'
          );
        }

        // In SemApps pod-provider mode, activitypub.actor.get treats an actor as
        // remote whenever ctx.meta.dataset is absent. That is unsafe as a
        // provisioning barrier in a horizontal Pod cell: the actor is local and
        // its authoritative dataset belongs to the local account. Resolve that
        // binding from auth.account rather than trusting caller-supplied routing
        // metadata, then make the local dataset explicit for the whole wait.
        const account = await ctx.call('auth.account.findByWebId', { webId });
        const dataset = account?.username;
        if (typeof dataset !== 'string' || dataset.length === 0) {
          throw new MoleculerError(
            `Unable to resolve the local dataset for ActivityPub actor ${webId}`,
            500,
            'ACTIVITYPUB_PROVISIONING_DATASET_UNAVAILABLE'
          );
        }
        if (dataset !== username) {
          throw new MoleculerError(
            `ActivityPub provisioning account/dataset mismatch for ${webId}`,
            409,
            'ACTIVITYPUB_PROVISIONING_DATASET_MISMATCH'
          );
        }

        const actor = await ctx.call(
          'activitypub.actor.awaitCreateComplete',
          {
            actorUri: webId,
            // SemApps already requires publicKey, inbox, outbox, followers and
            // following. Keep the extra list non-duplicative and extend the
            // bounded convergence window for horizontally loaded Pod cells.
            additionalKeys: ['preferredUsername'],
            delayMs: this.settings.actorReadinessDelayMs,
            maxTries: this.settings.actorReadinessMaxTries
          },
          { meta: { dataset } }
        );

        if (!actor?.id || !actor?.inbox || !actor?.outbox) {
          throw new MoleculerError('ActivityPub actor provisioning is incomplete', 500, 'ACTIVITYPUB_PROVISIONING_FAILED');
        }

        const preferredUsername = actor.preferredUsername || username;
        const hostname = new URL(actor.id).hostname;

        return {
          actorId: actor.id,
          handle: `@${preferredUsername}@${hostname}`,
          inbox: actor.inbox,
          outbox: actor.outbox,
          followers: actor.followers || null,
          following: actor.following || null
        };
      }
    }
  }
};
