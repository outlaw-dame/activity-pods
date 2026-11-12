/**
 * ActivityPods Outbox Event Emitter Service
 */
'use strict';

const { ulid } = require('ulid');
const { retryWithBackoff } = require('../utils/backoff');
const { readBoundedAcknowledgement } = require('../utils/activitypub-webhook-ack');
const { validateDeliveryPlanV1 } = require('../utils/activitypub-delivery-plan');
const { resolvePublicSearchConsent } = require('../utils/search-consent');
const { extractHashtagsFromText } = require('../utils/hashtags');

module.exports = {
  name: 'outbox-emitter',
  dependencies: ['activitypub.outbox'],
  settings: {
    remoteDeliveryMode: String(process.env.SEMAPPS_ACTIVITYPUB_REMOTE_DELIVERY_MODE || 'native').trim().toLowerCase(),
    sidecarObservationWebhookUrl: process.env.SIDECAR_OBSERVATION_WEBHOOK_URL || 'http://fedify-sidecar:8080/webhook/outbox-observation',
    sidecarToken: process.env.SIDECAR_TOKEN || '',
    observationWebhookRetries: (() => {
      const value = Number(process.env.OBSERVATION_WEBHOOK_RETRIES);
      return Number.isSafeInteger(value) && value >= 1 ? Math.min(3, value) : 3;
    })(),
    observationWebhookTimeoutMs: (() => {
      const value = Number(process.env.OBSERVATION_WEBHOOK_TIMEOUT_MS);
      return Number.isSafeInteger(value) && value >= 100 ? Math.min(3000, value) : 3000;
    })()
  },
  events: {
    'activitypub.outbox.posted': {
      async handler(ctx) {
        if (this.settings.remoteDeliveryMode === 'external') {
          this.logger.debug('Ignoring raw outbox.posted routing event in APDM external mode');
          return;
        }
        const { activity } = ctx.params;
        const actorUri = typeof activity.actor === 'string' ? activity.actor : activity.actor?.id || null;
        const visibility = this.determineVisibility(activity);
        const isPublicActivity = visibility === 'public' || visibility === 'unlisted';
        const searchConsent = await this.buildSearchConsent(ctx, activity, actorUri);
        const event = await this.buildCommittedEvent(ctx, {
          activity,
          actorUri,
          deliveryTargets: [],
          visibility,
          isPublicActivity,
          searchConsent
        });
        ctx.emit('outbox.event.ready', event);
        await this.deliverObservationToSidecar(event);
      }
    },
    'activitypub.outbox.remote-delivery.handoff-queued': {
      async handler(ctx) {
        if (this.settings.remoteDeliveryMode !== 'external') return;
        const { activity, deliveryPlan } = ctx.params;
        if (!validateDeliveryPlanV1(deliveryPlan)) throw new Error('Refusing invalid ap.delivery-plan.v1 payload');
        if (deliveryPlan.activityId !== (activity.id || activity['@id'])) {
          throw new Error('Delivery Plan activityId does not match emitted Activity');
        }
        const actorUri = deliveryPlan.actorUri;
        const visibility = deliveryPlan.meta.visibility;
        const isPublicActivity = deliveryPlan.meta.isPublicActivity;
        const searchConsent = await this.buildSearchConsent(ctx, activity, actorUri);
        const deliveryTargets = deliveryPlan.remoteRecipients.map(target => ({
          targetDomain: target.targetDomain,
          inboxUrl: target.inboxUrl,
          ...(target.sharedInboxUrl ? { sharedInboxUrl: target.sharedInboxUrl } : {})
        }));
        const event = await this.buildCommittedEvent(ctx, {
          activity,
          actorUri,
          deliveryTargets,
          visibility,
          isPublicActivity,
          searchConsent,
          deliveryPlanIntentId: deliveryPlan.intentId
        });
        ctx.emit('outbox.event.ready', event);
      }
    }
  },
  methods: {
    async buildCommittedEvent(ctx, { activity, actorUri, deliveryTargets, visibility, isPublicActivity, searchConsent, deliveryPlanIntentId }) {
      return {
        schema: 'ap.outbox.committed.v1',
        eventId: ulid(),
        timestamp: new Date().toISOString(),
        actorUri,
        podDataset: ctx.meta?.podDataset,
        activityId: activity.id || activity['@id'],
        objectId: this.extractObjectId(activity),
        activityType: activity.type || activity['@type'],
        activity,
        deliveryTargets,
        meta: {
          isPublicActivity,
          isPublicIndexable: isPublicActivity && searchConsent.isPublic,
          isDeleteOrTombstone: this.isDeleteOrTombstone(activity),
          visibility,
          searchConsent,
          hashtags: this.extractMetadataHashtags(activity),
          ...(deliveryPlanIntentId ? { deliveryPlanIntentId } : {})
        }
      };
    },
    async deliverObservationToSidecar(event) {
      const payload = {
        actorUri: event.actorUri,
        activityId: event.activityId,
        activity: event.activity,
        meta: event.meta
      };
      try {
        // Native observation is not the authoritative remote delivery path.
        // Never let its network/retry budget grow with arbitrary configuration
        // or hold a Moleculer event handler indefinitely.
        const body = JSON.stringify(payload);
        if (Buffer.byteLength(body, 'utf8') > 1048576) {
          throw new Error('Native observation webhook exceeds sidecar request limit');
        }
        const headers = {
          'Content-Type': 'application/json',
          'X-Event-Id': event.eventId,
          'X-Event-Schema': event.schema
        };
        if (this.settings.sidecarToken) {
          headers.Authorization = `Bearer ${this.settings.sidecarToken}`;
        }
        await retryWithBackoff(async () => {
          const response = await fetch(this.settings.sidecarObservationWebhookUrl, {
            method: 'POST',
            headers, body,
            signal: AbortSignal.timeout(this.settings.observationWebhookTimeoutMs)
          });
          if (response.status !== 202) {
            const error = new Error(`Sidecar observation webhook returned ${response.status}`);
            error.retryable = response.status === 429 || response.status >= 500;
            throw error;
          }
          const ack = await readBoundedAcknowledgement(response);
          if (ack.accepted !== true ||
              ack.intentId !== 'apdm-observation:' + event.eventId ||
              ack.jobCount !== 0 || ack.observationOnly !== true) {
            throw new Error('Sidecar observation webhook did not confirm targetless durable acceptance');
          }
        }, {
          maxRetries: Math.max(0, this.settings.observationWebhookRetries - 1),
          baseDelayMs: 250,
          maxDelayMs: 1000,
          deadlineMs: 10000,
          retryIf: error => error.retryable !== false
        });
      } catch (error) {
        this.logger.error('Failed to deliver native observation to sidecar after retries', {
          eventId: event.eventId,
          activityId: event.activityId,
          error: error.message
        });
      }
    },
    extractObjectId(activity) {
      const object = activity.object;
      if (!object) return null;
      if (typeof object === 'string') return object;
      return object.id || object['@id'] || null;
    },
    isDeleteOrTombstone(activity) {
      const type = activity.type || activity['@type'];
      return type === 'Delete' || type === 'Tombstone' || (type === 'Undo' && activity.object?.type === 'Announce');
    },
    determineVisibility(activity) {
      const publicAddress = 'https://www.w3.org/ns/activitystreams#Public';
      const to = Array.isArray(activity.to) ? activity.to : [activity.to];
      const cc = Array.isArray(activity.cc) ? activity.cc : [activity.cc];
      if (to.includes(publicAddress) || to.includes('as:Public')) return 'public';
      if (cc.includes(publicAddress) || cc.includes('as:Public')) return 'unlisted';
      if (to.some(r => r?.endsWith('/followers'))) return 'followers';
      return 'direct';
    },
    async buildSearchConsent(ctx, activity, actorUri) {
      const obj = activity.object && typeof activity.object === 'object' ? activity.object : activity;
      let attributedToActor = null;
      if (actorUri && typeof ctx.call === 'function') {
        attributedToActor = await Promise.resolve(ctx.call('activitypub.actor.get', { actorUri, webId: 'system' })).catch(error => {
          this.logger.warn('Failed to resolve actor search consent for outbox event', { actorUri, error: error.message });
          return null;
        });
      }
      return resolvePublicSearchConsent(obj, { attributedToActor });
    },
    extractMetadataHashtags(activity) {
      const obj = activity.object && typeof activity.object === 'object' ? activity.object : activity;
      return extractHashtagsFromText(obj.content || '');
    }
  }
};
