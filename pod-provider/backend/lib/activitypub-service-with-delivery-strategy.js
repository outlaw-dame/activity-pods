'use strict';

const QueueMixin = require('moleculer-bull');
const { as, sec } = require('@semapps/ontologies');
const semappsActivityPubPackage = require('@semapps/activitypub/package.json');
const { buildDeliveryPlanV1 } = require('../utils/activitypub-delivery-planner');
const { sanitizeDeliveryActivity } = require('../utils/activitypub-delivery-plan');
const {
  DELIVERY_HANDOFF_QUEUE,
  enqueueDeliveryHandoff,
  processDeliveryHandoffJob
} = require('../utils/activitypub-delivery-handoff');

const SUPPORTED_SEMAPPS_ACTIVITYPUB_VERSION = '1.1.4';
const REMOTE_DELIVERY_MODES = new Set(['native', 'external']);
const REMOTE_DELIVERY_PLANNED_EVENT = 'activitypub.outbox.remote-delivery.handoff-queued';
const PUBLIC_ADDRESSES = new Set(['https://www.w3.org/ns/activitystreams#Public', 'as:Public', 'Public']);
const ACTIVITY_TYPE_NAMES = new Set([
  'Accept', 'Add', 'Announce', 'Arrive', 'Block', 'Create', 'Delete', 'Dislike', 'Flag', 'Follow', 'Ignore', 'Invite',
  'Join', 'Leave', 'Like', 'Listen', 'Move', 'Offer', 'Question', 'Reject', 'Read', 'Remove', 'TentativeReject',
  'TentativeAccept', 'Travel', 'Undo', 'Update', 'View'
]);
const ACTIVITYSTREAMS_NAMESPACE = 'https://www.w3.org/ns/activitystreams#';
const SEMAPPS_INTERNAL_PATHS = Object.freeze({
  ActorService: '@semapps/activitypub/services/activitypub/subservices/actor',
  ActivityService: '@semapps/activitypub/services/activitypub/subservices/activity',
  ApiService: '@semapps/activitypub/services/activitypub/subservices/api',
  CollectionService: '@semapps/activitypub/services/activitypub/subservices/collection',
  FollowService: '@semapps/activitypub/services/activitypub/subservices/follow',
  InboxService: '@semapps/activitypub/services/activitypub/subservices/inbox',
  LikeService: '@semapps/activitypub/services/activitypub/subservices/like',
  ObjectService: '@semapps/activitypub/services/activitypub/subservices/object',
  OutboxService: '@semapps/activitypub/services/activitypub/subservices/outbox',
  CollectionsRegistryService: '@semapps/activitypub/services/activitypub/subservices/collections-registry',
  ReplyService: '@semapps/activitypub/services/activitypub/subservices/reply',
  ShareService: '@semapps/activitypub/services/activitypub/subservices/share',
  SideEffectsService: '@semapps/activitypub/services/activitypub/subservices/side-effects',
  FakeQueueMixin: '@semapps/activitypub/mixins/fake-queue'
});
const SEMAPPS_OUTBOX_INTERCEPTION_MARKERS = Object.freeze([
  'activitypub.activity.getRecipients',
  "this.createJob('remotePost'",
  'activitypub.outbox.posted',
  'this.localPost(localRecipients, activity)'
]);

function normalizeRemoteDeliveryMode(value) {
  const normalized = value === undefined || value === null ? 'native' : String(value).trim().toLowerCase();
  if (!REMOTE_DELIVERY_MODES.has(normalized)) {
    throw new Error(`Unsupported ActivityPub remote delivery mode '${value}'. Expected one of: native, external.`);
  }
  return normalized;
}

function assertSupportedSemappsVersion() {
  if (semappsActivityPubPackage.version !== SUPPORTED_SEMAPPS_ACTIVITYPUB_VERSION) {
    throw new Error(
      `APDM delivery strategy adapter supports @semapps/activitypub ${SUPPORTED_SEMAPPS_ACTIVITYPUB_VERSION}; ` +
        `installed version is ${semappsActivityPubPackage.version}. Review the upstream outbox implementation before upgrading.`
    );
  }
}

function assertSupportedSemappsOutboxShape(OutboxService) {
  const post = OutboxService?.actions?.post;
  const localPost = OutboxService?.methods?.localPost;
  const remotePostProcessor = OutboxService?.queues?.remotePost?.process;
  if (typeof post !== 'function' || typeof localPost !== 'function' || typeof remotePostProcessor !== 'function') {
    throw new Error(
      'APDM delivery strategy requires the SemApps 1.1.4 outbox post/localPost/remotePost shape. ' +
        'Review the installed outbox implementation before enabling the adapter.'
    );
  }

  const source = Function.prototype.toString.call(post);
  const indexes = SEMAPPS_OUTBOX_INTERCEPTION_MARKERS.map(marker => source.indexOf(marker));
  if (indexes.some(index => index < 0) || indexes.some((index, position) => position > 0 && index <= indexes[position - 1])) {
    throw new Error(
      'APDM delivery strategy detected incompatible SemApps outbox ordering. Expected getRecipients -> remotePost -> ' +
        'activitypub.outbox.posted -> localPost before intercepting remote delivery.'
    );
  }
}

function parseSafeHttpUrl(value) {
  if (typeof value !== 'string' || value.length === 0) return null;
  try {
    const parsed = new URL(value);
    if (!['http:', 'https:'].includes(parsed.protocol) || parsed.username || parsed.password) return null;
    return parsed;
  } catch {
    return null;
  }
}

function normalizeEntityId(value) {
  if (typeof value === 'string' && value.length > 0) return value;
  if (value && typeof value === 'object' && !Array.isArray(value)) {
    return value.id || value['@id'] || null;
  }
  return null;
}

function normalizeAddressValues(value) {
  const values = Array.isArray(value) ? value : [value];
  return values.map(normalizeEntityId).filter(item => typeof item === 'string' && item.length > 0);
}

function normalizeTypeValues(value) {
  const values = Array.isArray(value) ? value : [value];
  return values.filter(item => typeof item === 'string' && item.length > 0).map(item =>
    item.startsWith(ACTIVITYSTREAMS_NAMESPACE) ? item.slice(ACTIVITYSTREAMS_NAMESPACE.length) : item
  );
}

function isPostedActivity(params) {
  return normalizeTypeValues(params?.type ?? params?.['@type']).some(type => ACTIVITY_TYPE_NAMES.has(type));
}

function isActorFollowersAddress(value, actorUri) {
  if (typeof value !== 'string' || typeof actorUri !== 'string') return false;
  try {
    const address = new URL(value);
    const actor = new URL(actorUri);
    if (actor.search || actor.hash || address.search || address.hash) return false;
    if (address.origin !== actor.origin) return false;
    const actorPath = actor.pathname.replace(/\/+$/u, '');
    const addressPath = address.pathname.replace(/\/+$/u, '');
    return addressPath === `${actorPath}/followers`;
  } catch {
    return false;
  }
}

function assertSupportedAudienceAddressing(params) {
  const audience = normalizeAddressValues(params?.audience);
  if (audience.length === 0) return;

  const actorUri = normalizeEntityId(params?.actor || params?.attributedTo);
  const standardAddresses = new Set(
    ['to', 'bto', 'cc', 'bcc'].flatMap(key => normalizeAddressValues(params?.[key]))
  );

  for (const recipient of audience) {
    if (PUBLIC_ADDRESSES.has(recipient)) continue;
    if (actorUri && isActorFollowersAddress(recipient, actorUri)) {
      throw new Error(
        'ActivityPub sender-followers audience is unsupported by SemApps 1.1.4 recipient discovery; ' +
          'duplicate the followers collection in to/cc only after an explicit compatibility decision.'
      );
    }
    if (!standardAddresses.has(recipient)) {
      throw new Error(
        `ActivityPub audience recipient ${recipient} must also appear in to/bto/cc/bcc until authoritative audience expansion is implemented.`
      );
    }
  }
}

function activityIdentity(activity) {
  if (!activity || typeof activity !== 'object' || Array.isArray(activity)) return { id: null, actor: null };
  return {
    id: normalizeEntityId(activity.id || activity['@id']),
    actor: normalizeEntityId(activity.actor)
  };
}

function assertMatchingActivityIdentity(expectedActivity, observedActivity, label) {
  const expected = activityIdentity(expectedActivity);
  const observed = activityIdentity(observedActivity);
  if (!expected.id || observed.id !== expected.id) {
    throw new Error(`APDM intercepted ${label} with an Activity that does not match the outbox result.`);
  }
  if (expected.actor && observed.actor !== expected.actor) {
    throw new Error(`APDM intercepted ${label} with an actor that does not match the outbox result.`);
  }
}

function assertCapturedRemotePostStructure(job) {
  const recipientUri = job?.recipientUri;
  if (!parseSafeHttpUrl(recipientUri)) {
    throw new Error('APDM intercepted a remotePost job without a safe concrete HTTP(S) recipientUri.');
  }
  if (job.jobId !== recipientUri) {
    throw new Error('APDM intercepted an incompatible remotePost job: SemApps 1.1.4 requires jobId === recipientUri.');
  }
  const identity = activityIdentity(job.activity);
  if (!identity.id || !identity.actor) {
    throw new Error('APDM intercepted a remotePost job without a concrete Activity id and actor.');
  }
}

function validateCapturedRemotePosts(capturedRemotePosts, activity) {
  const recipients = [];
  for (const job of capturedRemotePosts) {
    assertCapturedRemotePostStructure(job);
    assertMatchingActivityIdentity(activity, job.activity, 'remotePost job');
    recipients.push(job.recipientUri);
  }
  return [...new Set(recipients)];
}

function validateCapturedLocalPosts(capturedLocalPosts, activity) {
  const recipients = [];
  for (const post of capturedLocalPosts) {
    if (!Array.isArray(post.recipients)) {
      throw new Error('APDM intercepted localPost with a non-array recipient list.');
    }
    assertMatchingActivityIdentity(activity, post.activity, 'localPost call');
    for (const recipientUri of post.recipients) {
      if (!parseSafeHttpUrl(recipientUri)) {
        throw new Error('APDM intercepted localPost without a safe concrete HTTP(S) recipientUri.');
      }
      recipients.push(recipientUri);
    }
  }
  return [...new Set(recipients)];
}

function hasBlindRecipients({ bto, bcc }) {
  return bto !== undefined || bcc !== undefined;
}

function createPrivacySafeOutboxContext(ctx, { persistBlindSnapshot = false } = {}) {
  if (!ctx || typeof ctx !== 'object' || Array.isArray(ctx)) {
    throw new TypeError('ActivityPub outbox context must be an object.');
  }

  if (ctx.params === undefined || ctx.params === null) return ctx;
  if (typeof ctx.params !== 'object' || Array.isArray(ctx.params)) {
    throw new TypeError('ActivityPub outbox context params must be an object.');
  }

  const postedActivity = isPostedActivity(ctx.params);
  if (postedActivity) assertSupportedAudienceAddressing(ctx.params);

  const blindRecipients = postedActivity
    ? { bto: ctx.params.bto, bcc: ctx.params.bcc }
    : { bto: undefined, bcc: undefined };
  const wrappedCtx = Object.create(ctx);
  wrappedCtx.params = sanitizeDeliveryActivity(ctx.params);

  if (typeof ctx.call !== 'function') {
    if (hasBlindRecipients(blindRecipients)) {
      throw new TypeError('ActivityPub blind-address routing requires a context call function.');
    }
    return wrappedCtx;
  }

  const nativeCall = ctx.call.bind(ctx);
  wrappedCtx.call = async (action, params, options) => {
    if (
      action === 'activitypub.activity.post' &&
      persistBlindSnapshot &&
      hasBlindRecipients(blindRecipients)
    ) {
      if (!params?.resource || typeof params.resource !== 'object' || Array.isArray(params.resource)) {
        throw new Error('APDM blind-address recovery snapshot requires the finalized Activity resource before persistence.');
      }
      await nativeCall(
        'activitypub-delivery-reconciler.storeBlindRecipientSnapshot',
        {
          activity: params.resource,
          ...(blindRecipients.bto !== undefined ? { bto: blindRecipients.bto } : {}),
          ...(blindRecipients.bcc !== undefined ? { bcc: blindRecipients.bcc } : {})
        },
        options
      );
    }

    if (action !== 'activitypub.activity.getRecipients' || !hasBlindRecipients(blindRecipients)) {
      return nativeCall(action, params, options);
    }

    const baseRecipients = await nativeCall(action, params, options);
    const activity = params?.activity;
    const actor = activity && activity.actor;
    if (!actor) {
      throw new Error('APDM blind-address recipient recovery requires a concrete Activity actor.');
    }

    const blindRecipientsOnly = await nativeCall(
      action,
      {
        activity: {
          actor,
          ...(blindRecipients.bto !== undefined ? { bto: blindRecipients.bto } : {}),
          ...(blindRecipients.bcc !== undefined ? { bcc: blindRecipients.bcc } : {})
        }
      },
      options
    );

    return [...new Set([...(baseRecipients || []), ...(blindRecipientsOnly || [])])];
  };

  return wrappedCtx;
}

function assertExternalDeliveryConfiguration(settings) {
  if (normalizeRemoteDeliveryMode(settings?.remoteDeliveryMode) !== 'external') return;
  if (settings.allowExternalDeliveryPreview !== true) {
    throw new Error('ActivityPub external remote delivery requires the explicit APDM preview guard until Phase 5 cutover.');
  }
  if (typeof settings.queueServiceUrl !== 'string' || settings.queueServiceUrl.trim().length === 0) {
    throw new Error('ActivityPub external remote delivery requires SEMAPPS_QUEUE_SERVICE_URL; FakeQueueMixin is forbidden.');
  }
  if (typeof settings.deliveryHandoffUrl !== 'string' || settings.deliveryHandoffUrl.trim().length === 0) {
    throw new Error('ActivityPub external remote delivery requires a sidecar Delivery Plan handoff URL.');
  }
  if (settings.deliveryHandoffUrl !== settings.deliveryHandoffUrl.trim()) {
    throw new Error('ActivityPub external remote delivery handoff URL must not contain whitespace padding.');
  }
  if (settings.deliveryHandoffUrl.includes('#')) {
    throw new Error('ActivityPub external remote delivery handoff URL must not contain a URL fragment.');
  }
  const handoffUrl = parseSafeHttpUrl(settings.deliveryHandoffUrl);
  if (!handoffUrl) {
    throw new Error('ActivityPub external remote delivery handoff URL must be a valid credential-free HTTP(S) URL.');
  }
  if (typeof settings.deliveryHandoffToken !== 'string' || settings.deliveryHandoffToken.trim().length === 0) {
    throw new Error('ActivityPub external remote delivery requires SIDECAR_TOKEN for authenticated durable handoff.');
  }
  if (
    !Number.isInteger(settings.deliveryHandoffTimeoutMs) ||
    settings.deliveryHandoffTimeoutMs < 100 ||
    settings.deliveryHandoffTimeoutMs > 60000
  ) {
    throw new Error('ActivityPub external remote delivery handoff timeout must be an integer between 100 and 60000 milliseconds.');
  }
}

function resolveSemappsInternalPaths() {
  return Object.fromEntries(
    Object.entries(SEMAPPS_INTERNAL_PATHS).map(([name, modulePath]) => [name, require.resolve(modulePath)])
  );
}

function loadSemappsActivityPubInternals() {
  assertSupportedSemappsVersion();
  const internals = Object.fromEntries(
    Object.entries(SEMAPPS_INTERNAL_PATHS).map(([name, modulePath]) => [name, require(modulePath)])
  );
  assertSupportedSemappsOutboxShape(internals.OutboxService);
  return internals;
}

function createOutboxPostHandler(
  nativePostHandler,
  { buildDeliveryPlan = buildDeliveryPlanV1, enqueueHandoff = enqueueDeliveryHandoff } = {}
) {
  if (typeof nativePostHandler !== 'function') throw new TypeError('SemApps outbox post handler must be a function');
  if (typeof buildDeliveryPlan !== 'function') throw new TypeError('ActivityPub delivery plan builder must be a function');
  if (typeof enqueueHandoff !== 'function') throw new TypeError('ActivityPub durable handoff enqueuer must be a function');

  return async function postWithRemoteDeliveryStrategy(ctx) {
    const mode = normalizeRemoteDeliveryMode(this.settings.remoteDeliveryMode);
    if (mode === 'external') assertExternalDeliveryConfiguration(this.settings);

    const privacySafeCtx = createPrivacySafeOutboxContext(ctx, { persistBlindSnapshot: mode === 'external' });
    if (mode === 'native') return nativePostHandler.call(this, privacySafeCtx);

    const capturedRemotePosts = [];
    const capturedLocalPosts = [];
    const executionContext = Object.create(this);
    const nativeCreateJob = this.createJob.bind(this);
    const nativeLocalPost = typeof this.localPost === 'function' ? this.localPost.bind(this) : null;

    executionContext.createJob = (queueName, jobId, payload, options) => {
      if (queueName === 'remotePost') {
        const capturedJob = {
          jobId,
          recipientUri: payload && payload.recipientUri,
          activity: payload && payload.activity,
          options
        };
        assertCapturedRemotePostStructure(capturedJob);
        capturedRemotePosts.push(capturedJob);
        return undefined;
      }
      return nativeCreateJob(queueName, jobId, payload, options);
    };

    if (nativeLocalPost) {
      executionContext.localPost = (recipients, localActivity) => {
        capturedLocalPosts.push({
          recipients: Array.isArray(recipients) ? [...recipients] : recipients,
          activity: localActivity
        });
        return nativeLocalPost(recipients, localActivity);
      };
    }

    const activity = await nativePostHandler.call(executionContext, privacySafeCtx);
    if (!activityIdentity(activity).id) {
      throw new Error('APDM external delivery requires the SemApps outbox handler to return an Activity with a concrete id.');
    }

    const remoteRecipientUris = validateCapturedRemotePosts(capturedRemotePosts, activity);
    const localRecipientUris = validateCapturedLocalPosts(capturedLocalPosts, activity);

    const deliveryPlan = await buildDeliveryPlan(ctx, {
      activity,
      localRecipientUris,
      remoteRecipientUris,
      podProvider: this.settings.podProvider
    });

    await enqueueHandoff(this, deliveryPlan);

    this.broker.emit(
      REMOTE_DELIVERY_PLANNED_EVENT,
      {
        activity,
        deliveryPlan,
        remoteRecipients: remoteRecipientUris,
        localRecipients: localRecipientUris,
        suppressedNativeRemotePostCount: capturedRemotePosts.length,
        deliveryMode: 'external',
        durableHandoffQueued: true
      },
      { meta: { webId: null } }
    );

    return activity;
  };
}

function createOutboxServiceSchema({
  baseUri,
  podProvider,
  queueServiceUrl,
  remoteDeliveryMode,
  allowExternalDeliveryPreview,
  deliveryHandoffUrl,
  deliveryHandoffToken,
  deliveryHandoffTimeoutMs,
  internals,
  buildDeliveryPlan,
  enqueueHandoff
}) {
  const { OutboxService, FakeQueueMixin } = internals;
  const settings = {
    baseUri,
    podProvider,
    queueServiceUrl,
    remoteDeliveryMode,
    allowExternalDeliveryPreview,
    deliveryHandoffUrl,
    deliveryHandoffToken,
    deliveryHandoffTimeoutMs
  };
  assertExternalDeliveryConfiguration(settings);
  const queueMixin = queueServiceUrl ? QueueMixin(queueServiceUrl) : FakeQueueMixin;

  return {
    mixins: [OutboxService, queueMixin],
    settings,
    actions: {
      post: createOutboxPostHandler(OutboxService.actions.post, { buildDeliveryPlan, enqueueHandoff }),
      enqueueDeliveryHandoff: {
        params: { deliveryPlan: { type: 'object' } },
        async handler(ctx) {
          assertExternalDeliveryConfiguration(this.settings);
          const intentId = await enqueueHandoff(this, ctx.params.deliveryPlan);
          return { intentId };
        }
      }
    },
    queues: {
      ...OutboxService.queues,
      [DELIVERY_HANDOFF_QUEUE]: {
        name: '*',
        async process(job) {
          return processDeliveryHandoffJob(this, job);
        }
      }
    }
  };
}

function createActivityPubServiceWithDeliveryStrategy({
  remoteDeliveryMode = 'native',
  allowExternalDeliveryPreview = false,
  settings = {},
  internals,
  buildDeliveryPlan,
  enqueueHandoff
} = {}) {
  assertSupportedSemappsVersion();
  if (typeof allowExternalDeliveryPreview !== 'boolean') {
    throw new TypeError('ActivityPub external delivery preview guard must be a boolean.');
  }
  const normalizedRemoteDeliveryMode = normalizeRemoteDeliveryMode(remoteDeliveryMode);
  const resolvedInternals = internals || loadSemappsActivityPubInternals();
  const serviceSettings = {
    baseUri: null,
    podProvider: false,
    activitiesPath: '/as/activity',
    collectionsPath: '/as/collection',
    activateTombstones: true,
    selectActorData: null,
    queueServiceUrl: null,
    deliveryHandoffUrl: null,
    deliveryHandoffToken: '',
    deliveryHandoffTimeoutMs: 5000,
    ...settings,
    remoteDeliveryMode: normalizedRemoteDeliveryMode,
    allowExternalDeliveryPreview
  };
  assertExternalDeliveryConfiguration(serviceSettings);

  return {
    name: 'activitypub',
    settings: serviceSettings,
    dependencies: ['api', 'ontologies'],
    created() {
      const {
        baseUri,
        podProvider,
        activitiesPath,
        collectionsPath,
        selectActorData,
        queueServiceUrl,
        activateTombstones,
        remoteDeliveryMode: configuredRemoteDeliveryMode,
        allowExternalDeliveryPreview: configuredExternalPreview,
        deliveryHandoffUrl,
        deliveryHandoffToken,
        deliveryHandoffTimeoutMs
      } = this.settings;
      assertExternalDeliveryConfiguration(this.settings);
      const {
        ActorService,
        ActivityService,
        ApiService,
        CollectionService,
        FollowService,
        InboxService,
        LikeService,
        ObjectService,
        CollectionsRegistryService,
        ReplyService,
        ShareService,
        SideEffectsService,
        FakeQueueMixin
      } = resolvedInternals;
      const sideEffectsQueueMixin = queueServiceUrl ? QueueMixin(queueServiceUrl) : FakeQueueMixin;

      this.broker.createService({ mixins: [SideEffectsService, sideEffectsQueueMixin], settings: { podProvider } });
      this.broker.createService({ mixins: [CollectionService], settings: { podProvider, path: collectionsPath } });
      this.broker.createService({ mixins: [CollectionsRegistryService], settings: { baseUri, podProvider } });
      this.broker.createService({ mixins: [ActorService], settings: { baseUri, selectActorData, podProvider } });
      this.broker.createService({ mixins: [ApiService], settings: { baseUri, podProvider } });
      this.broker.createService({ mixins: [ObjectService], settings: { baseUri, podProvider, activateTombstones } });
      this.broker.createService({ mixins: [ActivityService], settings: { baseUri, podProvider, path: activitiesPath } });
      this.broker.createService({ mixins: [FollowService], settings: { baseUri } });
      this.broker.createService({ mixins: [InboxService], settings: { podProvider } });
      this.broker.createService({ mixins: [LikeService], settings: { baseUri, podProvider } });
      this.broker.createService({ mixins: [ShareService], settings: { baseUri, podProvider } });
      this.broker.createService({ mixins: [ReplyService], settings: { baseUri, podProvider } });
      this.broker.createService(
        createOutboxServiceSchema({
          baseUri,
          podProvider,
          queueServiceUrl,
          remoteDeliveryMode: configuredRemoteDeliveryMode,
          allowExternalDeliveryPreview: configuredExternalPreview,
          deliveryHandoffUrl,
          deliveryHandoffToken,
          deliveryHandoffTimeoutMs,
          internals: resolvedInternals,
          buildDeliveryPlan,
          enqueueHandoff
        })
      );
    },
    async started() {
      await this.broker.call('ontologies.register', as);
      await this.broker.call('ontologies.register', sec);
    }
  };
}

module.exports = {
  REMOTE_DELIVERY_PLANNED_EVENT,
  SEMAPPS_INTERNAL_PATHS,
  SEMAPPS_OUTBOX_INTERCEPTION_MARKERS,
  SUPPORTED_SEMAPPS_ACTIVITYPUB_VERSION,
  assertCapturedRemotePostStructure,
  assertExternalDeliveryConfiguration,
  assertSupportedAudienceAddressing,
  assertSupportedSemappsOutboxShape,
  assertSupportedSemappsVersion,
  createActivityPubServiceWithDeliveryStrategy,
  createOutboxPostHandler,
  createOutboxServiceSchema,
  createPrivacySafeOutboxContext,
  isPostedActivity,
  loadSemappsActivityPubInternals,
  normalizeRemoteDeliveryMode,
  resolveSemappsInternalPaths,
  validateCapturedLocalPosts,
  validateCapturedRemotePosts
};