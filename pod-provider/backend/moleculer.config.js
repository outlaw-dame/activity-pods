const { WebAclMiddleware, CacherMiddleware } = require('@semapps/webacl');
const { ObjectsWatcherMiddleware } = require('@semapps/sync');
const AppControlMiddleware = require('./middlewares/app-control');
const HashtagNormalizationMiddleware = require('./middlewares/hashtag-normalization');
const TrustEvaluatorMiddleware = require('./middlewares/trust-evaluator');
const ContentWarningMiddleware = require('./middlewares/content-warning');
const LinkPreviewMiddleware = require('./middlewares/link-preview');
const LongFormTextMiddleware = require('./middlewares/long-form-text');
const MediaAttachmentsMiddleware = require('./middlewares/media-attachments');
const PollsMiddleware = require('./middlewares/polls');
const ReplyPoliciesMiddleware = require('./middlewares/reply-policies');
const SearchConsentMiddleware = require('./middlewares/search-consent');
const QuotePostsMiddleware = require('./middlewares/quote-posts');
const ActorMetadataMiddleware = require('./middlewares/actor-metadata');
const AuthorAttributionMiddleware = require('./middlewares/author-attribution');
const Fep4adbMiddleware = require('./middlewares/fep-4adb');
const Fep5bf0CollectionViewsMiddleware = require('./middlewares/fep-5bf0-collection-views');
const SkipOrphanBlankNodesCleanupMiddleware = require('./middlewares/skip-orphan-blank-nodes-cleanup');
const ApdmLocalDeliveryDatasetExistMemoMiddleware = require('./middlewares/apdm-local-delivery-dataset-exist-memo');
const AdspActionLocalityMiddleware = require('./middlewares/adsp-action-locality');
const AdspRootEntryEvidenceMiddleware = require('./middlewares/adsp-root-entry-evidence');
const AdspLocalOntologyRegistrationMiddleware = require('./middlewares/adsp-local-ontology-registration');
const AtprotoProvisioningReservationMiddleware = require('./middlewares/atproto-provisioning-reservation');
const { createPhase8Tier1Instrumentation } = require('./lib/apdm-phase8-tier1-instrumentation');
const CONFIG = require('./config/config');
const errorHandler = require('./config/errorHandler');
const {
  GROUP_POD_CELL,
  MODE_DISTRIBUTED,
  createMoleculerFabricConfig
} = require('./config/moleculer-fabric');

Error.stackTraceLimit = Infinity;

const fabric = createMoleculerFabricConfig();

function createPodCellMiddlewares() {
  const cacherConfig = CONFIG.REDIS_CACHE_URL
    ? {
        type: 'Redis',
        options: {
          prefix: 'action',
          ttl: 2592000,
          redis: CONFIG.REDIS_CACHE_URL
        }
      }
    : undefined;

  const phase8Instrumentation = createPhase8Tier1Instrumentation({
    enabled: CONFIG.APDM_PHASE8_INSTRUMENTATION_ENABLED,
    outputPath: CONFIG.APDM_PHASE8_INSTRUMENTATION_OUTPUT,
    recipientCount: CONFIG.APDM_PHASE8_RECIPIENT_COUNT,
    caseLabel: CONFIG.APDM_PHASE8_CASE_LABEL,
    fusekiBase: CONFIG.FUSEKI_BASE,
    sparqlEndpoint: CONFIG.SPARQL_ENDPOINT
  });

  // In a replicated Pod cell, SemApps' ontology registry is broker-local
  // in-memory state. Service dependencies can be satisfied by sibling nodes
  // before this broker's own ontology baseline has finished starting, so an
  // early broker.call('ontologies.register', ...) can otherwise mutate a
  // sibling and leave this cell semantically incomplete. Intercept only that
  // mutation and hold it until the local baseline is initialized.
  const localOntologyRegistration = AdspLocalOntologyRegistrationMiddleware({
    enabled: fabric.mode === MODE_DISTRIBUTED
  });

  // Keep the production Pod/SemApps cell middleware order exactly as before,
  // except for the distributed ontology-registration guard above. Non-production
  // P1 groups intentionally do not attach these middlewares: several of them
  // have startup dependencies on LDP/WebACL/etc. that belong to the colocated
  // Pod cell and must not force every independent broker to load the full graph.
  const middlewares = [];
  if (localOntologyRegistration) middlewares.push(localOntologyRegistration);
  middlewares.push(
    CacherMiddleware(cacherConfig),
    WebAclMiddleware({ baseUrl: CONFIG.BASE_URL, podProvider: true }),
    SkipOrphanBlankNodesCleanupMiddleware({ enabled: CONFIG.SKIP_ORPHAN_BLANK_NODE_CLEANUP }),
    ApdmLocalDeliveryDatasetExistMemoMiddleware({ enabled: CONFIG.APDM_LOCAL_DELIVERY_DATASET_EXIST_MEMO_ENABLED }),
    ObjectsWatcherMiddleware({ baseUrl: CONFIG.BASE_URL, podProvider: true, postWithoutRecipients: true }),
    LongFormTextMiddleware(),
    ContentWarningMiddleware(),
    PollsMiddleware(),
    QuotePostsMiddleware(),
    ReplyPoliciesMiddleware(),
    ActorMetadataMiddleware(),
    AuthorAttributionMiddleware(),
    Fep4adbMiddleware(),
    Fep5bf0CollectionViewsMiddleware(CONFIG.BASE_URL),
    HashtagNormalizationMiddleware(),
    LinkPreviewMiddleware(),
    MediaAttachmentsMiddleware(),
    SearchConsentMiddleware(),
    TrustEvaluatorMiddleware(),
    AppControlMiddleware({ baseUrl: CONFIG.BASE_URL })
  );

  if (phase8Instrumentation.middleware) middlewares.push(phase8Instrumentation.middleware);
  return middlewares;
}

const middlewares = fabric.serviceGroup === GROUP_POD_CELL ? createPodCellMiddlewares() : [];

// Provisioning must be serialized before signing.provisionAtprotoIdentity can
// perform its missing-binding check or generate private keys. This middleware
// uses the shared Redis authority so the reservation remains effective across
// replicated Pod cells, not merely within one Node.js process.
const atprotoProvisioningReservation = AtprotoProvisioningReservationMiddleware({
  redisUrl: CONFIG.QUEUE_SERVICE_URL || CONFIG.REDIS_CACHE_URL || undefined
});
if (atprotoProvisioningReservation) middlewares.unshift(atprotoProvisioningReservation);

// Locality telemetry is fabric-safe and may be enabled for either the real Pod
// cell or an isolated proof group. It observes routing only; it has no service
// dependencies and does not change endpoint selection.
const localityTelemetry = AdspActionLocalityMiddleware({
  enabled: process.env.SEMAPPS_MOLECULER_LOCALITY_TELEMETRY_ENABLED === 'true',
  maxActions: Number(process.env.SEMAPPS_MOLECULER_LOCALITY_MAX_ACTIONS) || 200,
  outputPath: process.env.SEMAPPS_MOLECULER_LOCALITY_TELEMETRY_OUTPUT || undefined
});
if (localityTelemetry) middlewares.push(localityTelemetry);

// Fault-injection evidence may need to prove one exact ambiguous commit window:
// the real root action completes on the selected victim, but its response is
// held until that process is SIGKILLed. Every control is explicit and disabled
// outside the dedicated evidence fixture.
const rootEntryEvidence = AdspRootEntryEvidenceMiddleware({
  enabled: process.env.SEMAPPS_ADSP_ROOT_ENTRY_EVIDENCE_ENABLED === 'true',
  outputPath: process.env.SEMAPPS_ADSP_ROOT_ENTRY_EVIDENCE_OUTPUT || undefined,
  nodeID: fabric.nodeID,
  holdAfterAction: process.env.SEMAPPS_ADSP_ROOT_HOLD_AFTER_ACTION === 'true',
  holdRequestPrefix: process.env.SEMAPPS_ADSP_ROOT_HOLD_REQUEST_PREFIX || undefined
});
if (rootEntryEvidence) middlewares.push(rootEntryEvidence);

/** @type {import('moleculer').BrokerOptions} */
module.exports = {
  nodeID: fabric.nodeID,
  namespace: fabric.namespace,
  heartbeatInterval: fabric.heartbeatInterval,
  heartbeatTimeout: fabric.heartbeatTimeout,
  registry: fabric.registry,
  middlewares,
  errorHandler,
  logger: [
    {
      type: 'Console',
      options: {
        formatter: 'short',
        level: 'info'
      }
    },
    {
      type: 'File',
      options: {
        formatter: 'short',
        level: 'error',
        folder: './logs',
        filename: 'moleculer-errors-{date}.log'
      }
    }
  ],
  transporter: fabric.transporter,
  serializer: fabric.serializer
};