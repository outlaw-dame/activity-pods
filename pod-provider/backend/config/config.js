// Read all .env* files in the root folder and add them to process.env
// See https://github.com/kerimdzhanov/dotenv-flow for more details
// A disposable role-isolated Pod process receives its complete environment
// from its launcher. Loading .env.test here would import the Jena admin login.
if (!(process.env.NODE_ENV === 'test' && process.env.PAPER_LOCAL_POD_DATA_PASSWORD !== undefined)) {
  require('dotenv-flow').config();
}

const {
  parseAutomaticReconciliationLookbackMs
} = require('../utils/activitypub-delivery-reconciliation-policy');

module.exports = {
  INSTANCE_NAME: process.env.SEMAPPS_INSTANCE_NAME,
  INSTANCE_DESCRIPTION: {
    en: process.env.SEMAPPS_INSTANCE_DESCRIPTION_EN || process.env.SEMAPPS_INSTANCE_DESCRIPTION,
    fr: process.env.SEMAPPS_INSTANCE_DESCRIPTION_FR
  },
  INSTANCE_OWNER: process.env.SEMAPPS_INSTANCE_OWNER,
  INSTANCE_AREA: process.env.SEMAPPS_INSTANCE_AREA,
  BASE_URL: process.env.SEMAPPS_HOME_URL,
  PORT: process.env.SEMAPPS_PORT,
  FRONTEND_URL: process.env.SEMAPPS_FRONTEND_URL,
  SHAPE_REPOSITORY_URL: process.env.SEMAPPS_SHAPE_REPOSITORY_URL,
  COLOR_PRIMARY: process.env.SEMAPPS_COLOR_PRIMARY,
  COLOR_SECONDARY: process.env.SEMAPPS_COLOR_SECONDARY,
  AVAILABLE_LOCALES: process.env.SEMAPPS_AVAILABLE_LOCALES.split(','),
  DEFAULT_LOCALE: process.env.SEMAPPS_DEFAULT_LOCALE,
  ENABLE_GROUPS: process.env.SEMAPPS_ENABLE_GROUPS === 'true',
  MAPBOX_ACCESS_TOKEN: process.env.SEMAPPS_MAPBOX_ACCESS_TOKEN,
  // Fuseki
  SPARQL_ENDPOINT: process.env.SEMAPPS_SPARQL_ENDPOINT,
  JENA_USER: process.env.SEMAPPS_JENA_USER,
  JENA_PASSWORD: process.env.SEMAPPS_JENA_PASSWORD,
  FUSEKI_BASE: process.env.SEMAPPS_FUSEKI_BASE,
  SKIP_ORPHAN_BLANK_NODE_CLEANUP: process.env.SEMAPPS_SKIP_ORPHAN_BLANK_NODE_CLEANUP === 'true',
  // ActivityPub delivery migration (APDM)
  ACTIVITYPUB_REMOTE_DELIVERY_MODE: process.env.SEMAPPS_ACTIVITYPUB_REMOTE_DELIVERY_MODE || 'native',
  ACTIVITYPUB_ALLOW_EXTERNAL_DELIVERY_PREVIEW:
    process.env.SEMAPPS_ACTIVITYPUB_ALLOW_EXTERNAL_DELIVERY_PREVIEW === 'true',
  ACTIVITYPUB_EXTERNAL_AUTHORITY_CUTOVER:
    process.env.SEMAPPS_ACTIVITYPUB_EXTERNAL_AUTHORITY_CUTOVER === 'true',
  // Phase 10 remains opt-in until its real OFF/ON measurement gate passes.
  // A later evidence-backed closure commit may promote the default; merely
  // merging the implementation must never activate unproven delivery behavior.
  APDM_LOCAL_DELIVERY_DATASET_EXIST_MEMO_ENABLED:
    process.env.APDM_LOCAL_DELIVERY_DATASET_EXIST_MEMO_ENABLED === 'true',
  // APDM Phase 8 is opt-in measurement only. These settings do not alter
  // delivery behavior; they attach observers to the real local Tier 1 path.
  APDM_PHASE8_INSTRUMENTATION_ENABLED: process.env.SEMAPPS_APDM_PHASE8_INSTRUMENTATION_ENABLED === 'true',
  APDM_PHASE8_INSTRUMENTATION_OUTPUT:
    process.env.SEMAPPS_APDM_PHASE8_INSTRUMENTATION_OUTPUT || './apdm-phase8-tier1.jsonl',
  APDM_PHASE8_RECIPIENT_COUNT: Number(process.env.SEMAPPS_APDM_PHASE8_RECIPIENT_COUNT),
  APDM_PHASE8_CASE_LABEL: process.env.SEMAPPS_APDM_PHASE8_CASE_LABEL,
  // The durable APDM handoff is intentionally isolated from the legacy
  // SIDECAR_WEBHOOK_URL. That older setting may point at the sidecar origin
  // for transitional emitters, while Phase 4/5 requires the exact durable
  // acceptance endpoint.
  ACTIVITYPUB_DELIVERY_HANDOFF_URL:
    process.env.SIDECAR_DELIVERY_HANDOFF_URL || 'http://fedify-sidecar:8080/webhook/outbox',
  ACTIVITYPUB_DELIVERY_HANDOFF_TOKEN: process.env.SIDECAR_TOKEN || '',
  ACTIVITYPUB_DELIVERY_HANDOFF_TIMEOUT_MS: Number(process.env.SIDECAR_DELIVERY_HANDOFF_TIMEOUT_MS) || 5000,
  ACTIVITYPUB_DELIVERY_RECONCILIATION_INTERVAL_MS:
    Number(process.env.SEMAPPS_ACTIVITYPUB_DELIVERY_RECONCILIATION_INTERVAL_MS) || 60000,
  ACTIVITYPUB_DELIVERY_RECONCILIATION_INITIAL_DELAY_MS:
    Number(process.env.SEMAPPS_ACTIVITYPUB_DELIVERY_RECONCILIATION_INITIAL_DELAY_MS) || 15000,
  ACTIVITYPUB_DELIVERY_RECONCILIATION_LOOKBACK_MS: parseAutomaticReconciliationLookbackMs(
    process.env.SEMAPPS_ACTIVITYPUB_DELIVERY_RECONCILIATION_LOOKBACK_MS
  ),
  ACTIVITYPUB_DELIVERY_RECONCILIATION_ACCOUNT_BATCH_SIZE:
    Number(
      process.env.SEMAPPS_ACTIVITYPUB_DELIVERY_RECONCILIATION_ACCOUNT_BATCH_SIZE ||
        process.env.SEMAPPS_ACTIVITYPUB_DELIVERY_RECONCILIATION_MAX_ACCOUNTS
    ) || 500,
  ACTIVITYPUB_DELIVERY_RECONCILIATION_MAX_ACTIVITIES_PER_ACCOUNT:
    Number(process.env.SEMAPPS_ACTIVITYPUB_DELIVERY_RECONCILIATION_MAX_ACTIVITIES_PER_ACCOUNT) || 50,
  ACTIVITYPUB_DELIVERY_RECONCILIATION_CONCURRENCY:
    Number(process.env.SEMAPPS_ACTIVITYPUB_DELIVERY_RECONCILIATION_CONCURRENCY) || 4,
  // Redis
  REDIS_CACHE_URL: process.env.SEMAPPS_REDIS_CACHE_URL,
  REDIS_TRANSPORTER_URL: process.env.SEMAPPS_REDIS_TRANSPORTER_URL,
  QUEUE_SERVICE_URL: process.env.SEMAPPS_QUEUE_SERVICE_URL,
  // OIDC Provider
  REDIS_OIDC_PROVIDER_URL: process.env.SEMAPPS_REDIS_OIDC_PROVIDER_URL,
  COOKIE_SECRET: process.env.SEMAPPS_COOKIE_SECRET,
  // Email
  FROM_EMAIL: process.env.SEMAPPS_FROM_EMAIL,
  FROM_NAME: process.env.SEMAPPS_FROM_NAME,
  SMTP_HOST: process.env.SEMAPPS_SMTP_HOST,
  SMTP_PORT: parseInt(process.env.SEMAPPS_SMTP_PORT, 10),
  SMTP_SECURE: process.env.SEMAPPS_SMTP_SECURE === 'true',
  SMTP_USER: process.env.SEMAPPS_SMTP_USER,
  SMTP_PASS: process.env.SEMAPPS_SMTP_PASS,
  // Auth
  AUTH_RESERVED_USER_NAMES: process.env.SEMAPPS_AUTH_RESERVED_USER_NAMES.split(','),
  AUTH_ACCOUNTS_DATASET: process.env.SEMAPPS_AUTH_ACCOUNTS_DATASET,
  // Backup
  BACKUP_COPY_METHOD: process.env.SEMAPPS_BACKUP_COPY_METHOD,
  BACKUP_SERVER_PATH: process.env.SEMAPPS_BACKUP_SERVER_PATH,
  BACKUP_SERVER_HOST: process.env.SEMAPPS_BACKUP_SERVER_HOST,
  BACKUP_SERVER_USER: process.env.SEMAPPS_BACKUP_SERVER_USER,
  BACKUP_SERVER_PASSWORD: process.env.SEMAPPS_BACKUP_SERVER_PASSWORD,
  BACKUP_SERVER_PORT: process.env.SEMAPPS_BACKUP_SERVER_PORT
};
