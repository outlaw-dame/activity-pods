# Notification quarantine operator replay (non-activated)

The original durable delivery ledger has a **per-recipient** queue, a
bounded 8-attempt retry budget, and an immutable quarantine row after poison
or repeated lease failures. This extension adds a credential-isolated
**manual replay** path; it is not a background retry scheduler.

Migration administrators must run
`pod-provider/backend/sql/paper-notification-quarantine-replay-v2.sql`
only after the v1 notification ledger migration. The script creates a small
append-only `quarantine_replays` audit history, plus
`paper_notification_replay_operator` (a **NOLOGIN** role). Production
operators require a separately authenticated, audited database LOGIN
granted only that role. They must never receive the general
`paper_notification_runtime` worker credential or migration privileges.
No HTTP endpoint, Moleculer action, CLI with implicit production access or
environment-only enable flag is introduced in this change.

Each replay request supplies exact SHA256 intent and recipient keys and a
unique UUID operation ID. A restricted PostgreSQL `SECURITY DEFINER`
function reads the current recipient under `FOR UPDATE`, verifies a
durably quarantined **dead** state and eight previous failed attempts,
then atomically appends an audit record and requeues that exact recipient.
The operator's identity is the database-authenticated `session_user`:
a caller cannot inject an arbitrary WebID or actor name. Reusing the same
operation ID for the same recipient returns an idempotent no-op;
reusing it for a different recipient is rejected. A database-enforced
maximum of **three manual replays per recipient** prevents unlimited
operator-triggered replays. Failure or crash inside this transaction
cannot commit an unaudited requeue.

The original quarantine record remains intact; subsequent poison cycles
perform `ON CONFLICT DO NOTHING` rather than replacing or erasing the first
failure evidence. The replay-history table preserves operator, operation ID,
prior attempt count and time across successive replays. Ordinary runtime
workers have no direct replay-function EXECUTE privilege, while the
restricted replay credential cannot mutate the `deliveries` table.

The real disposable PostgreSQL 18 CI proof uses separate database logins
and checks: a general worker cannot replay; an operator cannot UPDATE
delivery state directly; successful replay, exact idempotency, and failure
after the third replay; unchanged quarantine evidence; and audit rows
bound to PostgreSQL's authenticated session identity.

**Release requirements:** authenticated operator provisioning and audit,
tenant-specific access control, backup/restore, real queue recovery/cleanup
and a documented manual approval protocol. No production runtime or queue
consumer is activated by this addition. The Kafka-side restricted dead-letter
topic in the separate Fedify sidecar remains an independent quarantine
mechanism, and is not directly replayed by this database function.
