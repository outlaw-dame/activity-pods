# Post-enrollment owner authorization and deny-before-revoke: P0 handoff

**Status: NONACTIVATED. Production signup and PDS OAuth remain CLOSED.**

## What this increment implements

The canonical PostgreSQL 18 v8 post-enrollment read function joins the
existing ActivityPods WebID, managed ATProto identity, native-attested SAI
activation and exact OAuth generation with the unified-account credential
epoch. A blocked OAuth grant, changed SAI revision, disabled identity or
pending/disabled credential epoch cannot return a current grant. The
separate restricted reader login is function-only, with no grant/revoke,
raw table access or service auto-registration. No new identity authority or
account store exists.

The new private, disposable owner-admission adapter combines the existing
signed browser/Redis/password-verifier proof with independently
challenge-signed credential epoch, real primary PG18 owner+SAI+OAuth
readback, fresh native Jena SAI evidence and the independent immutable
witness epoch. It rechecks those authorities, exact browser session and
credential epoch after network reads. A browser cannot choose a WebID via
request JSON or substitute an old RS256 bearer for a live session.
The issuance credential epoch must be bound to the browser session: the
current production OAuth cookie does NOT yet carry this datum.

This adapter is **read-only**. The returned object is preparatory evidence
for an eventual independently witnessed pre-denial ceremony, NOT a
mutation authorization, signed PDS admission or token issuance permit.
The production services do not import this candidate. Its gates require
NODE_ENV=test and explicit disposable flags.

## Evidence and outstanding boundaries

The CI fixture runs a real PostgreSQL 18 cluster with canonical credential,
SAI, managed DID and OAuth rows, restricted function-only roles and a real
Ed25519 challenge-signed fresh credential checkpoint. Tests exercise
client/owner isolation, stale cookie epochs, pending password rotation,
primary epoch rewind despite a newer independent signed head, role drift,
SAI and witness denial and concurrent SAI revocation.

The native Jena permissions verifier, real browser/Redis session and
separately administered immutable OAuth-witness reader are **simulated
callbacks in this new integrated test**, not live wiring. Their individual
proof suites do not establish combined production operation.

## Mandatory next mutating gate: irreversible pre-denial

1. Authenticate the owner through the real HttpOnly signed browser session,
   shared Redis session, current password verifier, independent signed
   credential epoch, CSRF, challenge fingerprint and exact grant ID.
2. Independently reserve a monotonic deny transition and drain/settle
   existing signed-PDS pending/commit intents with independently retained
   receipt evidence. An ambiguous signed write MUST NOT expire itself.
3. BEFORE ANY canonical PG, Redis or Jena revoke/replace/delete mutation,
   archive and independently uncached-read a WORM pre-denial receipt.
   A separately administered, monotonic latest-head signer must expose
   this denial to EVERY code/access/refresh/introspection/DPoP/PDS
   authorization path, including during primary and witness PITR.
4. Only after durable independent denial, perform restricted canonical
   PG18 owner/credential/SAI/exact-grant CAS, blocked witness epoch and
   immutable receipt confirmation, then Redis refresh-family tombstoning.
   Handle every lost acknowledgement as an ambiguous operation: never
   blindly retry or report successful revocation on assumed completion.
5. Independently reconcile the physical PG/Redis/Jena/PDS backups, WAL,
   signed repository CAR/outbox and Object Lock receipts before reopening
   affected operations. A generic SQL revoker alone cannot do this.

No currently deployed externally administered COMPLIANCE WORM archive,
monotonic independent pre-denial signer, fully wired owner lifecycle,
coordinated physical multi-store restore or production positive signup
is established by this increment. The existing OAuth production release
fuse must stay CLOSED, and historical exposed secrets need operator
rotation and old credential invalidation.
