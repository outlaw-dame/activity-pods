# Paper Groups G2-P2c — Consent-First Admission Policy Contract

**Status: policy kernel only. Not wired to HTTP, Moleculer, Solid-OIDC,
TDB2, ATProto or Fedify. Not production activated.**

## Why this separate slice exists

The G2-P2 owner-only membership mutation service currently supports
`active`, `banned`, and `left`, but does not store a verified invitation
acceptance, a self-authenticated membership request, or delegated moderator
authorization. A user may follow a Group without joining it, and an owner
must not be able to force an arbitrary remote or local actor into active
Group membership.

This policy is a pure, deterministic transition checker with no Fuseki,
Redis, broker, federation, identity, authentication or signing work. Its
absence of external IO is useful for per-operation cost, but it is **not**
an authorization boundary on its own.

## Canonical admission states

- `requested`: a verified subject initiated a restricted Group request.
- `invited`: a permitted manager offered membership. This is **not** active.
- `active`: the actor self-joined a public Group, accepted a prior invite,
  or initiated a restricted request which a manager then approved.
- `left`: the member left, declined, withdrew or was removed.
- `banned`: disallows requests/invites/acceptance; unban transitions to
  `left`, never directly to `active`.

Private Groups require invitations. Following and subscribing to ActivityPub
Group actors remain separate from member/role grants. Remote membership must
not be inferred from a Follow alone.

## Delegated moderation constraints

The current owner is immutable in this policy. The owner role must be
validated against the provider's authenticated and persisted Group owner,
not client metadata. Moderators may act only on members, admins on
moderators/members, and the owner on all nonowner roles. No self-ban,
self-moderation, peer-role escalation, implicit owner transfer or
unconsented moderator/admin promotion. Co-ownership and offered role
delegation require a separate explicit acceptance contract.

## Required integration before any runtime action

1. Define provider-issued Group membership **self-action** grants bound to
   existing Solid-OIDC identity and authorized app, plus a federated
   authenticated remote-actor equivalent. Never use raw `actor` or
   `actorRole` from a public payload as authorization.
2. Add `requested` and `invited` storage states and a durable provenance
   record of the authenticated request/acceptance/approval event. Ban and
   revocation tombstones survive retries and restarts.
3. Resolve actor role, target state, Group visibility and consent rev under
   one stable provider authority snapshot; enforce epoch CAS and
   actor/Group-specific idempotency. Revalidate authorization at commit.
4. Keep SAI `ManageMembers` for manager actions and add narrowly scoped,
   app-neutral user participation consent to self-service operations.
   ATProto OAuth and Solid-OIDC remain separate grants.
5. Prove denial of identity spoofing, moderation escalation, stale retries,
   deleted account, revoked consent, private membership disclosure and
   cross-protocol unauthorized joins against **real** TDB2 and provider
   HTTP gateway, including SIGKILL/restart and multi-replica races.
6. Only then connect a versioned, authoritative admission snapshot to
   read-only membership and future G2 delivery. Never enable an
   owner-forced `active` assignment route.

The existing `CONSENT_BRIDGE_RELEASED=false` must remain immutable until
all relevant identity, privacy, cost and federation gates pass.

## Complexity and cost

The pure policy evaluator does constant bounded in-process work per
authorized requested transition. It does not scan members or resolve actors.
The actual authorization/store execution must similarly use bounded
per-transition queries and transactionally indexed Group/member records,
not a provider-wide account lookup or a per-recipient Moleculer/RDF cascade.
The policy code alone supplies no measured TDB2 throughput evidence.

See `docs/paper-groups-g2-membership-authority.md` and
`docs/paper-groups-g2-delivery-architecture.md`.
