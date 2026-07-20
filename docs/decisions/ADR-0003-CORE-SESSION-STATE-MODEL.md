# ADR-0003: Draft core session and disclosure state model

- Status: Proposed for draft v0.1 review
- Artifact status: draft
- Protocol profile: `private-match-core/v0.1`
- Decision owner: ITDO Inc.
- Decision date: 2026-07-21
- Review date: 2026-10-21

## Context

Protocol Issue #4 requires one lifecycle definition for session creation,
participant and policy binding, commitment, evaluation, symmetric result
acceptance, consent, optional disclosure extension, retry, abort, close, and
expiry.

The prior leakage contract fixes a three-value result and prohibits exact count,
matching elements, identity reveal, asymmetric output, and coordinator plaintext
outcome in the core profile. A state model must preserve that boundary while
remaining translatable to TLA+ and independent of a specific PET, message format,
transport, persistence system, or product implementation.

This ADR records the selected draft semantics. It does not promote the profile to
candidate or stable, select a production technology, or claim model-checking or
implementation evidence.

## Decision

Adopt the machine-readable state vector and transition relation in
[`private-match-core-session-v0.1.yaml`](../../specs/state-machines/private-match-core-session-v0.1.yaml).

The principal choices are:

1. Use an orthogonal state vector with a normalized lifecycle phase rather than
   one status enum carrying all protocol facts.
2. Keep actual disclosure out of core. Core defines only result-bound consent and
   fail-closed guards for a separately reviewed versioned extension.
3. Keep each party decision and acknowledgment binding entry-scoped. The global
   invariant observer may compare A and B, but that observer is not an
   implementation actor. Give the coordinator only an opaque receipt reference,
   normalized acknowledgment status, and normalized lifecycle.
4. Reserve budget before evaluation and atomically consume it at the first
   accepted `start_evaluation`; release or expire an unused reservation on
   pre-evaluation terminalization and never refund after evaluation starts.
5. Use distinct delivery and duplicate identities for party messages,
   coordinator commands, profile callbacks, timers, derived transitions, and
   local guidance.
6. Order withdrawal and disclosure completion by the coordinator's authoritative
   monotonic event order and require a new session after consent withdrawal or
   expiry.
7. Require a new authorized session for another evaluation after
   `INDETERMINATE`, timeout, failure, or commitment-pair change in v0.1.
8. Model authoritative time with an explicit bounded monotonic environment/timer
   relation, an evaluation deadline, and atomic deadline crossing.

## Options considered

### Single lifecycle enum versus orthogonal state vector

**Option A:** Encode participant, commitment, evaluation, result, consent,
replay, and expiry facts in one expanding status enum.

**Option B:** Use a small normalized phase plus independently typed state
variables.

Option B was selected. It exposes the facts that transitions read and write,
avoids combinatorial status names, and maps more directly to variables and
predicates in a later TLA+ model. The validator rejects references to undeclared
variables and illegal terminal transitions.

### Core reveal transition versus extension-only authorization

**Option A:** Make identity or private-data reveal a normal core transition after
`MATCH`.

**Option B:** Let core record bilateral result-bound consent and define an
extension guard, while keeping authorization and completion unreachable until a
separately reviewed disclosure profile exists.

Option B was selected. `MATCH` is not blanket consent. The core profile has no
disclosure profile or payload. A future profile must bind exact scope, audience,
expiry, receipt, session, participants, and consent artifacts and undergo
separate protocol, privacy, publication, and compatibility review.

### Coordinator plaintext outcome versus opaque receipt reference

**Option A:** Send the coordinator `MATCH`, `NO_MATCH`, or `INDETERMINATE` and let
it compare values.

**Option B:** Keep values party-local and let the coordinator compare and record
only an opaque reference whose construction belongs to a selected reviewed
profile.

Option B was selected. A bare `hash(MATCH)`, `hash(NO_MATCH)`,
`hash(INDETERMINATE)`, or other three-value dictionary digest is forbidden. The
profile must provide a high-entropy or confidentiality property and binding to
the full session context. This is a requirement, not evidence that outcome
confidentiality has been achieved.

The selected state representation is entry-scoped: A cannot read B's local
proposal or acknowledgment and B cannot read A's. The selected integration
profile's access remains profile-dependent. Formal equality testing is a global
specification predicate, not permission for an implementation actor to read the
peer entry.

### Budget consumption at evaluation start versus result acceptance

**Option A:** Consume budget only when a result is accepted.

**Option B:** Reserve before evaluation and atomically consume on the first
accepted `start_evaluation`.

Option B was selected. Option A permits failures, timeouts, or deliberately
indeterminate executions to become free probes. Exact duplicate delivery does
not consume twice. If the session closes or aborts before evaluation starts, an
unused reservation becomes `RELEASED`; on pre-evaluation session expiry it
becomes `EXPIRED`. After start it remains `CONSUMED`. Release is assumed atomic
with the opaque authorization ledger and is not a post-result refund.

### Delivery-class duplicate handling

**Option A:** Apply party-message ID, nonce, and response prose to every event.

**Option B:** Give each delivery class a realizable identity and retry path.

Option B was selected. Party messages use sender sequence, message ID, nonce,
`issued_at`, and canonical event digest. Coordinator commands use an actor-scoped
operation envelope. Profile callbacks use profile-instance/session/attempt
scope. Timers are level-triggered without message IDs, and derived/local
relations have no external retry. An exact envelope duplicate returns its
class-specific prior response without another state, budget, release,
disclosure, or audit update. A reused identity with a different canonical digest
is `REPLAY_CONFLICT`.

### Authoritative time progression

**Option A:** Let future formalization or implementation attach an implicit clock
update to arbitrary transitions.

**Option B:** Add bounded `advance_authoritative_time` and expiry timer relations,
an explicit `evaluation_deadline`, and an `issued_at` party-message check.

Option B was selected. The live relation can update only `authoritative_time` and
stays below all active deadlines. Session expiry, evaluation timeout, and active
consent expiry are terminalized atomically with the time update. Same-time
evaluation is a no-op; rollback and policy-excessive jumps reject. This removes
the need to invent `Tick` semantics during later TLA+ translation.

### Consent withdrawal ordering

**Option A:** Let client timestamps decide whether withdrawal preceded
completion.

**Option B:** Use the coordinator's authoritative monotonic accepted-event order.

Option B was selected. Client time is auxiliary and cannot be the security
authority. Withdrawal accepted before completion invalidates authorization;
completion accepted first is not retroactively reversed.

### Consent expiry and replacement

**Option A:** Permit same-session replacement after expiry or withdrawal while
retaining prior consent history.

**Option B:** Make expiry or withdrawal fail closed and require a new session.

Option B was selected for draft v0.1. It avoids mixed consent generations,
reauthorization races, and accidental reuse of an old receipt/scope/audience
binding. Each party consent slot is single-use. Expiry or withdrawal enters
`ABORTED`; a later authorization requires a new session, result, budget, and
bilateral consent. `CLOSED` does not accept withdrawal and a past completed
disclosure is not reversed.

### `INDETERMINATE` retry semantics

**Option A:** Permit unlimited same-session reevaluation of the same commitment
pair.

**Option B:** Treat `INDETERMINATE` as a valid minimum result that ends the one
accepted evaluation; another evaluation requires a new session and budget.

Option B was selected for v0.1. A future same-pair retry would require a separate,
versioned, reviewed transition that preserves query-budget and leakage controls.

## Security and privacy assumptions

- Coordinator state transitions, delivery-class deduplication, budget,
  reservation release/expiry, and terminal updates are assumed atomic; no
  persistence implementation is supplied here.
- The coordinator clock/environment supplies only nondecreasing values in a
  finite policy-bounded time domain. Client timestamps are not clock authority.
- The selected integration profile is assumed to verify its own contribution and
  receipt rules; no profile or PET is selected here.
- Party clients protect their own local inputs, result values, and consent
  artifacts. A compromised endpoint is outside the protection established by
  this model.
- Participants may omit, fabricate, adapt, replay, reorder, or selectively submit
  inputs.
- Transport authentication and confidentiality are required environment
  assumptions, not implemented or evidenced by this artifact.
- Coordinator outcome confidentiality, malicious-party security, collusion
  resistance, side-channel resistance, and traffic-analysis resistance remain
  unresolved.

## Evidence

- Human-readable state-machine specification.
- Strict YAML artifact and Draft 2020-12 JSON Schema.
- Local-only semantic validator.
- Positive, negative, replay, expiry, malformed-input, disclosure-guard, and
  terminal-state unit tests.
- Existing privacy leakage contract and actor/trust-boundary specification.

This evidence establishes draft consistency only. It does not establish
cryptographic or implementation security.

## Compatibility impact

This adds the first session state-machine artifact for
`private-match-core/v0.1`. No stable implementation compatibility exists.
Changing accepted transitions, party result semantics, coordinator outcome
visibility, replay domain, budget consumption, consent binding, terminal
behavior, or unknown-field/version handling is a breaking change under
`GOVERNANCE.md` and requires explicit review and versioning.

This review keeps Schema version `0.1`. The artifact remains Draft, has not been
merged as a compatibility target, and has no stable external-reader commitment.
These required fields harden the unpublished draft rather than revising a stable
profile. A future compatibility commitment requires a separate version decision.

## Deferred decisions

- concrete PET and threat profile;
- opaque receipt construction and its evidence;
- message schemas, canonical encoding, signatures, and transport;
- persistence and transactional implementation;
- business values for clock, expiry, minimum-set, and budget parameters;
- any actual disclosure profile or payload;
- TLA+ syntax, bounds, fairness configuration, and model-check results; and
- candidate, stable, production, security-certification, or legal status.
