# Private Match core session and disclosure state machine v0.1

## Status and scope

- Artifact status: **draft**
- Protocol profile: `private-match-core/v0.1`
- Machine artifact:
  [`private-match-core-session-v0.1.yaml`](private-match-core-session-v0.1.yaml)
- JSON Schema:
  [`session-state-machine.schema.json`](../../schema/session-state-machine.schema.json)
- Decision record:
  [ADR-0003](../../docs/decisions/ADR-0003-CORE-SESSION-STATE-MODEL.md)

This specification defines an abstract, two-party session lifecycle. It fixes the
state ownership, transition guards, replay behavior, query-budget semantics,
result acceptance, consent registration, optional disclosure-extension guards,
expiry, and failure handling needed before message schemas are defined.

It does not select a PET, define wire fields, implement cryptography, transport,
persistence, or a coordinator, carry an actual disclosure payload, or establish a
security or production-readiness claim. TLA+ has not been created or run for this
artifact.

The normative machine-readable artifact is strict and fail closed. This document
explains it. If the two differ, the conflict requires protocol review rather than
an implementation-specific interpretation.

## Normative result and disclosure boundary

The only party decision values are:

```text
MATCH
NO_MATCH
INDETERMINATE
```

Both parties must accept the same value. The coordinator is not given any of
these plaintext values. It records only a normalized lifecycle state and an
opaque receipt reference defined by a separately reviewed integration profile.

The core profile prohibits:

- exact intersection count;
- matching or non-matching elements;
- identity or private-attribute reveal;
- party-specific accepted results;
- coordinator access to a plaintext outcome;
- raw or normalized private inputs outside their approved client boundary;
- actual disclosure payloads; and
- silent downgrade, fallback, or use of an unknown profile.

`MATCH` is not consent. The core machine can record result-bound bilateral
consent and describe an extension authorization guard. It has no disclosure
profile, so authorization and completion are unreachable in
`private-match-core/v0.1`. Actual disclosure requires a separate, versioned,
reviewed disclosure profile.

## State vector

The state is not represented by one ambiguous status string. `phase` is only the
normalized lifecycle dimension. Orthogonal state retains the bindings and
monotonic facts needed for later formalization.

### Lifecycle phases

| Phase | Terminal | Core reachable | Meaning |
| --- | ---: | ---: | --- |
| `UNINITIALIZED` | no | yes | No session exists; only creation is enabled. |
| `CREATED` | no | yes | Session, versions, audience, clocks, and replay domains exist. |
| `PARTICIPANTS_BOUND` | no | yes | Both participant and key bindings exist. |
| `COMMITMENTS_PENDING` | no | yes | Budget is reserved; commitments may be registered. |
| `COMMITTED` | no | yes | Both immutable commitments and the pair identifier exist. |
| `EVALUATING` | no | yes | The first attempt has atomically consumed the reservation. |
| `RESULT_ACCEPTED` | no | yes | Both parties accepted one symmetric result and receipt. |
| `CONSENT_PENDING` | no | yes | Result-bound consent metadata exists; no disclosure is authorized. |
| `DISCLOSURE_AUTHORIZED` | no | **no** | A reviewed extension is authorized; unreachable in core. |
| `CLOSED` | yes | yes | No further mutating protocol operation is allowed. |
| `ABORTED` | yes | yes | The session failed closed; another evaluation needs a new session. |
| `EXPIRED` | yes | yes | Authoritative session expiry has passed. |

Terminal sessions permit only exact idempotent replay, bounded rejection or
status behavior, and guidance to request a new session. These operations do not
change session, sequence, nonce, budget, consent, or result state.

### Binding and lifecycle variables

The machine artifact defines the full type, initial value, owner, visibility,
coordinator access, and description for every variable. The principal groups are:

| Group | Variables | Normative purpose |
| --- | --- | --- |
| Lifecycle | `phase`, `terminal_failure_code`, `party_terminal_category`, `audit_lifecycle` | Private failure detail, reviewed Party projection, and bounded audit outcome. |
| Session | `session_id`, `protocol_profile`, `policy_binding`, `intended_audience` | Exact versioned context for every accepted event. |
| Participants | `participant_binding`, `policy_acceptance` | Party and key identities plus policy acceptance. |
| Commitments | `commitment`, `commitment_pair_id` | Immutable opaque inputs to one evaluation. |
| Evaluation | `evaluation_started`, `evaluation_attempt_id`, `evaluation_deadline`, `evaluation_contribution`, `accepted_evaluation_count` | One accepted attempt and an explicit authoritative deadline per commitment pair. |
| Budget | `query_budget_state` | Coordinator-authoritative reservation, consumption, release, or expiry. |
| Result | `proposed_result_state`, `accepted_result_state`, `opaque_receipt_ref`, `result_ack` | Party-local proposed/accepted values and shared opaque reference. |
| Consent | `consent`, `disclosure_profile_ref`, `disclosure_state` | Result-bound extension authorization metadata. |
| Time | `session_created_at`, `session_expires_at`, `authoritative_time`, `allowed_clock_skew`, `message_stale_threshold`, `verification_material_validity` | Coordinator-authoritative ordering and validity. |
| Replay | `accepted_message_records`, `normalized_message_responses`, `operation_by_id`, `operation_by_key`, `callback_by_id`, `callback_by_key` | Sender-scoped responses plus independently indexed delivery identity and idempotency keys. |

`proposed_result_state`, `result_ack`, and `accepted_result_state` use
machine-readable entry-scoped visibility. Party A can read only entry A and
Party B can read only entry B. Before and after acceptance, neither party is
granted peer local-result or acknowledgment-binding access. The coordinator
projection for `result_ack` is exactly `opaque_receipt_ref` and
`normalized_ack_status`; the other two maps have no coordinator projection.
The selected integration profile's access is profile-dependent and is not an
unconditional core grant.

The global specification observer may compare A and B to evaluate
`INV-RESULT-SYMMETRY`. That mathematical observer is not an implementation
actor and grants no read access. `CONFLICT` is a fail-closed local marker and
never an accepted decision result.

The coordinator may store `opaque_receipt_ref`, but it must treat the reference
as opaque bytes. It must not be:

- `hash(MATCH)`;
- `hash(NO_MATCH)`;
- `hash(INDETERMINATE)`; or
- another bare low-entropy digest that permits a three-value dictionary attack.

The selected integration profile must define a high-entropy or confidential
reference bound to the session, participants, policy, commitment pair,
evaluation attempt, and profile version. No concrete construction is selected
here, and coordinator outcome confidentiality remains an unresolved target until
profile and implementation evidence exist.

## Actors and authority

The machine models:

- Party A client;
- Party B client;
- coordinator;
- abstract selected integration profile;
- service operator;
- assurance pipeline;
- network observer; and
- malicious participant.

The coordinator is authoritative for:

- session phase and terminal reason;
- participant, key, protocol, policy, and audience binding;
- replay domains, accepted IDs, nonces, event digests, and sequences;
- query-budget reservation and atomic consumption;
- authoritative event ordering and expiry; and
- normalized audit lifecycle.

The party clients are authoritative for their local decision value and consent
artifact. The abstract integration profile verifies profile-specific
contributions and defines the opaque receipt construction. The service operator
and assurance pipeline are not authorities for protocol result meaning.

Each event in the YAML identifies its initiator, verifier, authoritative state
owner, visibility, prohibited data, audit fields, delivery class, required
envelope, deduplication domain, idempotency behavior, conflicting-duplicate
behavior, retry class, and default failure. These are abstract event parameters,
not Protocol Issue #5 wire-message fields.

### Delivery and duplicate classes

| Class | Required identity | Exact duplicate behavior |
| --- | --- | --- |
| `party_message` | session context plus sender, sequence, `message_id`, nonce, `issued_at`, and canonical event digest | Return the prior normalized message response; do not repeat state, sequence, budget, release, or audit. |
| `coordinator_command` | actor-scoped `operation_id`, idempotency key, and canonical operation digest | Return the prior normalized operation response through the operation retry path. |
| `profile_callback` | profile ID/version/instance, session, attempt, callback ID, idempotency key, and canonical callback digest | Return the prior normalized callback response through the callback retry path. |
| `timer` | bounded authoritative time and source class | Level-triggered; the same threshold is a no-op and has no message ID or nonce. |
| `derived_transition` | current state predicate | No external delivery or retry identity. |
| `local_guidance` | current state | Non-mutating guidance only; no external duplicate identity. |

The party-only `retry_idempotent_message` relation never applies to coordinator
commands or profile callbacks. Those classes have independent actor-scoped
registries and no-op retry relations. Reusing an operation or callback ID with a
different key or digest, or reusing a key with a different ID or digest, fails
closed as `REPLAY_CONFLICT`. The coordinator operation actor must be
`coordinator`. A callback must match the selected profile ID, version, instance,
session, and evaluation attempt already held in state.

Party message responses are cached under
`(session_id, sender_participant_id, message_id)`. The accepted record also
stores nonce, sequence, `issued_at`, and canonical event digest. Party A can
retrieve only Party A's sender-domain response and Party B can retrieve only
Party B's. The coordinator may hold the authoritative whole map; neither Party
has whole-map or peer-entry access.

### Machine-readable event-parameter flow

All 21 abstract event-parameter records have field-level catalogs. The YAML also
contains 92 predicate/operation contracts that list each required
`parameter_reads` path. This makes session and policy context, sender identity,
message replay identity, participant/key binding, policy acceptance digest,
commitment, attempt, contribution, local result, receipt, consent, extension,
abort reason, operation/callback envelope, and authoritative-time flow explicit.
Six additional equality contracts bind the operation actor and callback profile,
instance, session, and attempt fields to the current transition/state.

The validator rejects an unknown field path, a field not declared by the event,
a missing contract field, a wrong parameter substitution, or a required event
parameter that is declared but unused. These are abstract state-relation inputs;
the Issue #5 registry now defines their canonical message sources; transport-specific
framing remains outside both drafts.

## Transition relation

Every transition contains structured `guards` and `effects`. A guard identifies
its predicate, state variables read, and arguments. An effect identifies its
operation, state variables written, and arguments. Narrative notes do not define
state changes.

The major transition families are:

| Stage | Events | Phase effect |
| --- | --- | --- |
| Creation and acceptance | `create_session`, `accept_session_a`, `accept_session_b` | Create, then record Party-specific exact-proposal acceptance |
| Participant binding | `bind_participant_a`, `bind_participant_b` | Remain `CREATED` until both are bound, then `PARTICIPANTS_BOUND` |
| Policy and budget | `accept_policy`, `reserve_query_budget` | Reserve only after both accept; then `COMMITMENTS_PENDING` |
| Commitment | `register_commitment_a`, `register_commitment_b` | Bind once; then `COMMITTED` |
| Evaluation | `start_evaluation`, `submit_evaluation_contribution` | Consume budget atomically and enter/remain `EVALUATING` |
| Receipt | `acknowledge_opaque_receipt_a`, `acknowledge_opaque_receipt_b` | Record party-local binding and shared opaque reference |
| Result | `accept_symmetric_result` | `RESULT_ACCEPTED` or fail closed to `ABORTED` on conflict |
| Consent | `grant_consent_a`, `grant_consent_b` | Enter/remain `CONSENT_PENDING` |
| Withdrawal | `withdraw_consent_a`, `withdraw_consent_b` | Invalidate authorization, enter `ABORTED`, and require a new session |
| Extension | `authorize_disclosure_extension` | Extension-only transition to `DISCLOSURE_AUTHORIZED` |
| Completion | `record_disclosure_completion` | Extension-only completion to `CLOSED` |
| Clock | `advance_authoritative_time`, `expire_session` | Advance only within the bounded time domain and atomically terminalize crossed deadlines |
| Terminal | `abort_session`, `expire_session`, `close_session` | Enter `ABORTED`, `EXPIRED`, or `CLOSED` with explicit budget disposition |
| Duplicate | party, operation, and profile retry events | No-op and return the delivery-class-specific prior normalized response |
| New evaluation | `request_new_evaluation_session` | No change to current session; require new authorization and binding |

Session acceptance stores the trusted participant, key, subject-binding, and
verification-material identity produced after material validation. Participant
binding must equal that immutable Party-specific acceptance record; a different
active material or key requires a new session because v0.1 has no rotation
transition.

The YAML contains 41 transitions. Proposal acceptance, participant order, first/final binding,
result acceptance, conflict, deadline crossing, extension authorization, and
delivery-class retry paths have distinct guards and atomic effects.

## Normative invariants

### `INV-REVEAL-SAFETY`

Disclosure completion implies all of the following:

- both party-local accepted results are `MATCH`;
- both valid consents bind to the same session, participant set, opaque receipt,
  disclosure profile ID/version, exact scope, intended audience, and expiry;
- both consent artifacts contain issuance time, nonce, and artifact digest;
- a separately reviewed disclosure profile exists;
- the session is not expired, closed, or aborted; and
- no earlier accepted withdrawal precedes completion in coordinator ordering.

The core profile has `disclosure_profile_ref = NONE`; therefore completion is
unreachable.

### `INV-RESULT-SYMMETRY`

Both parties acknowledge the same opaque receipt and accept identical local
values. One-party acceptance, asymmetric acceptance, result preference, and
automatic fallback are forbidden. Conflict moves to `ABORTED` with normalized
`RESULT_CONFLICT`. The coordinator need not and must not receive the value.

### `INV-COMMITMENT-IMMUTABILITY`

After `evaluation_started` becomes true, neither commitment, the commitment pair,
policy/version binding, nor participant/key binding can change.

The pair identifier is never Party supplied. On the second Party commitment the
coordinator atomically derives `sha256:<64 lowercase hex>` from RFC 8785 bytes in
fixed A/B slot order under `private-match-commitment-pair/v0.1`. The canonical
input includes protocol profile, policy, session, participant bindings, selected
integration profile, and both opaque commitments. Before the second commitment
the identifier remains `NONE`. This construction binds identity only; it does
not prove commitment truth, input completeness, or PET security.

### `INV-SESSION-BINDING`

Every accepted post-creation event binds to the current session ID, protocol
profile/version, policy ID/version, participant and key set, intended audience,
commitment pair, and evaluation attempt. Values not created yet bind explicitly
to `NONE`; they are not omitted or inferred.

### `INV-NO-REPLAY` and `INV-IDEMPOTENCY`

The replay domain is:

```text
(session_id, sender_participant_id)
```

A nonce is unique in that domain. An exact duplicate requires the same sender,
session, `message_id`, nonce, sequence, `issued_at`, and canonical event digest.
It returns only that sender's prior bounded response without changing state or
consuming budget again. Reusing either ID or nonce with a different identity
field or digest is `REPLAY_CONFLICT`.

### `INV-ONE-EVALUATION`

A commitment pair receives at most one accepted evaluation. Timeout, failure, or
`INDETERMINATE` cannot be used for a free second attempt. A subsequent evaluation
requires a new session or a separately reviewed versioned retry transition, a
new budget authorization, participant/policy rebinding, and the applicable
material dataset-change policy.

### `INV-EXPIRY`

`EXPIRED`, `CLOSED`, and `ABORTED` sessions accept no mutating evaluation, result,
consent, disclosure authorization, or disclosure-completion transition.

### `INV-MINIMUM-DISCLOSURE`

Core state, audit, errors, and normalized responses contain none of:

- raw identifiers;
- normalized private inputs;
- matching or non-matching elements;
- exact intersection count;
- coordinator plaintext decision outcome;
- private attributes;
- local secrets; or
- actual disclosure payload.

### Additional invariants

`INV-OPAQUE-RECEIPT`, `INV-QUERY-BUDGET`, and
`INV-COORDINATOR-OUTCOME-CONFIDENTIALITY` make the receipt, budget, and
coordinator boundaries independently reviewable.

## Query-budget semantics

The coordinator is the sole authoritative budget owner. A client counter is not
sufficient.

1. Reservation occurs after the session and policy bindings exist and before
   commitment evaluation.
2. The first accepted `start_evaluation` atomically changes the reservation from
   `RESERVED` to `CONSUMED`, sets `evaluation_started`, binds one attempt ID, and
   sets `evaluation_deadline` from the reviewed policy parameter.
3. Timeout, partial failure, conflict, or `INDETERMINATE` does not automatically
   return budget.
4. An exact duplicate of the same accepted event does not consume budget again.
5. Before evaluation starts, `close_session` or `abort_session` atomically moves
   an unused `RESERVED` authorization to `RELEASED`; `expire_session` moves it to
   `EXPIRED`. These are reservation dispositions, not post-result refunds.
6. After evaluation starts, terminalization leaves the state `CONSUMED`. Result,
   timeout, failure, conflict, and `INDETERMINATE` never refund it.
7. Release or expiry is assumed atomic with the opaque authorization ledger and
   emits only a normalized audit category. The terminal session cannot reuse it.
8. A new commitment pair or session requires new authorization.

This choice prevents failure-driven free probing. It does not establish that a
particular operational budget, minimum set size, or abuse policy is sufficient.

## Result acceptance

The parties derive their local result under a selected profile and acknowledge
the profile-defined opaque receipt. Acceptance requires:

- both profile contribution records exist;
- both acknowledgments exist;
- both reference exactly the same opaque receipt;
- each Party status is `ACKNOWLEDGED` and the profile callback status is
  `BOTH_ACKNOWLEDGED`;
- the callback evidence and identity bind the current profile, session, and
  evaluation attempt;
- both local result values are identical and in the three-value result set;
- no result has already been accepted for the commitment pair;
- verification material exists and is current; and
- the session is live.

`INDETERMINATE` is a valid minimum result. It is not a disclosure condition and
does not authorize another attempt on the same commitment pair.

## Consent and disclosure extension

Consent may be registered only after result acceptance. Each consent binds to:

- session ID;
- participant set;
- opaque receipt reference;
- disclosure profile ID and version;
- exact disclosure scope;
- recipient or intended audience;
- `issued_at` and `expires_at`;
- consent nonce; and
- consent artifact digest.

The abstract executor checks these values across messages rather than only
checking phase prerequisites. A consent receipt must equal the accepted receipt;
the bilateral profile ID/version, scope, and audience must match exactly; the
coordinator-authoritative time must be inside the consent interval; and each
Party nonce/digest slot is immutable. Failed cross-message guards are atomic and
do not update state, dedup indexes, transcript, query budget, or audit state.

v0.1 chooses **new session required** after consent expiry or withdrawal. Each
party consent slot is single-use within the session. An accepted withdrawal
before completion atomically invalidates authorization, enters `ABORTED`, and
records `CONSENT_WITHDRAWN`. Crossing any active consent expiry similarly enters
`ABORTED` with `CONSENT_EXPIRED`. Old and new consent generations cannot be
mixed because no same-session replacement transition exists.

A completion accepted before a later withdrawal remains historical; `CLOSED`
does not accept that mutation and the past disclosure is not reversed. A later
authorization requires a new session, result, budget, and bilateral consent.
The coordinator's event order decides the completion/withdrawal race. No actual
identity or private-data payload is modeled in core.

## Clock and expiry

The coordinator clock is authoritative for transitions. The explicit
`advance_authoritative_time` timer relation accepts a bounded
`new_authoritative_time` and source class. It never decreases time. A client
`issued_at` value is auxiliary and cannot advance, roll back, or extend
validity.

The following are typed, bounded policy parameters rather than fixed business
values:

- allowed clock skew: non-negative and less than the session TTL;
- session TTL: positive;
- consent TTL: positive and no later than session expiry;
- stale-message threshold: non-negative;
- verification-material interval: closed-open validity range; and
- evaluation timeout: bounded per selected profile and policy; and
- maximum authoritative-time jump: a reviewed finite non-negative bound carried
  by the accepted session proposal, not a Party-controlled business duration.

For party messages, validity is:

```text
authoritative_time - message_stale_threshold
  <= issued_at
  <= authoritative_time + allowed_clock_skew
```

`start_evaluation` sets `evaluation_deadline`. A time proposal crossing that
deadline enters `ABORTED` with `EVALUATION_TIMEOUT`. A proposal crossing session
expiry atomically updates time, enters `EXPIRED`, invalidates disclosure
authorization, records `SESSION_EXPIRED`, and applies the budget disposition.
When one proposal crosses several thresholds, the machine selects exactly one
effect in this order: session expiry, evaluation timeout, active-consent expiry,
then normal live advance. The reviewed reason/source class must match the
derived effect and cannot select a transition. State effects and the canonical
transcript append are committed together or not at all.
The live-time relation is disabled at a crossed session, evaluation, or consent
deadline, so no active post-deadline window exists. A same-time proposal is a
no-op. Rollback, out-of-domain time, and policy-excessive jumps reject as
`CLOCK_ROLLBACK`, `CLOCK_DOMAIN_INVALID`, and `CLOCK_JUMP_EXCEEDED`. Parties
receive only `CLOCK_ERROR`. A timer recheck in a terminal phase maps to
`SESSION_CLOSED`, `SESSION_ABORTED`, or `SESSION_EXPIRED`; `STALE_MESSAGE`
remains exclusive to Party `issued_at` validation.

## Ordering and retries

Each party has a monotonic `next_sequence`.

| Input condition | Result |
| --- | --- |
| Expected sequence, new ID, new nonce, valid `issued_at` | Evaluate guards; accepted event advances the sender sequence. |
| Exact same sender-domain ID, nonce, sequence, `issued_at`, and canonical digest | No-op; return only the sender's prior normalized message response. |
| Same ID or nonce, different digest | `REPLAY_CONFLICT`; no partial state change. |
| Lower sequence with unknown message | `REPLAY` or `STALE_MESSAGE`; no state change. |
| Future sequence gap | Retryable `OUT_OF_ORDER`; no buffering or state change. |
| Cross-session message | `SESSION_MISMATCH`. |
| Prior policy message | `POLICY_VERSION_MISMATCH`. |
| Prior participant-set message | `PARTICIPANT_MISMATCH`. |

Coordinator operations maintain independent `(actor_id, operation_id)` and
`(actor_id, idempotency_key)` indexes. Profile callbacks maintain independent ID
and key indexes inside the profile-instance/session/attempt domain. First
acceptance writes both indexes and the same prior response atomically. Exact
retries are available even after terminalization and write no state, budget,
release, disclosure, or audit. Timers are level-triggered and derived/local
relations have no external retry semantics.

Before current-head, time, or verification-material gates, an authoritative
retry handler strictly parses the input, validates its Schema, recomputes its
canonical digest, identifies the deduplication domain, and looks up an accepted
record. A complete match returns only the domain/recipient-scoped cached
response. Later expiry or revocation does not turn that response lookup into a
new protocol event. Without an accepted record, all current-event gates apply;
a stateless validator cannot infer or grant this historical duplicate path.

The machine distinguishes party resend, coordinator operation resend, profile
callback resend, timer re-evaluation, transient new-message retry, continuation
of the one bound evaluation, new-session retry, and non-retryable terminal
failure. v0.1 defines no same-pair new-attempt transition.

## Canonical accepted transcript

Issue #5 adds `accepted_event_index` and `canonical_transcript_head` as
coordinator-authoritative orthogonal variables. The genesis head, domain labels,
JCS rules, authentication input, and append formula are defined in the
[canonical transcript contract](../messages/canonical-transcript-v0.1.md).

Each mutating Party message, coordinator command, profile callback, or timer
transition checks that its supplied prior head equals the current head. The
validated canonical message or timer-event digest is then appended atomically
with the state mutation and the event index increments by exactly one. Party
senders cannot choose the authoritative event index.

The following do not append: rejected input, conflicting duplicate input, exact
duplicate resend, derived outbound notice, local guidance, and same-threshold
timer no-op. `INV-CANONICAL-TRANSCRIPT` and the semantic validator enforce this
classification. The transcript does not replace sender sequence, nonce, dual
operation/callback indexes, query-budget, or audit controls.

Coordinator-readable transcript inputs contain opaque receipt and normalized
lifecycle data, never the plaintext decision. Bare hashes of the three decision
values remain prohibited. This is a structural requirement and not evidence
that an unselected integration profile achieves outcome confidentiality.

## Generic abort

`abort_session` is a coordinator command, not a participant-controlled failure
selector. Its `normalized_failure_parameter.failure_code` must exist in the
declared taxonomy and have `session-abort` disposition. `G-ABORT-REASON` reads
that event parameter rather than prior terminal state.

`E-ABORT` atomically sets `phase = ABORTED`, copies the supplied code to
`terminal_failure_code`, derives `party_terminal_category` from the taxonomy,
invalidates disclosure authorization, applies the unused or consumed budget
rule, and records both operation indexes once. An undeclared or message-only
code is rejected. Party-initiated abort requests are deferred to the later
message-schema work; this draft does not let a party select an internal
coordinator failure category.

## Failure taxonomy

The YAML declares each code's rejection or abort disposition, retryability,
whether a new message or session is required, query-budget effect, party-visible
normalized category, and restricted detail visibility.

| Family | Codes | Default boundary |
| --- | --- | --- |
| Binding/version | `PARTICIPANT_MISMATCH`, `PROTOCOL_VERSION_MISMATCH`, `POLICY_VERSION_MISMATCH`, `SESSION_MISMATCH`, `AUDIENCE_MISMATCH` | Reject without partial mutation. |
| Replay/order | `REPLAY`, `REPLAY_CONFLICT`, `OUT_OF_ORDER`, `STALE_MESSAGE` | Exact replay is separate; conflict may abort. |
| Commitment | `COMMITMENT_MISMATCH`, `COMMITMENT_MUTATION` | Mutation after evaluation fails closed. |
| Budget | `QUERY_BUDGET_MISSING`, `QUERY_BUDGET_EXHAUSTED` | No evaluation without coordinator authorization. |
| Verification | `VERIFICATION_MATERIAL_MISSING`, `VERIFICATION_MATERIAL_EXPIRED` | Missing or expired material fails closed. |
| Evaluation | `EVALUATION_TIMEOUT`, `PARTIAL_PARTY_FAILURE`, `RESULT_CONFLICT` | Abort current session; consumed budget is not automatically returned. |
| Consent | `CONSENT_MISSING`, `CONSENT_EXPIRED`, `CONSENT_WITHDRAWN` | Expiry or withdrawal aborts same-session authorization; a new session is required. |
| Disclosure | `DISCLOSURE_PROFILE_REQUIRED`, `DISCLOSURE_SCOPE_MISMATCH` | Core remains fail closed. |
| Session | `SESSION_EXPIRED`, `SESSION_CLOSED`, `SESSION_ABORTED` | No mutating operation. |
| Clock | `CLOCK_DOMAIN_INVALID`, `CLOCK_ROLLBACK`, `CLOCK_JUMP_EXCEEDED` | Reject timer input; Party projection is only `CLOCK_ERROR`. |
| Unknown | `UNKNOWN_STATE`, `UNKNOWN_EVENT`, `UNKNOWN_VERSION`, `UNKNOWN_FIELD` | Fail closed; do not infer new semantics. |

`terminal_failure_code` is visible only to the coordinator and private assurance
pipeline. `party_terminal_category` is derived from the declared taxonomy and is
the only terminal failure projection available to either Party. Normalized
responses and public-safe audit projections prohibit raw failure codes and
private detail. Multiple detail codes may intentionally collapse to the same
reviewed category to reduce inference.

## Audit and visibility

Permitted audit fields are limited to:

- event ID;
- authoritative timestamp;
- actor category or pseudonymous reference;
- protocol profile and policy version;
- normalized lifecycle and error category;
- opaque artifact or transcript reference; and
- approved size class.

Audit and errors exclude plaintext decisions, private inputs, elements, counts,
secret consent material, local secrets, and disclosure payloads. This state
model does not claim traffic-analysis resistance: a network observer may still
see transport metadata described by the leakage contract.

## TLA+ readiness

The machine-readable artifact supplies:

- the complete state-variable list and initial values;
- an initial predicate;
- an event-to-transition relation;
- a next-state relation mapping;
- machine-readable invariant IDs and state references;
- fairness candidates;
- bounded participant, session, message, nonce, budget, and time parameters;
- unresolved nondeterminism; and
- environment assumptions.

The current model has 12 phases, 46 state variables, 20 parameter catalogs, 84
parameter-flow contracts, 6 envelope-binding contracts, 29 events, 41
transitions, 14 invariants, and 33 failure codes.

`create_session` binds one `session_proposal_digest` and the abstract reviewed
integration-profile binding supplied by that proposal. Both are unbound in the
pre-create state. Party A and Party B then use separate acceptance events to bind
their own immutable proposal and acceptance digests. Every participant-binding
transition has a Party-specific exact-proposal-acceptance guard. One Party cannot
satisfy the other Party's prerequisite, and an acceptance for another proposal
cannot bind a slot.

Candidate fairness assumptions include weak fairness for the authoritative timer
while a later bounded `TimeDomain` point exists, atomic expiry when the threshold
is reached, and enabled contribution processing. `TimeDomain` includes same-time
no-op, stale/future message bounds, evaluation deadline, consent and verification
expiry, session expiry, and maximum-jump points. The environment supplies only
nondecreasing policy-bounded clock proposals. No fairness assumption forces a
party to respond or consent.

The later TLA+ work must not invent different result, receipt, replay, budget,
consent, or disclosure semantics. Model-checking success is not claimed here.

## Compatibility and claim boundary

This artifact is draft `private-match-core/v0.1`. It makes no compatibility
commitment. Weakening result symmetry, minimum disclosure, coordinator outcome
confidentiality, replay, query budget, consent, expiry, or unknown-field handling
is a breaking protocol change under `GOVERNANCE.md`.

The Schema remains `0.1` for this review hardening because the artifact is still
Draft, has not been merged or published as a compatibility target, and has no
external stable reader commitment. The added required fields make the existing
unpublished draft unambiguous; they do not silently change a stable protocol.
A later compatibility commitment or accepted external implementation would
require an explicit version decision.

Schema and unit-test success establish only structural and semantic consistency
of this draft. They do not establish cryptographic security, endpoint security,
collusion resistance, traffic-analysis resistance, input truth or completeness,
legal compliance, implementation conformance, or production readiness.
