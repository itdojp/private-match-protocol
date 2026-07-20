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
| Lifecycle | `phase`, `terminal_reason`, `audit_lifecycle` | Normalized state and bounded audit outcome. |
| Session | `session_id`, `protocol_profile`, `policy_binding`, `intended_audience` | Exact versioned context for every accepted event. |
| Participants | `participant_binding`, `policy_acceptance` | Party and key identities plus policy acceptance. |
| Commitments | `commitment`, `commitment_pair_id` | Immutable opaque inputs to one evaluation. |
| Evaluation | `evaluation_started`, `evaluation_attempt_id`, `evaluation_contribution`, `accepted_evaluation_count` | One accepted attempt per commitment pair. |
| Budget | `query_budget_state` | Coordinator-authoritative reservation and consumption. |
| Result | `proposed_result_state`, `accepted_result_state`, `opaque_receipt_ref`, `result_ack` | Party-local proposed/accepted values and shared opaque reference. |
| Consent | `consent`, `disclosure_profile_ref`, `disclosure_state` | Result-bound extension authorization metadata. |
| Time | `session_created_at`, `session_expires_at`, `authoritative_time`, `allowed_clock_skew`, `message_stale_threshold`, `verification_material_validity` | Coordinator-authoritative ordering and validity. |
| Replay | `next_sequence`, `accepted_message_ids`, `accepted_nonces`, `accepted_event_digests`, `normalized_responses` | Ordering, duplicate equality, and prior response. |

`proposed_result_state` records the party-local value bound by each receipt
acknowledgment. `accepted_result_state` is written only after the proposed values
and opaque references agree. Both are party-local maps whose members are `NONE`,
`MATCH`, `NO_MATCH`, `INDETERMINATE`, or `CONFLICT`, and both are prohibited from
coordinator state and visibility. `CONFLICT` is a fail-closed local marker and
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
owner, visibility, prohibited data, audit fields, idempotency behavior,
conflicting-duplicate behavior, retry class, and default failure. These are
abstract event parameters, not Protocol Issue #5 wire-message fields.

## Transition relation

Every transition contains structured `guards` and `effects`. A guard identifies
its predicate, state variables read, and arguments. An effect identifies its
operation, state variables written, and arguments. Narrative notes do not define
state changes.

The major transition families are:

| Stage | Events | Phase effect |
| --- | --- | --- |
| Creation | `create_session` | `UNINITIALIZED` to `CREATED` |
| Participant binding | `bind_participant_a`, `bind_participant_b` | Remain `CREATED` until both are bound, then `PARTICIPANTS_BOUND` |
| Policy and budget | `accept_policy`, `reserve_query_budget` | Reserve only after both accept; then `COMMITMENTS_PENDING` |
| Commitment | `register_commitment_a`, `register_commitment_b` | Bind once; then `COMMITTED` |
| Evaluation | `start_evaluation`, `submit_evaluation_contribution` | Consume budget atomically and enter/remain `EVALUATING` |
| Receipt | `acknowledge_opaque_receipt_a`, `acknowledge_opaque_receipt_b` | Record party-local binding and shared opaque reference |
| Result | `accept_symmetric_result` | `RESULT_ACCEPTED` or fail closed to `ABORTED` on conflict |
| Consent | `grant_consent_a`, `grant_consent_b` | Enter/remain `CONSENT_PENDING` |
| Withdrawal | `withdraw_consent_a`, `withdraw_consent_b` | Invalidate authorization and return to `RESULT_ACCEPTED` |
| Extension | `authorize_disclosure_extension` | Extension-only transition to `DISCLOSURE_AUTHORIZED` |
| Completion | `record_disclosure_completion` | Extension-only completion to `CLOSED` |
| Terminal | `abort_session`, `expire_session`, `close_session` | Enter `ABORTED`, `EXPIRED`, or `CLOSED` |
| Duplicate | `retry_idempotent_message` | No-op and return the prior normalized response |
| New evaluation | `request_new_evaluation_session` | No change to current session; require new authorization and binding |

The YAML contains 35 transitions because participant order, first/final binding,
normal result acceptance, conflict, timeout, partial failure, and extension
authorization have different guards and effects, while each party has explicit
exact-replay and new-session guidance transitions.

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

A nonce is unique in that domain. An exact duplicate requires the same
`message_id`, nonce, and canonical event digest. It returns the prior bounded
response without changing state or consuming budget again. Reusing either ID or
nonce with a different digest is `REPLAY_CONFLICT`.

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
   `RESERVED` to `CONSUMED`, sets `evaluation_started`, and binds one attempt ID.
3. Timeout, partial failure, conflict, or `INDETERMINATE` does not automatically
   return budget.
4. An exact duplicate of the same accepted event does not consume budget again.
5. A refund requires an explicit versioned policy and auditable transition; none
   exists in v0.1.
6. A new commitment pair or session requires new authorization.

This choice prevents failure-driven free probing. It does not establish that a
particular operational budget, minimum set size, or abuse policy is sufficient.

## Result acceptance

The parties derive their local result under a selected profile and acknowledge
the profile-defined opaque receipt. Acceptance requires:

- both acknowledgments exist;
- both reference exactly the same opaque receipt;
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

A withdrawal accepted before completion invalidates the authorization. A
completion accepted before a later withdrawal is not retroactively reversed.
The coordinator's monotonic sequence and authoritative event order decide the
race. No actual identity or private-data payload is modeled in core.

## Clock and expiry

The coordinator clock is authoritative for transitions. A client `issued_at`
value is auxiliary and cannot extend validity.

The following are typed, bounded policy parameters rather than fixed business
values:

- allowed clock skew: non-negative and less than the session TTL;
- session TTL: positive;
- consent TTL: positive and no later than session expiry;
- stale-message threshold: non-negative;
- verification-material interval: closed-open validity range; and
- evaluation timeout: bounded per selected profile and policy.

`timeout` terminates the current evaluation as `ABORTED`; `expiry` terminates the
whole session as `EXPIRED`. `authoritative_time` never decreases. A rollback or
ambiguous time source fails closed and is audited.

## Ordering and retries

Each party has a monotonic `next_sequence`.

| Input condition | Result |
| --- | --- |
| Expected sequence, new ID, new nonce | Evaluate guards; accepted event advances the sender sequence. |
| Exact same ID, nonce, and canonical digest | No-op; return prior normalized response. |
| Same ID or nonce, different digest | `REPLAY_CONFLICT`; no partial state change. |
| Lower sequence with unknown message | `REPLAY` or `STALE_MESSAGE`; no state change. |
| Future sequence gap | Retryable `OUT_OF_ORDER`; no buffering or state change. |
| Cross-session message | `SESSION_MISMATCH`. |
| Prior policy message | `POLICY_VERSION_MISMATCH`. |
| Prior participant-set message | `PARTICIPANT_MISMATCH`. |

The machine distinguishes idempotent resend, transient new-message retry,
continuation of the one bound evaluation, a retry requiring a new attempt ID,
new-session retry, and non-retryable terminal failure. v0.1 defines no same-pair
new-attempt transition.

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
| Consent | `CONSENT_MISSING`, `CONSENT_EXPIRED`, `CONSENT_WITHDRAWN` | No disclosure authorization. |
| Disclosure | `DISCLOSURE_PROFILE_REQUIRED`, `DISCLOSURE_SCOPE_MISMATCH` | Core remains fail closed. |
| Session | `SESSION_EXPIRED`, `SESSION_CLOSED`, `SESSION_ABORTED` | No mutating operation. |
| Unknown | `UNKNOWN_STATE`, `UNKNOWN_EVENT`, `UNKNOWN_VERSION`, `UNKNOWN_FIELD` | Fail closed; do not infer new semantics. |

Detailed failure information is restricted to the coordinator and approved audit
when revealing it would increase counterparty inference. Parties receive a
bounded category.

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

Candidate fairness assumptions include weak fairness for authoritative expiry and
enabled contribution processing. No fairness assumption forces a party to
respond or consent.

The later TLA+ work must not invent different result, receipt, replay, budget,
consent, or disclosure semantics. Model-checking success is not claimed here.

## Compatibility and claim boundary

This artifact is draft `private-match-core/v0.1`. It makes no compatibility
commitment. Weakening result symmetry, minimum disclosure, coordinator outcome
confidentiality, replay, query budget, consent, expiry, or unknown-field handling
is a breaking protocol change under `GOVERNANCE.md`.

Schema and unit-test success establish only structural and semantic consistency
of this draft. They do not establish cryptographic security, endpoint security,
collusion resistance, traffic-analysis resistance, input truth or completeness,
legal compliance, implementation conformance, or production readiness.
