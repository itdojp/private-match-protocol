<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Experimental PET integration profiles

This directory defines the public, implementation-independent P4 boundary between
`private-match-core/0.1` and experimental PET adapters. The authority is the
reviewed Research snapshot at commit
`45607b57d61de5ff2d46a092dc24f6beb50dfe7c`; its candidate status remains
`not-run` and its production selection remains `not-selected`.

The registry contains two materially different complete-decision contracts:

- [SecretFlow KKRT PSI](secretflow-kkrt-v0.2.md), using a semi-honest PSI model;
- [AWS Nitro Enclaves](nitro-enclave-v0.2.md), using hardware attestation and a
  reviewed enclave-artifact policy.

The [RFC 9497/CIRCL VOPRF profile](voprf-component-v0.2.md) is component-only.
It cannot be selected as `selected_integration_profile`, does not define set or
session semantics, and cannot emit the Protocol result.

The profiles do not duplicate the State Machine. The
[machine-readable binding](protocol-binding.v0.2.yaml) references exact State
Machine and Message Registry semantic digests and maps profile operations to
existing events, messages, transitions, guards, effects, transcript behavior,
and replay/idempotency domains.

`result_acceptance_notice` is the only externally presented profile-callback
operation. `accept_symmetric_result` remains its existing State Machine effect;
it is not a second Product-port operation. The binding validator compares the
complete message version, delivery class, direction, sender, verifier, audience,
event, transition set, transcript behavior, and replay domain with the live
Message Registry and State Machine.

## Lifecycle-stage authority

`operation-stage-contract.v0.2.yaml` is a closed deterministic projection of
the current State Machine and Message Registry. Each operation has its own
pre-phase, transition set, post-phase/effect, field-availability rules,
transcript behavior, query-budget effect, and result classification. Early
operations use the core Protocol's explicit `NONE`/JSON `null` representation
and may not fabricate a future commitment pair, evaluation attempt, receipt,
verification material, or result state.

The executable operation Schema is stage-specific. Timeout and abort are
terminal outcomes, component registration is a non-State-Machine no-op, and
normal accepted mutations remain distinct. The validator projects these
outcomes from the existing State Machine; it does not implement a second State
Machine.

Receipt acknowledgment is accepted only after both Party contribution slots are
complete. The profile callback must repeat the exact resource-policy and
execution-authorization digests introduced at evaluation start. Evaluation
timeout compares an explicit new authoritative time with both the prior
authoritative time and the stored evaluation deadline. Generic abort accepts
every source phase listed by `TR-ABORT`; a consumed query budget remains
consumed, while a reservation is released only when evaluation has not started.
Within `EVALUATING`, the abort authority also follows a closed seven-row
contribution/receipt-acknowledgment matrix. Its acknowledgment-complete rows
distinguish no acknowledgment, Party A only, Party B only, and both Parties;
they do not collapse those states into a boolean. No acknowledgment requires a
null receipt and no proposed-result presence. Each acknowledgment requires both
completed contributions, the common opaque receipt, the corresponding
normalized acknowledgment binding, a domain-separated digest binding its
public profile-Evidence reference to the exact session/profile/instance/attempt
authority, and only a Party-local proposed-result **presence** marker. This
preserves state introduced atomically by
`TR-ACK-RECEIPT-A/B` even though those transitions keep the phase unchanged.
`TR-ABORT` retains those receipt and proposed-result audit references because
its reviewed effects do not write or clear them.

## Minimum result and private boundary

Every complete profile exposes only `MATCH`, `NO_MATCH`, or `INDETERMINATE` as
symmetric Party-local results bound to one high-entropy opaque receipt. Exact
counts, matching or non-matching rows, raw identifiers, participant identities,
private inputs, and Coordinator-visible plaintext results are prohibited.
Repeated-query controls and query-budget authority remain Protocol/Product
responsibilities rather than upstream PET responsibilities.

The public `presented_operation` surface never carries both Parties' plaintext
decisions. Synthetic callback conformance uses a separate, domain-separated
`synthetic-global-observer` record solely to check the closed decision
vocabulary, symmetry, and common receipt binding. That observer is not a
Protocol message, Coordinator input, Product port, or Evidence hook.

The exact Protocol policy ID and version are bound before evaluation and carried
through contributions, callbacks, receipts, transcript context, and the Product
handoff. A profile cannot choose a default predicate or change policy after
evaluation starts. This Draft selects no commercial predicate or match
threshold.

## Registration and execution boundary

Profile registration is not execution permission. Current profiles allow only
deterministic `contract-fixture` validation with synthetic inputs, prohibited
network execution, no candidate execution, and no paid-resource use. A future
SecretFlow candidate requires a reviewed local-experiment grant; a future Nitro
candidate requires a reviewed paid-AWS experiment grant. Missing authority is
`unsupported`, and production execution remains unsupported.

## Artifacts

- Research snapshot: `config/research-technology-authority.v0.1.json`
- Profile registry: `registry/pet-integration-profiles.v0.2.yaml`
- Product handoff: `handoff/product-decision-engine-port.v0.2.yaml`
- Protocol binding: `specs/pet-integration/protocol-binding.v0.2.yaml`
- Closed version graph: `config/pet-contract-compatibility.v0.2.json`
- Operation-stage authority:
  `specs/pet-integration/operation-stage-contract.v0.2.yaml`
- Conformance cases: `conformance/pet-profiles/case-catalog.v0.2.json`
- Closed operation input: `schema/pet-profile-operation-input.v0.2.schema.json`
- Executed case results:
  `generated/pet-integration/executable-case-results.v0.2.json`
- Preserved Draft v0.1 compatibility evidence: the prior profiles, registry,
  binding, Product handoff, operation-input, operation-stage, and case-catalog
  Schemas and records, generated operation inputs, comparison/index/projection,
  and executable result set remain byte-identical and digest-checked.
- Generated comparison/index/handoff projection/digest manifest:
  `generated/pet-integration/`

Run `python scripts/validate_pet_profiles.py --root .` to validate the complete
closed authority, or `python scripts/generate_pet_profiles.py --root . --check`
to check deterministic projections. Neither command executes a candidate or
uses a network service.

Every catalogued valid case is converted into a complete authoritative context
and presented operation, executed through the same semantic validator used by
negative cases, and bound by input/observer/result digests. This proves contract handling
only; it does not prove PET security, policy correctness, or candidate behavior.

## Corrective callback, abort, and error authority

Draft message compatibility is exact-version-only. `evaluation_start` and
`result_acceptance_notice` use message version `0.2`; all other Draft message
types remain at `0.1`. The callback's strict canonical payload repeats the
resource-policy binding and execution-authorization digest introduced at
evaluation start. Those values therefore participate in the payload digest,
message authentication input, semantic digest, wire fingerprint, replay and
conflict equality, and canonical transcript input. No unsigned side channel is
accepted.

The acknowledged-receipt abort correction adds required abort-state fields and
changes the required authority references of the binding and Product handoff.
The complete profile, registry, binding, handoff, operation, stage, case, result,
index, comparison, projection, and digest-manifest graph therefore advances to
version `0.2`. Published v0.1 artifacts remain byte-identical and are selected
only as the complete rollback graph. The machine-readable compatibility map
prohibits partial graphs, implicit fallback, forward inference, and v0.1/v0.2
mixing. A v0.1 reader must reject v0.2 instead of reinterpreting v0.1.

Before any acknowledgment Evidence digest is computed, the semantic validator
requires a closed profile authority containing exactly the profile ID, version,
digest, and instance ID. It then compares that authority with the selected
profile, session/evaluation authority, and each acknowledgment binding.
Malformed direct callers and normal Schema-driven callers both fail with the
bounded `PET-PROFILE-AUTHORITY` code; raw language exceptions are not exposed.

The operation-stage contract contains a closed matrix for all eight
`TR-ABORT` source phases. Participant, commitment, attempt, deadline,
resource-policy, authorization, contribution, acknowledgment, receipt, result,
consent, disclosure, query-budget, transcript, and cleanup state are checked as
one phase-specific authority. Future state, omitted prior state, and arbitrary
nullable combinations fail closed. In particular, the `EVALUATING` substate
rows bind per-Party normalized acknowledgment authority, a common receipt, and
per-Party proposed-result presence to the exact acknowledgment-slot set. An
acknowledgment with a null receipt or missing corresponding proposed-result
presence, an unacknowledged state with future receipt/result state, mixed
receipts, stale session/profile/attempt authority, or result acceptance before
`TR-ACCEPT-SYMMETRIC-RESULT` is rejected. Party-local plaintext values are not
included in the abort projection, Product handoff, Coordinator state, or
Evidence hooks.

`config/pet-profile-error-codes.v0.2.json` is the closed bounded error-code
authority. Automated parity checks cover runtime emissions, mutation
expectations, Schemas, and generated results. In particular, resource-policy
and execution-authorization callback mismatches remain distinct, while timeout
state/time authority, canonical monotonic time, and deadline crossing retain
separate codes.

The published distinctions are:

- `PET-RESOURCE-POLICY` for a callback resource-policy mismatch;
- `PET-EXECUTION-AUTHORIZATION-BINDING` for a callback execution-authority
  digest mismatch;
- `PET-EVALUATION-TIME-AUTHORITY` when stored and presented timer authorities
  disagree;
- `PET-AUTHORITATIVE-TIME-ORDER` for noncanonical or nonmonotonic time; and
- `PET-EVALUATION-DEADLINE` when the authoritative time has not reached the
  immutable deadline.
