<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# ADR-0006: Experimental PET integration profiles and Product handoff

- Status: Proposed
- Date: 2026-08-08
- Review deadline: 2027-01-31

## Context

The completed Research technology bake-off selected SecretFlow KKRT, RFC
9497/CIRCL VOPRF, and AWS Nitro Enclaves as reproduction-experiment tracks.
Research commit `45607b57d61de5ff2d46a092dc24f6beb50dfe7c` records no local
candidate result, no production selection, and a separate human-approval gate
for paid AWS execution. The Protocol must give Product Issue #6 sufficient
public decision-engine semantics without importing private Product structure or
claiming that a PET candidate has run.

## Decision

Define SecretFlow KKRT and Nitro Enclaves as experimental
`complete-decision-profile` contracts with materially different security and
trust models. Define RFC 9497/CIRCL VOPRF only as `component-only`; fail closed
if it is selected as the complete engine. Bind both complete profiles to the
existing State Machine, Message Registry, query budget, canonical transcript,
profile callback, Party receipt acknowledgment, and symmetric-result
transitions. Do not create a second core result.

Expose `result_acceptance_notice` as the single canonical profile-callback
operation. `accept_symmetric_result` is the existing State Machine event/effect,
not a second externally invokable operation. Validate complete Message Registry
parity rather than checking only that referenced names exist.

Derive one closed lifecycle-stage authority from the current State Machine and
Message Registry. Use operation-specific Schemas rather than one maximal
operation shape: fields not yet available are prohibited or explicitly
`NONE`/JSON `null`, timeout and abort are terminal, and each case binds its
pre-state, transition, post-state/effect, transcript behavior, budget effect,
and result visibility.

Treat contribution completion, receipt acknowledgments, evaluation-start
resource and authorization bindings, authoritative time, and evaluation
deadline as explicit State Machine authority. A callback cannot reconstruct or
omit the resource-policy or execution-authorization digest. Timeout requires a
monotonic authoritative-time advance that reaches the stored deadline. Generic
abort uses every reviewed `TR-ABORT` source phase and preserves a consumed
budget after evaluation starts.

Keep Party-local plaintext results outside the public presented operation.
Synthetic conformance may use a separate domain-separated global observer to
compare both Party-local decisions and their common receipt. The observer is
test-only and is never a Protocol message, Coordinator-visible value, Product
port input, or Evidence output.

The minimum complete-profile output is symmetric Party-local `MATCH`,
`NO_MATCH`, or `INDETERMINATE` bound to one opaque receipt. Upstream native
rows, exact counts, matching elements, raw identifiers, private inputs, and
Coordinator plaintext outcomes cannot cross the public Product-facing profile
boundary. Verification uses profile-specific source/key material for KKRT and
hardware attestation/nonce/PCR/artifact authorities for Nitro. Repeated-query,
query-budget, replay, timeout, cancellation, cleanup, and Evidence policy remain
Protocol/Product authorities.

Bind one externally selected Protocol policy ID/version through the complete
operation context, contribution, callback, receipt, transcript, and Product
handoff. Profiles may neither invent a default predicate nor change policy after
evaluation starts. This decision selects no concrete use-case predicate or
threshold.

Separate profile registration, synthetic contract-fixture execution, candidate
execution, and production execution. Current profiles permit registration and
offline contract fixtures only. SecretFlow and Nitro candidate execution both
remain unauthorized without separate reviewed grants; production execution is
unsupported.

Publish an implementation-independent Product handoff whose fields define
meaning, requirement, source, expected port behavior, fail-closed rule, and
prohibited content. It contains no private Product class or path. Pin the
Research authority as an offline closed snapshot; validators never access
GitHub, vendors, AWS, or private repositories at runtime.

No profile is production eligible. No SecretFlow, CIRCL, or Nitro candidate was
executed. AWS execution is not authorized. Future Evidence may supersede these
profiles after a new reviewed decision.

Every valid PET catalog case is executed through the shared authoritative
stage-aware operation validator and produces a digest-bound result manifest.
Inputs bind the selected stage and, only for result acceptance, the separate
observer digest. One callback
case also passes a canonical `result_acceptance_notice` through the existing
message validator before PET-specific authority validation.

## Alternatives considered

- **Complete profile versus component-only:** treating every crypto primitive as
  an engine is simpler but invents set/session/result semantics. VOPRF remains
  component-only.
- **PSI versus TEE trust models:** collapsing them into one generic security
  claim hides semi-honest versus hardware/attestation assumptions. Profiles keep
  distinct models.
- **Upstream-native output versus Protocol minimum result:** native rows aid
  debugging but violate minimum disclosure. A wrapper is mandatory.
- **Implementation selection versus experimental contract:** selecting a vendor
  now exceeds the available Evidence. Contracts are experimental only.
- **Symmetric wrapper versus upstream result ownership:** the existing Protocol
  requires both Parties to accept one receipt-bound result; upstream ownership
  cannot bypass it.
- **Key verification versus hardware attestation:** the mechanisms are not
  interchangeable. Each profile declares exact responsibilities.
- **Public profile versus private adapter:** public semantics are reviewable;
  implementation details remain private and conform to the handoff.
- **Actual execution versus contract-only fixtures:** execution would add tool,
  network, and cost authority. Deterministic synthetic fixtures are used here.
- **Production approval versus experimental eligibility:** test success is not
  production approval. `production_eligible` remains false.

## Consequences

Product can design a decision-engine port without adding new public outcome,
receipt, leakage, or failure semantics. The closed validators reject profile,
version, instance, attempt, receipt, transcript, verification-material,
security-model, leakage, and execution-authority substitutions. Deterministic
projections improve reviewability but do not establish cryptographic security,
performance, candidate behavior, input truthfulness, production suitability, or
operational approval.

Conformance success establishes only deterministic contract handling. It does
not establish candidate execution, cryptographic security, policy correctness,
input completeness, performance, or production eligibility.

## Compatibility and rollback

These are new experimental Draft v0.1 artifacts and do not modify existing
State Machine or Message schemas. Consumers must reject unknown versions and
component-only engine selection. Rollback removes the new registry/profiles and
handoff as a unit; it must not silently fall back to an unregistered adapter.
