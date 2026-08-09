<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# SecretFlow KKRT experimental complete-decision profile v0.2

Version 0.2 binds this experimental profile to the complete PET contract v0.2
graph, including acknowledgment-substate-aware abort authority. Version 0.1 remains
a byte-preserved rollback graph and does not infer these semantics.

The profile pins `secretflow/psi` commit
`d7682707035d6b3e04cc09b8bfef629140641432` and the initial upstream protocol
`PROTOCOL_KKRT`. It is an experimental complete-decision contract, not an
execution result or a production selection.

## Security and trust model

The reviewed security model is **semi-honest**. Malicious-party security,
participant input completeness, endpoint correctness, and resistance to all
side channels are not established. A future experimental wrapper must keep
upstream rows or intersection representations inside its boundary and expose
only symmetric Party-local minimum results.

Those Party-local decisions do not cross the public callback or Coordinator
boundary. The canonical callback carries the common opaque receipt, normalized
acknowledgment, Evidence reference, and reviewed authority bindings. Bilateral
plaintext decisions exist only in the synthetic global-observer surface used
by offline contract conformance.

The wrapper, Party-local preparation/result verification, and the Protocol
State Machine are trusted to enforce minimum disclosure. Broad host privilege,
host-network configuration, process/container metadata, peer endpoints, and
message-size/timing classes remain explicit experimental leakage and
operational limitations.

## Protocol binding

Contributions bind session, participants, policy, profile ID/version/instance,
commitment pair, evaluation attempt, transcript head, input commitments, and
resource policy. A callback must match those authorities and one opaque receipt.
It also repeats the exact resource-policy and execution-authorization digests
bound at evaluation start. Receipt acknowledgment is unavailable until both
Party contributions are complete.
The Coordinator may record the receipt reference and normalized lifecycle only;
it must not observe the plaintext outcome.

The Protocol query budget is reserved before evaluation and consumed once by
`start_evaluation`. SecretFlow is not authoritative for replay, retries,
query-budget consumption, cancellation, or cleanup. Missing verification
material, timeout, resource exhaustion, result conflict, or unrecognized
failure mapping fails closed.

No SecretFlow binary, container, or network operation is invoked by this
profile or its tests.

## Decision and execution authority

The profile derives no implicit match predicate. An exact externally reviewed
Protocol policy ID/version must be fixed before evaluation and remain identical
across contributions, the opaque receipt, the canonical profile callback, and
the transcript context. Unknown, changed, or profile-defaulted policy fails
closed.

Registration and `contract-fixture` validation are allowed, but candidate
execution is not. A future candidate requires a separately reviewed
`reviewed-local-experiment-execution-grant` bound to the profile ID, version,
digest, instance, source revision, environment, and expiry. Production
execution remains unsupported.

Every exchange step is checked against the operation-stage authority. Profile
selection, budget reservation, evaluation start, contribution, acknowledgment,
and callback therefore carry only the state available at that exact Protocol
stage; no early step fabricates a later attempt, receipt, or result.
