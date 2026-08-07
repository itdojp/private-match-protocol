<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# SecretFlow KKRT experimental complete-decision profile v0.1

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

The wrapper, Party-local preparation/result verification, and the Protocol
State Machine are trusted to enforce minimum disclosure. Broad host privilege,
host-network configuration, process/container metadata, peer endpoints, and
message-size/timing classes remain explicit experimental leakage and
operational limitations.

## Protocol binding

Contributions bind session, participants, policy, profile ID/version/instance,
commitment pair, evaluation attempt, transcript head, input commitments, and
resource policy. A callback must match those authorities and one opaque receipt.
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
