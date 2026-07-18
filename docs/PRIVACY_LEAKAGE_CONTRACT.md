# Privacy Leakage Contract v0.1

## Purpose

Private Match is not designed to make every aspect of a transaction invisible. It is designed to disclose a bounded decision while prohibiting raw input and matching-element disclosure in the core profile.

The machine-readable contract is `privacy/leakage-contract.v0.1.yaml`.

## Minimum result

Both participants may receive exactly one of:

```text
MATCH
NO_MATCH
INDETERMINATE
```

The core receipt must not contain:

- exact intersection count
- matching or non-matching elements
- identity or attribute reveal
- a party-specific result
- detailed failure information that creates a probing oracle

`MATCH` and `NO_MATCH` still leak one bit or a small decision state about the agreed predicate. This is intentional disclosure, not zero leakage.

## What remains local

The initial profile requires these values to stay in the originating client:

- raw identifiers
- normalized identifiers and private attributes
- local salts, randomness, blinding values, and ephemeral private keys

Only a contribution defined by an approved PET profile may cross the client boundary.

## What the counterpart may infer

A party may learn:

- that the other party joined and accepted the policy
- that the other party registered a commitment
- public session and policy metadata
- message size and timing unless a later profile adds padding or traffic shaping
- the final decision state

A participant must not receive the other party's raw data or matching elements.

## What the coordinator may infer

The coordinator may learn:

- organization and participant routing identifiers
- protocol, policy, and message versions
- session ID, timestamps, sequence, nonce, and expiry
- message count and size class
- completion, abort, timeout, and error category
- approved audit fields

The target core profile prohibits coordinator access to the decision result. This requirement must be demonstrated with implementation, packet, log, and protocol evidence before publication as a supported claim.

## Repeated-query leakage

A boolean result can become a membership oracle if a malicious party is allowed to submit carefully chosen datasets repeatedly. Therefore:

- each commitment pair receives at most one accepted result
- replay and idempotency state is authoritative at the coordinator
- new evaluation requires a new authorized budget and binding
- minimum set and intersection rules must be selected before pilot use
- correlated and overlapping sessions require abuse monitoring
- exact count remains prohibited
- unlimited custom predicates are prohibited

Client-side counters and a random nonce alone do not enforce this property.

## Small intersections

A small intersection may identify individuals even when the names are not returned. The final minimum-set and threshold policy is unresolved. Until it is selected and tested, the project must not claim that decision-only output prevents re-identification.

## Input truth and completeness

A cryptographically valid result says nothing about whether either party submitted all relevant records, current records, or truthful records. Candidate controls include source-system manifests, signed attestations, organizational approval, trusted issuers, contractual representation, or independent review.

This limitation is material for conflict checking and M&A overlap. A technically correct computation over incomplete data can produce a misleading business decision.

## Logs and evidence

Allowed operational evidence is limited to identifiers and digests needed to establish protocol version, action, status, timing, and integrity. Raw input, matching elements, local secrets, and plaintext outcomes are prohibited by default.

Public assurance exports contain only reviewed metadata and digests. Private raw evidence remains private.

## Unsupported claims

This draft does not support claims of:

- zero leakage
- complete anonymity
- malicious-party security
- endpoint security
- side-channel resistance
- correct or complete participant data
- legal compliance
- production readiness
- security of an unselected cryptographic or TEE implementation

## Evidence required before stronger claims

At minimum:

- reviewed implementation data-flow diagram
- schema and conformance rejection of prohibited fields
- synthetic packet-capture or egress observation
- log and telemetry inspection
- replay, cross-session, adaptive-query, and small-intersection tests
- selected PET profile security analysis
- build and dependency provenance
- production artifact inspection excluding mocks and fallbacks
- known limitations and reproducibility classification

A passing schema test alone does not establish privacy.
