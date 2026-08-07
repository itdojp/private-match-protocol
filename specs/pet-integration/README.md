<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Experimental PET integration profiles

This directory defines the public, implementation-independent P4 boundary between
`private-match-core/0.1` and experimental PET adapters. The authority is the
reviewed Research snapshot at commit
`45607b57d61de5ff2d46a092dc24f6beb50dfe7c`; its candidate status remains
`not-run` and its production selection remains `not-selected`.

The registry contains two materially different complete-decision contracts:

- [SecretFlow KKRT PSI](secretflow-kkrt-v0.1.md), using a semi-honest PSI model;
- [AWS Nitro Enclaves](nitro-enclave-v0.1.md), using hardware attestation and a
  reviewed enclave-artifact policy.

The [RFC 9497/CIRCL VOPRF profile](voprf-component-v0.1.md) is component-only.
It cannot be selected as `selected_integration_profile`, does not define set or
session semantics, and cannot emit the Protocol result.

The profiles do not duplicate the State Machine. The
[machine-readable binding](protocol-binding.v0.1.yaml) references exact State
Machine and Message Registry semantic digests and maps profile operations to
existing events, messages, transitions, guards, effects, transcript behavior,
and replay/idempotency domains.

`result_acceptance_notice` is the only externally presented profile-callback
operation. `accept_symmetric_result` remains its existing State Machine effect;
it is not a second Product-port operation. The binding validator compares the
complete message version, delivery class, direction, sender, verifier, audience,
event, transition set, transcript behavior, and replay domain with the live
Message Registry and State Machine.

## Minimum result and private boundary

Every complete profile exposes only `MATCH`, `NO_MATCH`, or `INDETERMINATE` as
symmetric Party-local results bound to one high-entropy opaque receipt. Exact
counts, matching or non-matching rows, raw identifiers, participant identities,
private inputs, and Coordinator-visible plaintext results are prohibited.
Repeated-query controls and query-budget authority remain Protocol/Product
responsibilities rather than upstream PET responsibilities.

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
- Profile registry: `registry/pet-integration-profiles.v0.1.yaml`
- Product handoff: `handoff/product-decision-engine-port.v0.1.yaml`
- Conformance cases: `conformance/pet-profiles/case-catalog.v0.1.json`
- Closed operation input: `schema/pet-profile-operation-input.v0.1.schema.json`
- Executed case results:
  `generated/pet-integration/executable-case-results.v0.1.json`
- Generated comparison/index/handoff projection/digest manifest:
  `generated/pet-integration/`

Run `python scripts/validate_pet_profiles.py --root .` to validate the complete
closed authority, or `python scripts/generate_pet_profiles.py --root . --check`
to check deterministic projections. Neither command executes a candidate or
uses a network service.

Every catalogued valid case is converted into a complete authoritative context
and presented operation, executed through the same semantic validator used by
negative cases, and bound by input/result digests. This proves contract handling
only; it does not prove PET security, policy correctness, or candidate behavior.
