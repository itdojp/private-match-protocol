<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# PET contract correction v0.3

## Scope

Version 0.3 corrects two Draft PET wrapper-contract defects without changing
the reviewed experimental profile contracts or authorizing candidate execution.

First, public-result confidentiality is evaluated using closed field and JSON
path authority. Result-bearing fields and prohibited public paths fail closed
regardless of their contents. Non-result metadata is not rejected merely
because its schema-valid string value is `MATCH`, `NO_MATCH`, or
`INDETERMINATE`. Those values remain confined to reviewed synthetic-observer
result paths and remain excluded from Protocol messages, Coordinator state,
Product inputs, Evidence hooks, and public audit projections.

Second, acknowledgment Evidence binds the exact `profile_digest`, together with
profile ID, version, instance, session, evaluation attempt, receipt, status, and
Evidence reference. The binding projection uses the new domain separator
`private-match-pet-acknowledgment-evidence/v0.3`. A legacy acknowledgment digest
or a redigested substitution for another profile artifact cannot satisfy the
v0.3 authority.

## Compatibility and supersession

All published v0.1 and v0.2 artifacts remain byte-preserved and digest-checked.
The current selector resolves only the complete v0.3 wrapper graph. The
unchanged profile contracts are explicit exact-byte v0.2 dependencies of that
wrapper; they were not mechanically versioned because their profile semantics
did not change.

Historical selection and rollback are explicit. There is no implicit fallback,
forward inference, partial graph, or cross-version mixing. In particular, v0.2
acknowledgment Evidence is not accepted by v0.3.

## Operational boundary

This correction executes deterministic synthetic contract fixtures only. It
does not execute SecretFlow, CIRCL, VOPRF, Nitro, or AWS; select a Product
adapter, predicate, authentication, key, attestation, cloud, or KMS authority;
promote a profile; or establish PET security or production suitability.
