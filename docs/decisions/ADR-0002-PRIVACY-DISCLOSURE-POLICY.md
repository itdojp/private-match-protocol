# ADR-0002: Draft v0.1 privacy disclosure policy

- Status: Accepted for draft v0.1
- Decision owner: ITDO Inc.
- Decision date: 2026-07-19
- Review date: 2026-10-18

## Context

Issue #3 requires a minimum disclosure contract before a PET integration profile is selected.
Without a recorded decision, exact counts, matching elements, asymmetric results, replay, or
adaptive queries could create unintended disclosure or membership-oracle behavior.

This ADR records the existing draft contract. It does not approve a production PET, mark the
protocol stable, or claim that an implementation satisfies the contract.

## Decision

- The only decision values are `MATCH`, `NO_MATCH`, and `INDETERMINATE`, delivered
  symmetrically to both participants.
- Exact intersection count, matching or non-matching elements, identity or attribute reveal,
  and party-specific results are prohibited in the core profile.
- The coordinator is authoritative for session, replay, query-budget, and audit state, while
  coordinator outcome confidentiality remains an unresolved target requiring evidence.
- Reuse of a commitment pair is prohibited; a new evaluation requires a new session or explicit
  retry transition, new query-budget authorization, and participant/policy rebinding.
- The core protocol does not prove that participant inputs are truthful, complete, current, or
  authorized.
- PET-specific security and coordinator/participant collusion protection remain unresolved until
  a versioned integration profile selects and justifies a security model.

## Options considered

1. Decision-only, symmetric disclosure with authoritative replay/query controls.
2. Return exact counts or matching elements.
3. Permit identity reveal or party-specific results.
4. Rely on client-side counters or unrestricted repeated queries.
5. Select PET-specific leakage and collusion claims in this core contract.

Option 1 was selected for draft v0.1. Options 2 through 4 were rejected because they increase
direct or adaptive inference. Option 5 was deferred because no PET integration profile has been
selected or evidenced.

## Security and privacy assumptions

- Each client protects its own raw input and local secret material before protocol preparation.
- Participants may omit, fabricate, or selectively submit inputs and may attempt adaptive or
  colluding queries.
- A boolean result can still become a membership oracle without authoritative query, minimum-set,
  and organizational controls.
- Transport security, endpoint security, side-channel resistance, malicious-party security, and
  coordinator outcome confidentiality are not established by this decision.
- Input authenticity and completeness require external controls that are not selected here.

## Evidence

- `privacy/leakage-contract.v0.1.yaml` and its JSON Schema.
- `docs/PRIVACY_LEAKAGE_CONTRACT.md` and
  `specs/ACTORS_AND_TRUST_BOUNDARIES.md`.
- Validator and positive/negative regression tests for prohibited disclosure and unresolved
  boundaries.
- Pull-request CI establishes structural consistency only; implementation conformance and PET
  security evidence do not yet exist.

## Rejected alternatives

- Exact count, matching-element, identity-reveal, and asymmetric-output variants were rejected
  for the core profile.
- Client-only replay counters and unlimited predicate queries were rejected as insufficient.
- Treating incomplete participant data as a protocol failure was rejected because the core
  protocol cannot establish dataset truth or completeness.
- Claiming a selected PET or collusion threshold was rejected because those decisions and their
  evidence remain unavailable.

## Compatibility impact

The artifact remains draft `private-match-core/v0.1`. Weakening disclosure, replay, or
verification requirements is a breaking change under `GOVERNANCE.md` and requires a new protocol
version and review. This ADR creates no production compatibility commitment.
