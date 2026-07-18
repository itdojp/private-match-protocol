# Protocol Roadmap

## P0 — Repository baseline

- repository governance and agent rules
- artifact status and versioning policy
- issue-driven workflow
- public/private boundary
- initial assurance handoff contract

Exit criteria:

- bootstrap PR reviewed and merged
- initial protocol Epic exists
- no production-security claim is made

## P1 — Decision-only matching protocol draft

Define one bounded two-party flow for a result such as:

```text
MATCH | NO_MATCH | INDETERMINATE
```

Required specifications:

- actors and trust boundaries
- session lifecycle
- participant and policy binding
- commitment lifecycle
- result symmetry
- expiry and replay behavior
- consent and optional reveal
- error and abort semantics
- privacy leakage contract

Exit criteria:

- protocol draft is `candidate`
- public and private inputs are explicit
- exact output and metadata are explicit
- repeated-query assumptions are explicit

## P2 — Message schemas and conformance

- canonical message schemas
- positive and negative test vectors
- tamper, replay, expiry, and cross-session tests
- reference verifier
- compatibility rules
- implementation-independent conformance runner

Exit criteria:

- at least two independent implementations or adapters can run the vectors
- conformance failures are reproducible
- conformance claims are scoped to named versions

## P3 — Formal protocol model

- TLA+ state machine for session, commitment, evaluation, consent, reveal, expiry, and abort
- invariants for reveal safety, result symmetry, commitment immutability, session binding, and no replay
- bounded model-checking configuration and reports

Exit criteria:

- model and configuration are reviewed
- tool failures fail the verification lane
- public reports state bounds and assumptions

## P4 — PET integration profile

After the research repository completes a technology bakeoff:

- define adapter requirements for selected PSI, OPRF/VOPRF, MPC, or TEE approaches
- bind technology outputs to the protocol transcript
- define malicious-input, input-completeness, and repeated-query controls
- define key and attestation responsibilities

Exit criteria:

- selected integration is experimental, not production ready
- residual leakage and security model are published
- rejected alternatives and decision expiry are documented

## P5 — Stable profile candidate

- external review
- performance and operational limits
- version migration plan
- stable conformance suite
- signed assurance evidence
- known limitations and withdrawal procedure

Promotion to `stable` requires an explicit human decision and does not follow automatically from test success.
