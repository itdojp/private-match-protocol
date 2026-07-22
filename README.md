# Private Match Protocol

Public specification and conformance repository for the Private Match project.

Private Match is intended to let two parties evaluate a narrowly defined relationship between private inputs while disclosing only an agreed result. The repository defines what the protocol claims, what it leaks, which assumptions it depends on, and how independent implementations are tested.

## Repository role

This repository is the public system of record for:

- protocol state machines and message schemas
- privacy and metadata leakage contracts
- disclosure and consent rules
- replay, expiry, session, and commitment semantics
- reference client and verifier components approved for publication
- test vectors and conformance suites
- formal specifications and model-checking inputs
- public assurance claims related to the protocol

## Not contained here

The following belong in private repositories:

- production coordinator implementation
- customer-specific integrations and policies
- commercial UI, billing, and tenant administration
- infrastructure and key-management configuration
- abuse-detection thresholds
- customer data and interview material
- unpublished inventions and patent candidates
- unresolved vulnerability details

## Related repositories

- `itdojp/private-match-research` — public market, use-case, and technology research
- `itdojp/private-match-product` — private commercial product implementation
- `itdojp/private-match-strategy` — private business, IP, legal, and publication decisions
- `itdojp/private-match-assurance` — public release evidence and assurance reports
- `itdojp/ae-framework` — assurance control plane used to organize evidence and policy gates

## Current draft artifacts

- [Actors and trust boundaries](specs/ACTORS_AND_TRUST_BOUNDARIES.md)
- [Privacy Leakage Contract](docs/PRIVACY_LEAKAGE_CONTRACT.md) and its
  [machine-readable artifact](privacy/leakage-contract.v0.1.yaml)
- [Core session and disclosure state machine](specs/state-machines/private-match-core-session-v0.1.md)
  and its
  [machine-readable artifact](specs/state-machines/private-match-core-session-v0.1.yaml)
- [Core versioned message contract](specs/messages/private-match-core-messages-v0.1.md),
  [message registry](registry/message-types.v0.1.yaml), and
  [canonical transcript contract](specs/messages/canonical-transcript-v0.1.md)
- [Draft core conformance suite](specs/conformance/PRIVATE_MATCH_CORE_CONFORMANCE_V0.1.md),
  [reference verifier contract](specs/conformance/REFERENCE_VERIFIER_CONTRACT_V0.1.md),
  [canonical conformance-state projection](specs/conformance/CONFORMANCE_STATE_PROJECTION_V0.1.md), and
  [offline adapter-result contract](specs/conformance/INTEROPERABILITY_ADAPTER_CONTRACT_V0.1.md)

## Maturity

The repository contains draft protocol artifacts. No artifact is `candidate` or
`stable`, no production protocol or PET has been selected, no cryptographic
security claim has been established, and no compatibility commitment exists yet.

## Initial design principles

1. Minimize output before optimizing performance.
2. Separate facts, protocol assumptions, security claims, and business claims.
3. Treat repeated-query leakage as a protocol property.
4. Bind all accepted messages to a versioned session and participant context.
5. Fail closed when verification material or protocol state is missing.
6. Do not use test proofs or silent fallback in production paths.
7. Prefer reviewed protocols and libraries over novel cryptographic construction.
8. Publish known limitations and non-goals with each version.

## License

Repository content uses an explicit dual-license structure:

- Narrative protocol documentation, research text, tables, and diagrams are licensed under
  [Creative Commons Attribution 4.0 International](LICENSES/CC-BY-4.0.txt).
- Executable or reference code, Python and TypeScript code, JSON Schemas, validators, tests,
  fixtures, conformance vectors, GitHub Actions, and related build inputs are licensed under
  the [Apache License 2.0](LICENSES/Apache-2.0.txt).

[`REUSE.toml`](REUSE.toml) provides the machine-readable SPDX file mapping and takes
precedence over this summary for individual files. Patent-sensitive implementation material
and trade-secret candidates remain private or embargoed until human IP and publication
approval; these licenses do not indicate that such material has been published here.

The explicit human approval, scope, alternatives, and publication boundary for this decision
are recorded in [ADR-0001](docs/decisions/ADR-0001-PUBLIC-LICENSING.md).
