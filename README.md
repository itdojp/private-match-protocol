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

## Maturity

The repository is in pre-specification bootstrap. No protocol is production ready, no cryptographic security claim has been established, and no compatibility commitment exists yet.

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

A public license will be selected before publishing executable reference components. Until then, repository content should be treated as specification drafts owned by ITDO Inc.; no additional license is granted by this README.
