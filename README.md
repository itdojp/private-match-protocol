# Private Match Protocol

Public protocol specifications, privacy contracts, and deterministic conformance
tests for Private Match. Maintained by ITDO Inc.

Private Match explores how two parties can evaluate a narrowly defined
relationship between private inputs, disclose only an agreed result, and permit
further disclosure only through explicit policy and consent. This repository
defines the public contract; it is not the commercial service implementation.

> **Status: draft specifications and experimental PET contracts.** No artifact
> is candidate or stable. No production PET has been selected, and no PET
> candidate has been executed. Contract-validation success does not establish
> cryptographic security, input completeness, deployment security, legal
> compliance, or production readiness.

## Start here

| Goal | Read |
| --- | --- |
| Understand actors, outputs, and leakage | [Actors and trust boundaries](specs/ACTORS_AND_TRUST_BOUNDARIES.md) · [Privacy Leakage Contract](docs/PRIVACY_LEAKAGE_CONTRACT.md) |
| Implement session lifecycle and consent | [Core State Machine](specs/state-machines/private-match-core-session-v0.1.md) |
| Validate messages and transcripts | [Message contract](specs/messages/private-match-core-messages-v0.1.md) · [Canonical transcript](specs/messages/canonical-transcript-v0.1.md) |
| Run or integrate conformance checks | [Core conformance suite](specs/conformance/PRIVATE_MATCH_CORE_CONFORMANCE_V0.1.md) · [Reference verifier](specs/conformance/REFERENCE_VERIFIER_CONTRACT_V0.1.md) |
| Consume experimental PET contracts | [PET integration guide](specs/pet-integration/README.md) · [Product handoff](handoff/product-decision-engine-port.v0.3.yaml) |
| Review change and compatibility rules | [Governance](GOVERNANCE.md) · [Roadmap](ROADMAP.md) |

## What is available

- Machine-readable actor, leakage, session, consent, disclosure, replay, expiry,
  commitment, message, and transcript contracts.
- Canonical message vectors, a Draft core conformance suite, an offline
  reference verifier, and [adapter-result
  comparison](specs/conformance/INTEROPERABILITY_ADAPTER_CONTRACT_V0.1.md).
- Experimental PET profiles, lifecycle-stage-aware operation contracts, positive
  and negative fixtures, and deterministic generated projections.

The core profile remains `private-match-core/0.1`. The current **PET wrapper
graph is v0.3**, with exact byte-preserved **v0.2 profile contracts** as
explicit dependencies:

| Profile | Contract class | Execution status |
| --- | --- | --- |
| SecretFlow KKRT | Experimental complete-decision profile | Contract fixtures only; candidate not run |
| Nitro Enclaves | Experimental complete-decision profile | Contract fixtures only; candidate not run |
| RFC 9497 / CIRCL VOPRF | Component-only profile | Not a complete decision engine |

The v0.3 wrapper uses path-aware result confidentiality and binds acknowledgment
Evidence to the exact profile digest. Party-local plaintext decisions do not
enter public callbacks, Product-port projections, or Evidence. A separate
synthetic observer exists only for offline conformance.

Published v0.1/v0.2 graphs remain historical fixed-byte authorities; do not mix
them or infer newer behavior from an older version. Select the complete current
graph through the [compatibility
map](config/pet-contract-compatibility.v0.3.json),
[registry](registry/pet-integration-profiles.v0.3.yaml), and [Protocol
binding](specs/pet-integration/protocol-binding.v0.3.yaml). See the [v0.3
correction notice](specs/pet-integration/PET-CONTRACT-CORRECTION-v0.3.md). These
preservation rules do not promote an artifact to stable or establish a
production compatibility commitment.

## Local validation

The CI target is Ubuntu 24.04 with **CPython 3.12.11**. From the repository
root, use that runtime and install the hash-locked build and development
dependencies:

```bash
python3.12 -m venv .venv
. .venv/bin/activate
python -m pip install --require-hashes -r requirements-build.txt
python -m pip install --require-hashes --no-build-isolation -r requirements-dev.txt
python -m unittest discover -s tests -p 'test_*.py'
python -m ruff check scripts tests
python -m ruff format --check scripts tests
python scripts/validate_leakage_contract.py --root .
python scripts/validate_session_state_machine.py --root . --print-digest
python scripts/validate_messages.py --root .
python scripts/generate_message_vectors.py --root . --check
python scripts/generate_pet_profiles.py --root . --check
python scripts/validate_pet_profiles.py --root .
reuse lint
```

Dependency installation fetches packages; the contract validators operate
offline and do not execute SecretFlow, CIRCL/VOPRF, Nitro, or AWS operations.

Run the core reference conformance path separately:

```bash
python scripts/generate_verifier_manifest.py --root . --check
python scripts/generate_conformance_suite.py --root . --check
python scripts/validate_conformance_suite.py --root .
python scripts/run_conformance.py \
  --root . --all --output-dir artifacts/conformance-local
```

`--check` verifies committed generated output rather than refreshing it. Follow
the applicable artifact guide when changing source authority, and compare
independent regenerations before review. The [CI
workflow](.github/workflows/protocol-spec.yml) defines the complete repository
check sequence, including adapter-result comparison.

## Repository layout

| Path | Purpose |
| --- | --- |
| `specs/` | Human-readable and machine-readable Protocol contracts |
| `privacy/` | Leakage authority |
| `schema/` · `schemas/` | Versioned artifact and message Schemas |
| `registry/` · `config/` | Message/profile registries and closed authority maps |
| `handoff/` | Public Product integration requirements |
| `conformance/` | Inputs, cases, vectors, and expected results |
| `scripts/` · `tests/` | Validators, generators, reference execution, and regressions |
| `generated/` | Deterministic projections and manifests |

## Security, contribution, and scope

Work from an Issue and submit a scoped PR; do not redefine published field
meanings or use an unknown version as an implicit fallback. State assumptions,
public/private inputs, outputs, metadata leakage, and limitations before making
a claim. Conformance tests and future formal-model work are not proofs of PET
security.

No production coordinator, customer-specific policy, private source,
infrastructure, key-management configuration, customer data, or unpublished
invention belongs here. Report suspected vulnerabilities through
[SECURITY.md](SECURITY.md), not a public Issue. See [repository
boundaries](docs/REPOSITORY_BOUNDARIES.md) and [AGENTS.md](AGENTS.md).

## Related repositories

| Repository | Role |
| --- | --- |
| [private-match-research](https://github.com/itdojp/private-match-research) | Public market, use-case, substitute, and technology research |
| [private-match-assurance](https://github.com/itdojp/private-match-assurance) | Public assurance contracts, validation tools, and scoped claims |
| `private-match-product` (private) | Commercial implementation and private Evidence |
| `private-match-strategy` (private) | Business, IP, legal, and publication decisions |
| [ae-framework](https://github.com/itdojp/ae-framework) | Evidence organization and policy judgments, not independent certification |

## License

Narrative documentation, tables, and diagrams use
[CC-BY-4.0](LICENSES/CC-BY-4.0.txt). Executable/reference code, Schemas,
validators, tests, fixtures, vectors, workflows, and build inputs use
[Apache-2.0](LICENSES/Apache-2.0.txt). [REUSE.toml](REUSE.toml) is authoritative
for the per-file mapping. See
[ADR-0001](docs/decisions/ADR-0001-PUBLIC-LICENSING.md). Licensing does not
approve publication of private or patent-sensitive material.
