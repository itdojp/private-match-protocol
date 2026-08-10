# Experimental PET integration profile comparison

> Generated deterministically from validated public contract artifacts. Do not edit.

| Profile | Class | Technology | Security model | Trust model | Fixture | Candidate | Production |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `private-match-experimental-nitro-enclave/0.2` | complete-decision-profile | trusted-execution-environment | hardware-attested-trusted-execution-environment | nitro-hardware-attestation-and-enclave-code | contract-only | no | no |
| `private-match-experimental-secretflow-kkrt/0.2` | complete-decision-profile | psi | semi-honest | two-party-semi-honest-psi-with-public-wrapper | contract-only | no | no |
| `private-match-experimental-voprf-component/0.2` | component-only | voprf-component | rfc9497-voprf-component | component-only-cryptographic-primitive | contract-only | no | no |

SecretFlow KKRT and Nitro Enclaves are materially different experimental complete-decision contracts.
RFC 9497/CIRCL VOPRF is component-only and cannot be selected as the complete matching engine.
No candidate was executed and no production PET architecture was selected.
Profile registration and contract-fixture validation are not candidate execution permission.
