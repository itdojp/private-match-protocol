<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# AWS Nitro Enclaves experimental complete-decision profile v0.1

The profile pins AWS Nitro CLI `v1.4.5` and AWS NSM API `v0.5.2`. It defines a
hardware/attestation trust model for a future synthetic reproduction experiment.
It does not authorize an AWS API call or create an AWS resource.

## Required attestation boundary

A future experiment must use non-debug mode and validate the AWS Nitro
attestation chain, a fresh verifier nonce, the expected PCR policy, and the
exact enclave image/source/artifact digest. Debug-mode attestation, stale or
missing nonce, mismatched PCR policy, missing artifact binding, or unapproved
execution fails closed.

The opaque receipt binds the attestation-document digest, nonce, PCR policy,
enclave artifact digest, session, profile, evaluation attempt, transcript,
commitments, and resource policy. The enclave exposes only symmetric Party-local
`MATCH`, `NO_MATCH`, or `INDETERMINATE`; it cannot expose an exact count or
matching rows, and the Coordinator cannot receive the plaintext result.

## Limitations and approval

AWS hardware and attestation are trusted components. Input completeness,
endpoint correctness, and side-channel resistance are not established. Account,
region, instance, vsock/network/artifact metadata, cost, retention, and teardown
must remain visible and require separate human approval. Execution authorization
is `human-required-not-provided`; only synthetic input would be eligible for a
future experiment.

Registration and deterministic `contract-fixture` validation are not AWS
execution permission. Candidate execution is false and requires a separately
reviewed `reviewed-paid-aws-experiment-execution-grant`; missing authority is
`unsupported`. Production execution is unsupported. The profile also requires
an exact Protocol policy binding and cannot select or change a match predicate.
