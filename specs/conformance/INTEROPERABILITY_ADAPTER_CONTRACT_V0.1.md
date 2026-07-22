<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Interoperability Adapter Result Contract v0.1

Status: **Draft**.

An independent implementation is never launched by the reference verifier. It produces one closed,
versioned JSON result offline. `compare_adapter_result.py` strictly validates that artifact and
compares its suite/case digests, unchanged six-state status, Protocol outcome, ordered errors,
state digest, and transcript digest with the fixed expectation. The contract has no executable
path, shell command, network endpoint, credential, customer field, or transport definition.

The committed adapter result is explicitly `test-only`; it demonstrates deterministic comparison,
not independence. `conformance/interop/adapters.v0.1.yaml` records one public-only second adapter as
`planned`. Its implementation language/runtime remain human decisions. It must not import or copy
the Python reference implementation, must review its canonicalization dependency/license, and must
cover every manifest vector class before any interoperability claim is reviewed.

The adapter result can supply digest-bound metadata to a future private Assurance Evidence producer:
source revision, suite/case, implementation, input/result, status, and limitations. The Protocol
repository neither invokes the Assurance exporter nor publishes Evidence. Publication approval is
outside this contract.
