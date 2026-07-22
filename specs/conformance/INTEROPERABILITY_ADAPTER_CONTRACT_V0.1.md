<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Interoperability Adapter Result Contract v0.1

Status: **Draft**.

An independent implementation is never launched by the reference verifier. It produces one closed,
versioned JSON result offline. `compare_adapter_result.py` strictly validates that artifact and
compares its suite ID/version/digest, case ID/digest/input digest, unchanged six-state status,
Protocol outcome, ordered errors, canonical initial/final state-projection digests, initial/final
transcript heads, accepted-event count, state/transcript/budget/audit mutation flags, cached-response
authorization, limitations boundary, artifact status, and adapter mode with the fixed expectation. The contract has no executable
path, shell command, network endpoint, credential, customer field, or transport definition.

Adapter-result input uses the same repository-relative, non-symlink, regular-file, size, UTF-8, strict
JSON, and RFC 8785 boundary as suite input. Comparison requires an explicit `normal` or `test-fixture`
mode. Normal mode rejects the synthetic adapter identity; test-fixture mode requires it.

The committed adapter result is explicitly `test-only`; it demonstrates deterministic comparison,
not independence. `conformance/interop/adapters.v0.1.yaml` records one public-only second adapter as
`planned`. Its implementation language/runtime remain human decisions. It must not import or copy
the Python reference implementation, must review its canonicalization dependency/license, and must
cover every manifest vector class before any interoperability claim is reviewed.

The adapter result can supply digest-bound metadata to a future private Assurance Evidence producer:
source revision, suite/case, implementation, input/result, status, and limitations. The Protocol
repository neither invokes the Assurance exporter nor publishes Evidence. Publication approval is
outside this contract.
