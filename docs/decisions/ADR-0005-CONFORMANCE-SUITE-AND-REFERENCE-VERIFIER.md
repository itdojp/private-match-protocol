<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# ADR-0005: Conformance suite and reference verifier

- Status: Proposed
- Date: 2026-07-22

## Context

Issue #6 requires stable fixed vectors and a machine-readable result that independent implementations
can reproduce without turning the Protocol repository into a production implementation or executable
adapter host.

## Decision

Use versioned suite/case/expected-result manifests instead of monolithic prose or an array whose order
defines identity. Use a deterministic reference execution that composes the existing Message/State
Machine helpers. Compare independent adapter JSON offline; never execute an arbitrary adapter. Keep
runner status distinct from Protocol outcome. Use the explicit test-only
`fixture-preverified/v0.1` precondition rather than fake cryptography. Omit runtime timestamps and
host metadata. Record a second independent public adapter as planned rather than claiming it exists.

Generated suite artifacts are generator-owned and checked byte-for-byte. JSON Schema closes fields and
versions; semantic validation closes digests, references, class coverage, Protocol pins, expectations,
and fixture-adapter binding. All failures are candidate-copy atomic.

## Alternatives

- **Monolithic end-to-end vector files:** simpler initially, but weak stable identity and provenance.
- **Launch adapter subprocesses:** convenient, but creates command/path/network trust surfaces and
  nondeterminism; rejected.
- **Treat a placeholder signature as valid cryptography:** would make a false security claim; rejected.
- **Combine status and Protocol acceptance:** collapses negative-vector success and unavailable states;
  rejected.
- **Add execution timestamps:** useful for Evidence but destroys deterministic Protocol results; defer
  to a separate private Evidence envelope.
- **Require a second implementation in this PR:** would expand ownership and risk falsely claiming
  independence; retain a closed planned-adapter contract.

## Consequences

The suite is reproducible, reviewable, and suitable as input metadata for private Evidence. It adds no
runtime dependency and changes no `private-match-core/v0.1` message or State Machine semantics. It is
Draft and intentionally cannot establish cryptographic security, interoperability certification,
Product conformance, pilot readiness, deployment safety, or publication approval.
