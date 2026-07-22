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

Human-reviewed case definitions and normative expected results are the single oracle authority.
Generated suite artifacts are deterministic projections and are checked byte-for-byte; the generator
does not execute the reference verifier or update the oracle. Concrete executable fixtures replace
case-supplied semantic verdicts. The three result variants use protected, test-only profile-local
fixtures rather than adding plaintext outcomes to Coordinator-visible core messages.

JSON Schema closes fields and versions; semantic validation closes digests, references, class
coverage, Protocol pins, expectations, and fixture-adapter binding. The complete 74-file pre-Issue-6
Message input tree is listed and recomputed with the reviewed Issue #5 length-prefixed calculation.
Logical state comparison uses a closed versioned RFC 8785 projection, not `runner.__dict__`, and keeps
transcript bindings separate. A closed implementation manifest binds the transitive Python import
closure, explicitly loaded Schemas/policies/profiles, and dependency locks. A suite-tree manifest
binds the exact generated path set, and both generator check and repository validation reject stale
extras. Offline adapter input uses the shared safe-path boundary and every declared evidence surface
is compared under an explicit normal/test-fixture mode. Runner statuses are derived from actual
evaluator/budget/comparison/fault behavior. All message and
timer failures are candidate-copy atomic, and all-case output is staged, re-read as an exact run set,
fsynced, and directory-renamed atomically.

## Alternatives

- **Monolithic end-to-end vector files:** simpler initially, but weak stable identity and provenance.
- **Launch adapter subprocesses:** convenient, but creates command/path/network trust surfaces and
  nondeterminism; rejected.
- **Treat a placeholder signature as valid cryptography:** would make a false security claim; rejected.
- **Combine status and Protocol acceptance:** collapses negative-vector success and unavailable states;
  rejected.
- **Add execution timestamps:** useful for Evidence but destroys deterministic Protocol results; defer
  to a separate private Evidence envelope.
- **Generate expected results from reference execution:** convenient golden-file maintenance, but it
  makes the implementation under test its own oracle and hides regressions; rejected.
- **Case-supplied probes or forced statuses:** compact but tautological and unable to demonstrate real
  state, replay, timer, or policy behavior; rejected.
- **Write each `--all` result directly:** simple but exposes partial/stale sets after late failure;
  rejected in favor of one transactional run-set commit.
- **Digest `runner.__dict__`:** convenient but Python-specific and polluted by caches/transcript; rejected
  in favor of a closed logical projection.
- **Bind only direct verifier scripts:** smaller but omits transitive validators, Schemas, and locks;
  rejected in favor of a closed implementation manifest.
- **Allow unlisted generated files:** preserves local scratch output but lets stale cases appear
  authoritative; rejected in favor of an exact suite tree.
- **Require a second implementation in this PR:** would expand ownership and risk falsely claiming
  independence; retain a closed planned-adapter contract.

## Consequences

The suite is reproducible, reviewable, and suitable as input metadata for private Evidence. It adds no
runtime dependency and changes no `private-match-core/v0.1` message or State Machine semantics. It is
Draft and intentionally cannot establish cryptographic security, interoperability certification,
Product conformance, pilot readiness, deployment safety, or publication approval.
