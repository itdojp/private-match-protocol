<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Private Match Core Conformance Suite v0.1

Status: **Draft**. Profile: `private-match-core/v0.1`.

## Claim boundary

The suite determines whether a reported behavior matches one fixed synthetic case. It does not
establish cryptographic security, production authentication, PET security, deployment safety,
vendor certification, interoperability certification, or Product behavior. All inputs are public
synthetic fixtures. No private Product repository or private Evidence is a runtime dependency.

The suite is pinned to Protocol source revision
`2c314027f61ca0f0edbe2dcc55a8305710efd91d`, State Machine digest
`sha256:42e63b8a1f413e932e46370aae5fa0d972f3ab71d93efe08557472b4c7066fe8`, and message
registry digest `sha256:2ff1685ca4325a0ff3bd49c7a411cd7f0857add6215c2f285097bdf40dcbc2b6`.
These bindings identify reviewed inputs; they do not prove correctness or privacy.

## Artifact structure and authority

`conformance/suites/private-match-core-v0.1/suite-manifest.v0.1.json` is the generated index.
Each case has a stable ID, vector class, domain-separated case/input digests, initial abstract
state, ordered inputs, authentication precondition, expected Protocol outcome, expected state and
transcript digests, mutation assertions, timeout, limitations, and SPDX-compatible provenance.
The input digest covers the digest of every referenced trace, raw/message/timer fixture, initial
context, and verification-material fixture; paths alone are never treated as content bindings.
`conformance/source/case-definitions.v0.1.json` and
`conformance/source/normative-expected-results.v0.1.json` are the human-reviewed normative sources.
The generator canonicalizes and binds those sources; it does not import or call the reference
executor, recompute an oracle from actual behavior, or provide an update-golden mode. The generator
owns the manifest, case files, expected-results projection, fixed fixtures, and offline adapter
fixture. `scripts/generate_conformance_suite.py --check` rejects stale output without rewriting the
normative oracle.

`conformance/source/message-conformance-inputs.v0.1.json` closes all 74 pre-Issue-6 Message inputs.
Every relative path and file SHA-256 is checked, then the reviewed Issue #5 length-prefixed
path/byte tree digest is recomputed. Adding, removing, renaming, changing, or symlinking an input
fails closed; the pin is not accepted by constant comparison alone.

There are 68 vector classes and 68 cases: 58 Protocol-executable cases, six concrete policy
projections, and four explicit runner self-tests. The 64 Issue-required classes are covered only by
executable Protocol inputs or concrete inputs to the shared policy validators, never by a case-
supplied verdict. Required categories cover valid traces; strict JSON/JCS; digest
and transcript tampering; context binding; replay/order/time; result/receipt; verification
material; consent/disclosure; and Leakage Contract prohibitions. The manifest is the complete
machine-readable class catalog.

## Result semantics

Runner status and Protocol outcome are independent:

| Runner status | Meaning |
| --- | --- |
| `pass` | Actual behavior equals the case expectation, including an expected rejection. |
| `fail` | Verification ran but actual behavior differs from the expectation. |
| `skip` | A reviewed condition explicitly prevented execution. |
| `unsupported` | The adapter/authentication profile lacks the requested capability. |
| `timeout` | The reviewed bound was exceeded. |
| `tool-error` | Fixture, verifier, or adapter-result processing failed. |

`protocol_outcome` is separately one of `accepted`, `rejected`, `no-op`, `terminal`, or
`not-evaluated`. A negative vector rejected as expected therefore has status `pass` and Protocol
outcome `rejected`. Status conversion is forbidden: in particular `skip`/`unsupported` do not
become `pass`, and `timeout`/`tool-error` do not become `fail`.

The case cannot select a status. Unsupported is derived by the authentication-precondition
evaluator, timeout by a deterministic operation budget, tool error by a closed runner-self-test
processing fault, skip by a reviewed planned-adapter condition, and fail only by comparison with the
independent normative oracle.

## Atomicity and privacy observations

Messages and timers are applied to candidate copies through the reviewed
`apply_trace_message_atomically()` and `apply_trace_timer_atomically()` helpers. A rejected input
must not partially change State Machine state, transcript, query budget, or audit lifecycle.
Exact accepted duplicates are transcript no-ops. Conflicts are rejected without mutation.

The MATCH, NO_MATCH, and INDETERMINATE cases use three distinct test-only profile-local result
fixtures. Each binds profile/session/attempt/receipt and produces a distinct Party-local accepted
result state and final state digest while retaining bilateral symmetry. These fixtures are neither
wire messages nor new Protocol events and set `cryptographic_validity: not-evaluated`.
Coordinator-visible core messages contain no plaintext `MATCH`, `NO_MATCH`, or `INDETERMINATE`, private input, exact
count, matching element, identity reveal, or actual disclosure payload. The suite never uses a bare
hash over the three result values as an opaque receipt.

## Authentication boundary

`fixture-preverified/v0.1` is a test-only precondition adapter. It binds a synthetic message and
reviewed synthetic material to the suite but sets `cryptographic_validity: not-evaluated`. It is
not a signature, MAC, attestation algorithm, or production profile. Structural algorithm/material,
subject, time, audience, session, policy, and profile checks still run. An unknown real algorithm
returns `unsupported`, never a fabricated `pass` or `fail`.
