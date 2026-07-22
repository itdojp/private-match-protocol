<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Reference Verifier Contract v0.1

Status: **Draft**.

## Reused semantics

The Python reference verifier composes, rather than reimplements:

1. duplicate-key-rejecting strict JSON and RFC 8785 canonicalization;
2. Message Schema/registry and verification-material validation;
3. payload, message, canonical-wire, timer, and transcript digest functions;
4. `AbstractStateRunner`, sender/operation/callback dedup indexes, and cached-response rules;
5. atomic message/timer application; and
6. the session State Machine validator.

Semantic probes are closed checks for already reviewed cross-artifact assertions, such as Leakage
Contract prohibitions, equality bindings, or receipt construction. They are not a second State
Machine and cannot select a PET, transport, cryptographic algorithm, or disclosure profile.

## Processing order

The verifier performs: safe path resolution; strict parse; case Schema validation; case/suite digest
verification; Protocol pin verification; initial abstract-state construction; ordered input and
authentication-precondition evaluation; message/timer State Machine execution; outcome construction;
expected comparison; deterministic result construction; and final Schema/digest self-validation.
Only a fully validated candidate state and transcript are committed.

## Determinism

The run result is RFC 8785 JSON and binds suite, case, Protocol artifacts, reference implementation,
fixture adapter, input, initial/final state, initial/final transcript, accepted-event count, mutation
summary, status, Protocol outcome, ordered errors, and limitations. It includes no wall-clock time,
random value, hostname, absolute path, environment variable, or network-derived metadata. A future
private Evidence producer may wrap it in a separate execution envelope without changing these six
statuses.

Protocol failures retain the reviewed State Machine taxonomy. Runner failures use the
`CONFORMANCE-*` namespace. Error lists are sorted and duplicate-free. Unknown error/schema/version
values fail closed.

## File and execution boundary

Only repository-relative paths beneath the fixed suite or explicit output root are allowed.
Absolute/Windows/backslash/empty/dot/dot-dot paths, escapes, symlinks, directories, missing or
non-regular files, oversized data, invalid UTF-8, duplicate keys, unsafe numbers, and noncanonical
wire bytes are rejected with bounded value-free errors. The verifier performs no recursive repository
search, home scan, network request, GitHub API call, private checkout, adapter subprocess, shell
command, deployment, release, or publication. Output is an atomic mode-0600 write beneath the
explicit repository-local output root; failures leave no partial result.

## Limitations

This reference is an executable interpretation of the reviewed Draft artifacts, not an independent
implementation. Passing it is necessary evidence for these fixed cases only. It cannot certify
cryptographic security, production operation, pilot readiness, or interoperability.
