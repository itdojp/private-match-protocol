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

There are no case-directed semantic verdicts or status directives. Replay, ordering, transcript,
commitment, result, receipt, consent, disclosure, and clock vectors apply concrete messages, traces,
Party-local profile fixtures, or timer events through the shared evaluators. Leakage projections
submit concrete invalid message/notice/receipt bytes to strict Message and Leakage validation. These
paths are not a second State Machine and cannot select a PET, transport, cryptographic algorithm, or
disclosure profile.

## Processing order

The verifier performs: safe path resolution; strict parse; case Schema validation; case/suite digest
verification; Protocol pin verification; initial abstract-state construction; ordered input and
authentication-precondition evaluation; message/timer State Machine execution; outcome construction;
expected comparison; deterministic result construction; and final Schema/digest self-validation.
Only a fully validated candidate state and transcript are committed.

Expected values come exclusively from the reviewed normative oracle source. Reference execution is
an implementation under test: changing its outcome mapping, error mapping, or state mutation does
not alter expected artifacts and instead yields `CONFORMANCE-EXPECTED-MISMATCH` and runner `fail`.

## Determinism

The run result is RFC 8785 JSON and binds suite, case, Protocol artifacts, the closed reference-
implementation manifest and its semantic digest, fixture adapter, input, canonical v0.1 initial/final
state projections, initial/final transcript, accepted-event count, mutation
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

Single-case output remains a file-level atomic write. `--all` requires a nonexistent final output
directory, writes every result and a run-set manifest into a sibling repository-local staging
directory, re-reads the exact file set and every result/file/tree digest, fsyncs it, and performs one
directory rename. A late failure removes staging and leaves neither a partial nor a stale final set;
implicit replacement of an existing result directory is forbidden.

`conformance/source/reference-verifier-implementation.v0.1.json` closes the complete reviewed Python
import closure plus explicitly loaded Schemas, runtime policy/profile, and dependency locks. Each
path and file digest is rechecked, local imports must remain within the path set, and run/suite results
bind both manifest-file and implementation digests. Protocol State Machine, Message registry, and
Message input-tree pins remain separate normative artifact bindings.

## Limitations

This reference is an executable interpretation of the reviewed Draft artifacts, not an independent
implementation. Passing it is necessary evidence for these fixed cases only. It cannot certify
cryptographic security, production operation, pilot readiness, or interoperability.
