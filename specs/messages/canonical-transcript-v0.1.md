# Private Match canonical transcript contract v0.1

## Status

- Artifact status: `draft`
- Protocol profile: `private-match-core/v0.1`
- Canonical JSON: RFC 8785 JCS
- Digest: SHA-256
- Ordering authority: coordinator

This document is normative for digest construction and accepted-event ordering.
It does not establish cryptographic security, collision resistance in a
selected implementation, transport security, persistence durability, or a
production audit design.

## Domain encoding

For each ASCII label `L`:

```text
domain(L) = uint16be(length(ASCII(L))) || ASCII(L)
```

The fixed-width length makes concatenation unambiguous. A digest is represented
externally as `sha256:` followed by 64 lowercase hexadecimal characters. Digest
formulas operate on the underlying 32 bytes, not the textual prefix.

The labels are exact and case-sensitive:

- `private-match-payload/v0.1`
- `private-match-message/v0.1`
- `private-match-transcript/v0.1`
- `private-match-transcript-genesis/v0.1`
- `private-match-timer-event/v0.1`

## Payload digest

```text
payload_digest = SHA-256(
  domain("private-match-payload/v0.1")
  || RFC8785(payload)
)
```

The payload remains in the message for schema validation, but only the digest
enters the authentication input. A validator recomputes it before accepting the
message.

## Authentication input

The canonical authentication-input object contains:

- protocol profile and version
- message type and version
- delivery class
- full session context
- sender and key binding
- intended audience
- message issue and expiry times
- Party replay, coordinator operation, callback, or notice identity
- prior transcript digest
- payload digest
- authentication mode
- algorithm identifier
- key identifier
- verification-material identifier

It excludes only `payload`, `authentication.value`, and `message_digest`.
Excluding the final authenticator and message digest prevents circular input.
Excluding payload bytes does not omit the payload because the included
`payload_digest` binds its canonical value.

Algorithm and key identifiers are authenticated metadata. Moving them outside
the input would permit algorithm or key substitution and is prohibited.

## Message digest

```text
message_digest = SHA-256(
  domain("private-match-message/v0.1")
  || RFC8785(authentication_input)
)
```

This digest is the state machine's canonical Party event, coordinator operation,
or profile callback digest. It is not a signature, MAC, attestation, or result
receipt.

## Genesis

```text
transcript_digest_0 = SHA-256(
  domain("private-match-transcript-genesis/v0.1")
)
```

For this exact domain encoding:

```text
sha256:200b23451f65992feacb88e782a16afb595bc32d386a4347bb318892cde2ff3c
```

The initial `accepted_event_index` is `0`.

## Accepted transcript append

For each accepted mutating event in coordinator-authoritative order:

```text
accepted_event_index_n = accepted_event_index_(n-1) + 1

transcript_digest_n = SHA-256(
  domain("private-match-transcript/v0.1")
  || raw32(transcript_digest_(n-1))
  || uint64be(accepted_event_index_n)
  || raw32(accepted_event_digest_n)
)
```

The accepted event index is in `1..2^64-1`. For Party messages, coordinator
commands, and profile callbacks, `accepted_event_digest_n` is the validated
`message_digest`. For a timer mutation it is:

```text
timer_event_digest = SHA-256(
  domain("private-match-timer-event/v0.1")
  || RFC8785(authoritative_timer_event)
)
```

The coordinator atomically applies the protocol mutation, increments the event
index, and replaces the transcript head. A persistence mechanism is not defined
here, but a later implementation must not acknowledge a state mutation while
persisting a different transcript position.

Timer append is exception-atomic. The next index, canonical timer digest, and
next head are first computed as local values. The authoritative index and head
are assigned together only after all computations succeed. Invalid timer values,
malformed digests, prior-head mismatch, and the `uint64` bound leave both fields
unchanged.

The reference trace path is stricter than the low-level digest append: it copies
both the abstract State Machine runner and transcript, validates the timer
schema/session/prior head/clock bound, derives exactly one transition, applies
its state effects, and computes the append before committing either object.
Threshold precedence is session expiry, evaluation timeout, active-consent
expiry, then live advance. The caller-provided reason/source class must agree
with the derived effect. A same-time no-op commits neither state nor transcript.

## Included and excluded relations

Included exactly once:

- accepted mutating Party messages
- accepted mutating coordinator commands
- accepted mutating profile callbacks
- accepted mutating authoritative timer events

Excluded:

- rejected input
- conflicting duplicate input
- exact duplicate resend or operation/callback retry
- derived outbound notice whose source event was already accepted
- pure local guidance
- same-threshold timer no-op
- any other nonmutating normalized response

A rejected or conflicting message does not enter the accepted transcript. An
exact duplicate returns the prior normalized response and the previous
transcript head. It cannot consume budget, repeat audit mutation, or append a
second entry.

An authoritative accepted-record lookup precedes the gates that are meaningful
only for a new event. After strict parse/Schema/canonical-digest checks, a
complete sender/operation/callback-domain identity match may return the stored,
recipient-scoped response even if the current transcript head has advanced or
the original message/material later expired or was revoked. Any changed ID,
nonce, idempotency key, callback identity, digest, or domain is a conflict. If
no accepted record exists, current prior-head, time, material, State Machine,
and transcript checks all remain mandatory. A stateless file validator cannot
infer this historical state and does not take the cached-response path.

## Ordering, omission, and prior binding

The coordinator is the only authority for the accepted event index. Each
external message and timer event binds the expected prior transcript digest.
A reordered or omitted entry therefore changes the next head or makes the next
prior binding fail. Party sequence and nonce domains plus independent operation
and callback ID/idempotency-key indexes remain separate checks; the transcript
does not replace them.

A sender cannot choose the accepted event index. Transport buffering and
storage layout remain outside this draft.

## Result confidentiality

Transcript entries use complete message or timer-event digests. They never use
`hash(MATCH)`, `hash(NO_MATCH)`, `hash(INDETERMINATE)`, or another enumerable
bare result digest. Coordinator-readable messages contain only the opaque
receipt reference and normalized status. The transcript therefore does not
introduce a new plaintext outcome field.

This is a structural prohibition, not evidence that an unselected protected
artifact or future implementation hides the outcome. That property requires a
reviewed integration profile and implementation evidence.

## State-machine alignment

Issue #5 adds two orthogonal variables to the merged draft state machine:

- `accepted_event_index`
- `canonical_transcript_head`

Every accepted mutating delivery class has a machine-readable prior-head guard
and atomic append effect. `INV-CANONICAL-TRANSCRIPT` prohibits append on reject,
conflict, exact duplicate, derived notice, local guidance, or timer no-op. The
state-machine schema and semantic validator enforce this mapping.

This is a draft-internal compatibility change. The state-machine artifact
remains schema version `0.1` because neither it nor the message contract has a
candidate, stable, or external-reader compatibility commitment. Promotion or
wire deployment requires human review.

## Vectors

The expected-digest vector includes a synthetic accepted chain, exact duplicate
cases, independent operation/callback key conflicts, reordering, omission,
rejection, and a timer entry. Generation and validation are deterministic and
network-free:

```text
python scripts/generate_message_vectors.py --root .
python scripts/generate_message_vectors.py --root . --check
python scripts/validate_messages.py --root .
```

The vector values are synthetic. They are not real identities, commitments,
receipts, consent, keys, signatures, attestations, or disclosure approvals.
