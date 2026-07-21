# Private Match core message contract v0.1

## Status and claim boundary

- Artifact status: `draft`
- Protocol profile: `private-match-core/v0.1`
- Representation: UTF-8 JSON
- Schema vocabulary: JSON Schema Draft 2020-12
- Canonicalization: RFC 8785 JSON Canonicalization Scheme (JCS)
- Digest: SHA-256 with the domains defined in the
  [canonical transcript contract](canonical-transcript-v0.1.md)

This contract defines implementation-independent data and transcript inputs. It
selects no signature, MAC, attestation, PET, transport, storage, production API,
or production key. Passing its schemas and vectors establishes neither
cryptographic security nor implementation conformance.

## Strict input and version behavior

An accepted message is exactly one RFC 8785 canonical UTF-8 JSON value. A reader
must reject invalid UTF-8, a byte-order mark, duplicate object names, lone
Unicode surrogates, integers outside the I-JSON safe integer range, NaN,
Infinity, negative zero, trailing data, noncanonical whitespace, and
noncanonical number or property ordering.

The verified RFC 8785 erratum concerning negative zero is applied fail closed:
source-level and programmatic negative zero are rejected instead of collapsing
to canonical `0`. Unicode strings are preserved as-is. NFC and NFD are not
normalized to the same input.

Every object has `additionalProperties: false`. The protocol profile, protocol
version, message type, and message version must be registered exactly. An
unknown field, type, version, authentication mode, algorithm identifier, key
identifier, or verification-material identifier fails closed without accepted
state or transcript mutation.

Draft `v0.1` has no compatibility commitment. Adding a required field, changing
canonicalization, changing the authentication input, or changing a field's
meaning requires another reviewed draft or protocol version before this
artifact can become candidate or stable.

## Common envelope

[`envelope.v0.1.schema.json`](../../schemas/messages/envelope.v0.1.schema.json)
defines the common object. All message-specific payloads are selected by an
exact `message_type` conditional.

| Field | Purpose | Authentication input |
| --- | --- | --- |
| `protocol_profile`, `protocol_version` | Exact core profile binding | Included |
| `message_type`, `message_version` | Exact registry and payload contract | Included |
| `delivery_class` | State-machine delivery semantics | Included |
| `session_context` | Session, policy, participants, audience, commitment, attempt, and profile binding | Included |
| `sender` | Actor, participant, and key binding | Included |
| `audience` | Intended verifier or recipient set | Included |
| `issued_at`, `expires_at` | Auxiliary message-validity interval | Included |
| `identity` | Party replay, coordinator operation, callback, or derived-notice identity | Included |
| `prior_transcript_digest` | Expected accepted transcript head | Included |
| `payload` | Message-specific data | Excluded directly; bound through `payload_digest` |
| `payload_digest` | Domain-separated canonical payload digest | Included |
| `authentication` metadata | Mode, algorithm, key, and verification material | Included |
| `authentication.value` | External authenticator bytes/string | The only authentication member excluded |
| `message_digest` | Domain-separated digest of the canonical authentication input | Excluded to avoid a cycle |

The coordinator also computes an internal replay fingerprint over the complete
strictly parsed canonical wire value:

```text
wire_message_digest = SHA-256(
  domain("private-match-wire-message/v0.1") || RFC8785(complete message)
)
```

This includes `authentication.value`, `message_digest`, payload, envelope, and
all other wire fields. It is stored only as `sha256:<64 lowercase hex>` in the
accepted record, never enters the authentication input or accepted transcript,
and does not require retention of the raw authenticator.

`json.dumps(sort_keys=True)` is not an RFC 8785 implementation and must not be
used to produce authenticated bytes.

## Authentication contract

External messages require one of `signature`, `mac`, or
`profile-attestation`. `none` is not allowed in the core message schema. The
algorithm, key, verification-material, sender, audience, session, policy,
versions, delivery identity, time, prior transcript, and payload digest all
enter the authentication input.

This draft fixes only that input. It does not select or implement an algorithm.
The conformance material identifiers and authenticator values are explicitly
synthetic placeholders. They exercise fail-closed metadata validation and must
not be used as keys, authenticators, or production configuration. A future
reviewed integration or authentication profile must define actual verification,
revocation authority, issuer/verifier separation, and key lifecycle. A shared
HMAC key must not be assumed suitable where issuer and verifier separation is
required.

Missing, unknown, expired, revoked, sender-mismatched, algorithm-mismatched, or
key-mismatched verification metadata fails closed. Schema/metadata success does
not prove that the synthetic authentication value is valid.

## Delivery classes

### Party message

A Party message binds the exact session context, sender participant and key,
per-sender sequence, message ID, nonce, `issued_at`, expiry, payload digest,
prior transcript head, and authentication metadata. Its replay domain is
`(session_id, sender_participant_id)`. Same-domain message IDs and nonces are
independently unique.

An exact duplicate requires the same message ID, nonce, sequence, `issued_at`,
canonical message digest, full-wire digest, verification material, original
authenticated subject, and session/sender domain. A changed authenticator is a
`REPLAY_CONFLICT` even when the authentication input and semantic message digest
are unchanged. Draft v0.1 retry therefore means byte-identical canonical
retransmission; it does not permit regenerating a randomized signature.

Authoritative processing classifies a possible exact duplicate before applying
the current transcript-head, message-time, or verification-material validity
gates. It still performs strict JSON and Schema validation, recomputes the
canonical bytes and digest, resolves the replay domain, and requires a complete
match against an accepted record. Only that cached-response path may ignore a
later transcript head or a material/message expiry or revocation that occurred
after original acceptance. It is not a new authenticated event and cannot
change state, sequence, nonce, budget, audit, or transcript. Returning the cached
response additionally requires an independent trusted requester projection from
channel authentication, a service principal, or a reviewed profile instance.
It must exactly equal the response's original recipient subject; it is never
copied from the replayed message. No requester or a peer/mismatched requester can
receive the response, although the coordinator may classify the wire value as
an exact duplicate internally.

If no accepted record exists, the input follows the ordinary new-message path
and must satisfy the current transcript, time, material, State Machine, and
transcript-mutation checks. The stateless `validate_messages.py --file` path has
no authoritative accepted-record store; it therefore validates the input as a
current message and never fabricates exact-duplicate success.

### Coordinator command

A coordinator command carries `actor_id`, `operation_id`, and an independently
unique `idempotency_key`. The operation-ID and idempotency-key indexes must both
be new or both resolve to the same canonical message digest and prior response.
A one-sided or different binding fails as `REPLAY_CONFLICT` without state,
budget, audit, or transcript mutation.

### Profile callback

A callback binds profile ID, version, instance, callback ID, independent
idempotency key, session ID, and evaluation attempt ID. Both callback indexes
are scoped by the complete profile/session/attempt domain. The core selects no
concrete profile or PET.

### Timer

A timer is not a Party wire message. The strict
[`timer-event.v0.1.schema.json`](../../schemas/messages/timer-event.v0.1.schema.json)
binds coordinator-authoritative time, a reviewed reason/source class, the
session, and prior transcript. A mutating accepted timer event receives its own
domain-separated canonical event digest. It has no Party nonce, sequence,
message ID, or Party-supplied authoritative time. Same-threshold no-op
re-evaluation does not append the transcript.

The reference trace executor validates and applies the timer State Machine
transition and the transcript append as one abstract transaction. The selected
effect is derived from current state and thresholds, not chosen by the caller's
reason label. The fixed precedence is session expiry, evaluation timeout,
active-consent expiry, then live clock advance. The reason/source value must
match that derived effect. Same-time input is a no-op. Any rejected guard,
canonicalization failure, or transcript bound failure leaves both runner and
transcript unchanged.

### Derived transition and local guidance

A derived notice is authenticated for its external recipient but is not a
second accepted state mutation. The accepted source event already occupies the
transcript entry. `reject_message` and `request_new_evaluation_session` are not
externally acceptable messages. Rejected input, pure local guidance, and other
nonmutating relations do not enter the accepted transcript.

## Message registry

The normative machine-readable mapping is
[`message-types.v0.1.yaml`](../../registry/message-types.v0.1.yaml).

| Message type | Delivery class | State-machine event | Transcript rule |
| --- | --- | --- | --- |
| `session_proposal` | coordinator command | `create_session` | Accepted mutation |
| `session_acceptance` | Party message | `accept_session_a/b` | Accepted mutation |
| `participant_binding` | Party message | `bind_participant_a/b` | Accepted mutation |
| `policy_acceptance` | Party message | `accept_policy` | Accepted mutation |
| `commitment_registration` | Party message | `register_commitment_a/b` | Accepted mutation |
| `query_budget_reservation` | coordinator command | `reserve_query_budget` | Accepted mutation |
| `evaluation_start` | coordinator command | `start_evaluation` | Accepted mutation |
| `evaluation_contribution` | Party message | `submit_evaluation_contribution` | Accepted mutation |
| `opaque_receipt_ack` | Party message | `acknowledge_opaque_receipt_a/b` | Accepted mutation |
| `result_acceptance_notice` | profile callback | `accept_symmetric_result` | Accepted mutation |
| `consent_grant` | Party message | `grant_consent_a/b` | Accepted mutation |
| `consent_withdrawal` | Party message | `withdraw_consent_a/b` | Accepted mutation |
| `disclosure_extension_authorization` | coordinator command | `authorize_disclosure_extension` | Accepted mutation |
| `disclosure_completion_notice` | profile callback | `record_disclosure_completion` | Accepted mutation |
| `abort_notice` | coordinator command | `abort_session` | Accepted mutation |
| `normalized_error_notice` | derived output | `reject_message` | Excluded |
| `close_notice` | coordinator command | `close_session` | Accepted mutation |
| `expiry_notice` | derived output | timer source event | Excluded; source timer may enter |

`session_acceptance` and `participant_binding` are separate. `create_session`
fixes one proposal digest; each Party then records an immutable, Party-specific
acceptance of that exact digest together with the trusted authentication-subject
projection produced after verification-material validation. The stored
projection binds participant ID, key ID, subject-binding ID, and material ID. A
Party cannot enter either participant-binding transition until its acceptance
exists and the new binding equals that stored projection. A second active key
for the same role does not satisfy the guard, v0.1 defines no in-session key
rotation, and the binding message cannot substitute for proposal acceptance.

`commitment_registration` carries only one Party-slot opaque commitment. It does
not carry `commitment_pair_id`; that unknown field fails closed. When the second
commitment arrives, the coordinator deterministically derives the pair ID as
SHA-256 over the `private-match-commitment-pair/v0.1` domain and RFC 8785 bytes
containing the protocol, policy, session, fixed A/B participant slots, selected
profile, and both commitments. This is an identity binding, not proof of input
truth, input completeness, or PET security.

## Result confidentiality

Coordinator-readable core JSON never contains `MATCH`, `NO_MATCH`,
`INDETERMINATE`, a Party-local result or result binding, raw or normalized
identifiers, matching or non-matching elements, an exact count, private
attributes, secret input, or an actual disclosure payload.

`opaque_receipt_ack` carries only an opaque receipt reference, normalized
acknowledgment status, profile evidence reference, and existing context. A
Party-local result remains in a recipient-specific protected artifact defined
by a later integration profile. The coordinator cannot parse that artifact as
core JSON. The profile's protection properties are unestablished in this draft.

`result_acceptance_notice` is a profile callback with the common opaque receipt,
`BOTH_ACKNOWLEDGED`, and an opaque profile-evidence reference. It does not carry
or hash a plaintext decision. A public receipt must not contain a secret input.
The evolving conformance runner requires both contribution slots, two separate
`ACKNOWLEDGED` Party records with the same receipt, and a callback bound to the
current profile/session/attempt before accepting the result. These checks are
atomic with transcript and dedup acceptance.

Party notices expose only the reviewed `party_error_category`; detailed failure
codes remain coordinator/private-assurance data. The internal `abort_notice`
may carry a declared abort code only to coordinator and assurance audiences.

## Consent and disclosure boundary

Consent payloads bind the accepted opaque receipt, versioned disclosure
profile, exact scope, audience, issue/expiry times, nonce, and artifact digest.
The first Party consent establishes the exact profile/scope/audience tuple for
the second Party; a mismatch, expired interval, wrong receipt, or reused Party
slot fails without state, dedup, transcript, budget, or audit mutation.
`MATCH` is not blanket consent. Core messages carry no actual identity or
private-data disclosure payload. Disclosure authorization and completion
remain extension-only and fail closed without a separately reviewed profile.
Synthetic extension vectors demonstrate structure only and do not authorize a
real disclosure.

## Clock, verification, and failures

The coordinator clock remains authoritative. Party `issued_at` is auxiliary and
must fall inside the state-machine skew and stale-message policy. Expired
messages and verification material fail closed. Material validity requires
`not_before <= issued_at < not_after` and also
`not_before <= authoritative_time < not_after`; revocation always fails closed.
Authentication, sender, and material key IDs must be equal. Machine-readable
subject metadata additionally binds the Party participant, Coordinator actor,
or integration-profile ID/version/instance to the current context. The
`authenticated_subject_parameter` is a trusted post-validation projection; it
is not a caller-supplied wire field. Timer inputs use the state machine's clock
taxonomy, not Party `STALE_MESSAGE` semantics.

All failures occur before accepted transcript mutation. A normalized Party
response may state a reviewed category and retry/new-session disposition, but
must not reveal the raw failure detail when that would increase inference.

## Conformance assets and validation

Synthetic positive and negative vectors live under
[`conformance/messages`](../../conformance/messages). The generator is
network-free and deterministic:

```text
python scripts/generate_message_vectors.py --root . --check
python scripts/validate_messages.py --root .
```

The validator checks strict parsing, canonical byte equality, schemas, registry
uniqueness, state-machine mappings, payload and message digests,
verification-material metadata, replay identities, transcript chains, and
prohibited data classes. It does not contact a network or verify an actual
cryptographic authenticator.

The expected transcript is executed as an evolving abstract state trace.
Participants begin unbound; commitment-pair and attempt values begin as `null`;
the selected integration-profile state also begins as `null` and is established
from the session-proposal payload by `create_session`; acceptance precedes
binding; budget precedes commitments; and each message binds the state
immediately before its transition. Registry sources have structured
parameter/field destinations and exact consuming transition operations. Unknown,
unused, duplicate, or incorrectly consumed destinations fail validation.
Security-sensitive YAML rejects duplicate mapping keys, and semantic identifiers
are checked before lookup indexes are built.
