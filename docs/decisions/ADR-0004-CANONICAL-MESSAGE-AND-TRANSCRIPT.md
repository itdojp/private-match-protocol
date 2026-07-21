# ADR-0004: Draft canonical message and transcript contract

- Status: proposed
- Artifact status: draft
- Decision owner: ITDO Inc.
- Decision date: 2026-07-21
- Review date: 2026-10-21
- Protocol profile: `private-match-core/v0.1`
- Issue: `itdojp/private-match-protocol#5`

## Context

Issue #5 requires an implementation-independent, versioned message contract and
canonical transcript. The merged Issue #4 state machine already distinguishes
Party replay envelopes, coordinator operation envelopes, profile callbacks,
timers, derived relations, and local guidance. It did not select wire JSON,
canonicalization, authentication input bytes, or an accepted transcript head.

Canonicalization is security-sensitive. Python `json.dumps(sort_keys=True)`
does not implement RFC 8785 number formatting, UTF-16 property ordering, or the
full I-JSON domain. A local approximation would add interoperability and
substitution risk.

## Decision

Draft `private-match-core/v0.1` uses:

- UTF-8 JSON
- JSON Schema Draft 2020-12
- `additionalProperties: false` at every schema object boundary
- exact profile, message type, and version matching
- RFC 8785 JCS canonical bytes
- SHA-256 with length-prefixed ASCII domain labels
- separate payload, message/authentication-input, timer-event, genesis, and
  transcript digests
- coordinator-authoritative accepted-event ordering
- transcript inclusion only for accepted mutating relations

The complete construction is normative in the
[canonical transcript contract](../../specs/messages/canonical-transcript-v0.1.md).

Verification-material authorization is subject-specific, not role-only. The
synthetic registry binds each material to a Party participant, Coordinator, or
selected integration-profile ID/version/instance. Authentication, sender, and
material key IDs must agree. Both message issue time and
Coordinator-authoritative verification time must be inside the material's
half-open validity interval; revocation always fails closed. These checks do not
select an algorithm or establish real key ownership.

The successful check yields a trusted authentication-subject event parameter.
Party session acceptance stores that participant, key, subject-binding ID, and
material ID; later participant binding must match the stored record. The trusted
projection is not copied from caller-controlled JSON, and v0.1 deliberately has
no key-rotation path.

Conformance uses an evolving abstract state trace rather than an initially
fully populated session. Session acceptance and participant binding are separate
events, and the former is a real prerequisite. The integration-profile state is
unbound before `create_session` and is atomically established from the reviewed
session-proposal field rather than appearing as future state in pre-create
context. Registry mappings name catalog
parameter fields and consuming transition operations. Security-sensitive YAML
and semantic identifiers reject ambiguity before index construction. Timer
transcript append computes all values before an exception-atomic assignment.
The abstract runner additionally executes policy, contribution, bilateral
receipt/callback, and consent bindings across the evolving trace; phase alone is
not sufficient. Party commitment messages no longer assert a pair ID. The
second commitment causes a deterministic RFC 8785/SHA-256 pair derivation under
`private-match-commitment-pair/v0.1` in fixed A/B order.

## RFC 8785 implementation decision

The reviewed Python dependency is `rfc8785==0.1.4` from Trail of Bits.

Observed on 2026-07-21:

- the release is the latest published PyPI and GitHub tag
- PyPI publishes a `py3-none-any` wheel and declares Python 3.8 or newer
- the repository is not archived and received maintenance changes in June 2026
- current upstream tests cover Python 3.8 through 3.14
- the package is dependency-free at runtime
- the package and its adapted reference implementation are Apache-2.0
- its tests include the Apache-2.0 reference vectors and RFC 8785 number cases
- it emits deterministic UTF-8 bytes, preserves Unicode without normalization,
  rejects non-finite numbers and invalid Unicode, and implements RFC number and
  UTF-16 key ordering

The package accepts Python values and therefore cannot observe duplicate names
already discarded by a normal JSON parser. The repository adds a strict parser
that rejects duplicate names, invalid UTF-8, NaN, Infinity, and unsafe integer
values before calling it.

The package serializes negative zero as canonical `0`, matching the original
RFC text. Verified RFC erratum 7920 recommends rejecting parsed negative zero to
prevent distinct source inputs from collapsing. This contract follows that
fail-closed recommendation and also rejects programmatic negative-zero floats.

`requirements-dev.in` pins the exact version and `requirements-dev.txt` records
both reviewed PyPI SHA-256 distribution hashes. The supported CI target is
GitHub-hosted Ubuntu 24.04 x86_64 with CPython 3.12.11. Lock regeneration uses:

```text
uv pip compile --python-version 3.12 \
  --python-platform x86_64-manylinux_2_28 \
  --generate-hashes requirements-dev.in \
  --output-file requirements-dev.txt
```

The dependency must be reviewed and the official/adversarial vectors rerun
before renewal. A version or canonical-byte change is a protocol compatibility
change, not an automatic dependency update.

## Sources and evidence

Primary public sources reviewed:

- RFC 8785 and its official examples and number vectors:
  <https://www.rfc-editor.org/rfc/rfc8785.html>
- verified RFC 8785 errata:
  <https://www.rfc-editor.org/errata/rfc8785>
- Trail of Bits implementation and Apache-2.0 license:
  <https://github.com/trailofbits/rfc8785.py>
- published `rfc8785` 0.1.4 files, metadata, and hashes:
  <https://pypi.org/project/rfc8785/>
- reference cross-language vectors linked by the RFC:
  <https://github.com/cyberphone/json-canonicalization>

Repository evidence includes RFC sample/number tests, Unicode and number edge
cases, duplicate-key and noncanonical-source negatives, full message vectors,
transcript chain vectors, deterministic generation, and state-machine
consistency tests.

## Options considered

### RFC 8785 library versus deferred canonicalization

Adopt the reviewed library because it has a compatible license, exact release,
current repository maintenance, suitable Python support, official/reference
vectors, and deterministic bytes. If any of those facts ceases to hold, defer a
new encoding decision rather than implementing a pseudo-JCS replacement.

### RFC 8785 versus `json.dumps(sort_keys=True)`

Reject `json.dumps(sort_keys=True)`. It is useful for ordinary serialization but
is not the selected canonicalization standard.

### Dependency versus custom implementation

Reject a new in-repository JCS implementation. Number serialization and UTF-16
ordering are subtle, and inventing a canonicalizer is unnecessary protocol and
security risk.

### Canonical wire bytes versus arbitrary JSON with canonical companion bytes

Require canonical wire bytes for draft v0.1. This gives one byte representation
and makes noncanonical input a clear failure. A future version may allow a
noncanonical transport representation while authenticating a canonical
companion, but that is not this contract.

### One digest versus separate digest layers

Use separate payload, message, timer-event, and transcript domains. This avoids
cross-protocol confusion and avoids a circular message digest. The
`authentication.value` and `message_digest` are excluded from the authentication
input; algorithm, key, and verification-material identifiers remain inside.

### Transcript every observation versus accepted mutations only

Record accepted mutating events once. Exclude rejects, exact duplicates,
conflicts, derived notices, local guidance, and timer no-op. The normalized audit
may record allowed rejection categories separately; it is not the accepted
protocol transcript.

### Coordinator ordering versus Party ordering

Use the coordinator's atomic accepted-event order. Party sequence remains
per-sender and cannot globally order concurrent Party messages. This draft does
not define a distributed consensus or persistence implementation.

## Security and privacy assumptions

- SHA-256 is a digest identifier here, not a security certification.
- Actual signature, MAC, attestation, key, issuer, verifier, revocation, and PET
  profiles remain unselected.
- All committed authenticators and verification material are synthetic.
- Coordinator-readable messages and transcript inputs exclude plaintext
  decisions and secret inputs.
- A protected Party-local result artifact remains profile-dependent and
  unestablished.
- Transport confidentiality, endpoint security, traffic analysis, storage, and
  operational logging remain outside this ADR.

## State-machine compatibility impact

Issue #5 adds `accepted_event_index`, `canonical_transcript_head`, delivery-class
prior/digest fields, atomic append guards/effects, and
`INV-CANONICAL-TRANSCRIPT` to the merged draft Issue #4 artifact. It does not
change result values, result symmetry, commitment immutability, query-budget
consumption, consent replacement, failure projection, or extension-only
reveal semantics.

Schema version `0.1` is retained because these are coherent draft-internal
changes before any candidate, stable, deployed-reader, or compatibility
commitment. A later promotion is a human decision.

## Rejected claims and deferred decisions

This ADR does not claim:

- cryptographic security or authentication success
- production transport, API, database, or persistence design
- implementation conformance or cross-implementation interoperability
- PET or outcome-confidentiality mechanism selection
- legal compliance, production readiness, or candidate/stable status

Human decisions remain required for an actual authentication algorithm/profile,
key and verification-material authority, integration profile, publication and
merge approval, and any candidate/stable compatibility policy.
