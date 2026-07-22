<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Conformance State Projection v0.1

Status: **Draft**. Digest domain: `private-match-conformance-state-projection/v0.1`.

The versioned projection is the interoperable logical-state comparison surface for
`private-match-core/v0.1`. Independent implementations produce the same RFC 8785 JSON value for the
same reviewed State Machine state, then compute SHA-256 over the domain bytes followed by the
canonical projection bytes. The closed JSON Schema is
`schema/conformance-state-projection.v0.1.schema.json`; normalization and exclusion rules are bound
by `conformance/source/state-projection-profile.v0.1.json`.

The projection contains lifecycle, session and exact acceptance subjects, participant and policy
bindings, commitments and the derived pair, evaluation/profile/attempt/deadline, per-Party
contributions/results/receipt acknowledgments, accepted receipt, query-budget disposition, consent,
disclosure authorization, authoritative clock, terminal categories, sequence state, and stable
sorted replay/idempotency records. Unordered reviewed sets and replay records are RFC 8785 byte-sorted;
Party slots are always explicit `party_a`/`party_b`, including `null` unbound state.

The projection excludes Python class/layout data, object identity, arbitrary helper/cache fields,
audit helper values, normalized response bodies/references, raw authentication values, private
input, and any Coordinator plaintext result. Transcript head and accepted-event index are also
excluded: run results bind `initial_state_digest`/`final_state_digest` separately from
`initial_transcript_head`/`final_transcript_head` and `accepted_event_count`. Consequently a
transcript-only change does not alter the state projection digest, and state/transcript mutation
flags can be evaluated independently.

This is a Draft conformance projection. Its digest binds a logical value; it does not establish
correctness, cryptographic security, persistence equivalence, or interoperability certification.
