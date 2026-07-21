from __future__ import annotations

import copy
import json
import sys
import unittest
from unittest import mock
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import canonicalize_message as canonical  # noqa: E402
import validate_messages as validator  # noqa: E402
from strict_yaml import strict_yaml_load  # noqa: E402


class CanonicalTranscriptTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.vectors = canonical.strict_loads(
            (ROOT / validator.EXPECTED_DIGESTS).read_bytes()
        )
        cls.entries = cls.vectors["entries"]
        cls.duplicates = cls.vectors["duplicate_vectors"]

    def test_generated_chain_matches_every_expected_head(self) -> None:
        state = validator.TranscriptState()
        self.assertEqual(self.vectors["genesis_digest"], state.head)
        for index, entry in enumerate(self.entries, 1):
            if entry["kind"] == "message":
                outcome = state.accept_message(entry["message"])
            else:
                outcome = state.accept_timer(entry["timer_event"])
            self.assertEqual("ACCEPTED", outcome)
            self.assertEqual(index, state.accepted_event_index)
            self.assertEqual(entry["expected_head"], state.head)
        self.assertEqual(self.vectors["final_head"], state.head)

    def test_transcript_genesis_is_deterministic_and_domain_separated(self) -> None:
        first = canonical.transcript_genesis_digest()
        second = canonical.transcript_genesis_digest()
        self.assertEqual(first, second)
        self.assertNotEqual(first, canonical.payload_digest({}))

    def test_same_semantic_json_has_same_canonical_bytes_and_digest(self) -> None:
        first = canonical.strict_loads(b'{"z":0,"a":{"y":2,"x":1}}')
        second = canonical.strict_loads(b'{ "a" : { "x" : 1, "y" : 2 }, "z" : 0 }')
        self.assertEqual(canonical.canonicalize(first), canonical.canonicalize(second))
        self.assertEqual(
            canonical.payload_digest(first), canonical.payload_digest(second)
        )

    def test_payload_change_changes_message_and_transcript_head(self) -> None:
        message = self.entries[1]["message"]
        changed = copy.deepcopy(message)
        changed["payload"]["acceptance_digest"] = "sha256:" + "e" * 64
        changed = canonical.populate_digests(changed)
        self.assertNotEqual(message["message_digest"], changed["message_digest"])
        prior = message["prior_transcript_digest"]
        self.assertNotEqual(
            canonical.append_transcript(prior, 2, message["message_digest"]),
            canonical.append_transcript(prior, 2, changed["message_digest"]),
        )

    def test_security_routing_change_changes_transcript_entry(self) -> None:
        base = self.entries[1]["message"]
        fields = {
            "algorithm": lambda m: m["authentication"].__setitem__(
                "algorithm_id", "urn:private-match:test:algorithm:changed"
            ),
            "key": lambda m: m["authentication"].__setitem__(
                "key_id", "urn:private-match:test:key:changed"
            ),
            "session": lambda m: m["session_context"].__setitem__(
                "session_id", "urn:private-match:test:session:changed"
            ),
            "policy": lambda m: m["session_context"]["policy"].__setitem__(
                "policy_version", "9.9"
            ),
            "audience": lambda m: m.__setitem__("audience", ["party_b_client"]),
        }
        for name, mutate in fields.items():
            changed = copy.deepcopy(base)
            mutate(changed)
            digest = canonical.message_digest(changed)
            self.assertNotEqual(base["message_digest"], digest, name)

    def test_prior_digest_change_changes_transcript_head(self) -> None:
        entry = self.entries[0]
        alternate_prior = "sha256:" + "f" * 64
        self.assertNotEqual(
            entry["expected_head"],
            canonical.append_transcript(
                alternate_prior, 1, entry["message"]["message_digest"]
            ),
        )

    def test_reordering_fails_at_prior_binding(self) -> None:
        state = validator.TranscriptState()
        self.assertEqual(
            "PRIOR_TRANSCRIPT_MISMATCH",
            state.accept_message(self.entries[1]["message"]),
        )
        self.assertEqual(0, state.accepted_event_index)
        self.assertEqual(self.vectors["genesis_digest"], state.head)

    def test_omission_fails_at_next_prior_binding(self) -> None:
        state = validator.TranscriptState()
        self.assertEqual("ACCEPTED", state.accept_message(self.entries[0]["message"]))
        head = state.head
        self.assertEqual(
            "PRIOR_TRANSCRIPT_MISMATCH",
            state.accept_message(self.entries[2]["message"]),
        )
        self.assertEqual(head, state.head)
        self.assertEqual(1, state.accepted_event_index)

    def test_exact_party_duplicate_does_not_append_twice(self) -> None:
        message = self.duplicates["party_exact"]
        state = validator.TranscriptState(head=message["prior_transcript_digest"])
        self.assertEqual("ACCEPTED", state.accept_message(message))
        head, index = state.head, state.accepted_event_index
        self.assertEqual(
            "EXACT_DUPLICATE", state.accept_message(copy.deepcopy(message))
        )
        self.assertEqual((head, index), (state.head, state.accepted_event_index))

    def test_changed_party_duplicate_is_replay_conflict_without_mutation(self) -> None:
        original = self.duplicates["party_exact"]
        changed = self.duplicates["party_changed_payload"]
        state = validator.TranscriptState(head=original["prior_transcript_digest"])
        self.assertEqual("ACCEPTED", state.accept_message(original))
        head, index = state.head, state.accepted_event_index
        self.assertEqual("REPLAY_CONFLICT", state.accept_message(changed))
        self.assertEqual((head, index), (state.head, state.accepted_event_index))

    def test_rejected_message_does_not_mutate_transcript_or_dedup(self) -> None:
        message = self.duplicates["party_exact"]
        state = validator.TranscriptState(head=message["prior_transcript_digest"])
        before = (state.head, state.accepted_event_index)
        self.assertEqual("REJECTED", state.accept_message(message, rejected=True))
        self.assertEqual(before, (state.head, state.accepted_event_index))
        self.assertEqual("ACCEPTED", state.accept_message(message))

    def test_prior_head_rejection_does_not_reserve_replay_identity(self) -> None:
        message = copy.deepcopy(self.entries[0]["message"])
        correct_prior = message["prior_transcript_digest"]
        state = validator.TranscriptState()

        message["prior_transcript_digest"] = "sha256:" + "f" * 64
        message = canonical.populate_digests(message)
        self.assertEqual(
            "PRIOR_TRANSCRIPT_MISMATCH",
            state.accept_message(message),
        )
        self.assertEqual(0, state.accepted_event_index)

        message["prior_transcript_digest"] = correct_prior
        message = canonical.populate_digests(message)
        self.assertEqual("ACCEPTED", state.accept_message(message))
        self.assertEqual(1, state.accepted_event_index)

    def test_exact_operation_duplicate_uses_id_and_key_indexes(self) -> None:
        original = self.duplicates["operation_exact"]
        registry = validator.DedupRegistry()
        self.assertEqual("ACCEPTED", registry.classify(original))
        self.assertEqual("EXACT_DUPLICATE", registry.classify(copy.deepcopy(original)))
        for key in (
            "operation_same_id_different_key",
            "operation_same_key_different_id",
        ):
            self.assertEqual("REPLAY_CONFLICT", registry.classify(self.duplicates[key]))

    def test_same_operation_key_with_changed_digest_is_conflict(self) -> None:
        original = self.duplicates["operation_exact"]
        changed = copy.deepcopy(original)
        changed["payload"]["evaluation_deadline"] = "2026-07-21T00:09:00Z"
        changed = canonical.populate_digests(changed)
        registry = validator.DedupRegistry()
        self.assertEqual("ACCEPTED", registry.classify(original))
        self.assertEqual("REPLAY_CONFLICT", registry.classify(changed))

    def test_operation_actor_domain_is_independent(self) -> None:
        original = self.duplicates["operation_exact"]
        changed = copy.deepcopy(original)
        changed["identity"]["actor_id"] = "coordinator-other"
        changed = canonical.populate_digests(changed)
        registry = validator.DedupRegistry()
        self.assertEqual("ACCEPTED", registry.classify(original))
        self.assertEqual("ACCEPTED", registry.classify(changed))
        # Semantic validation, not the actor-scoped registry, rejects an actor
        # that does not equal the coordinator transition actor.
        self.assertNotEqual(
            [],
            [
                item
                for item in validator.semantic_message_findings(
                    changed,
                    yaml_load(ROOT / validator.REGISTRY_PATH),
                    yaml_load(ROOT / validator.MATERIAL_PATH),
                    yaml_load(ROOT / validator.CONTEXT_PATH),
                )
                if item.code == "operation-binding"
            ],
        )

    def test_exact_callback_duplicate_uses_id_and_key_indexes(self) -> None:
        original = self.duplicates["callback_exact"]
        registry = validator.DedupRegistry()
        self.assertEqual("ACCEPTED", registry.classify(original))
        self.assertEqual("EXACT_DUPLICATE", registry.classify(copy.deepcopy(original)))
        self.assertEqual(
            "REPLAY_CONFLICT",
            registry.classify(self.duplicates["callback_same_id_different_key"]),
        )
        self.assertEqual(
            "REPLAY_CONFLICT",
            registry.classify(self.duplicates["callback_same_key_different_id"]),
        )

    def test_callback_domain_includes_profile_session_and_attempt(self) -> None:
        original = self.duplicates["callback_exact"]
        registry = validator.DedupRegistry()
        self.assertEqual("ACCEPTED", registry.classify(original))
        for field, value in (
            ("profile_instance_id", "urn:private-match:test:profile-instance:other"),
            ("session_id", "urn:private-match:test:session:other"),
            ("evaluation_attempt_id", "urn:private-match:test:evaluation:other"),
        ):
            changed = copy.deepcopy(original)
            changed["identity"][field] = value
            changed = canonical.populate_digests(changed)
            self.assertEqual("ACCEPTED", registry.classify(changed), field)

    def test_party_replay_domain_includes_session_and_sender(self) -> None:
        original = self.duplicates["party_exact"]
        registry = validator.DedupRegistry()
        self.assertEqual("ACCEPTED", registry.classify(original))
        changed = copy.deepcopy(original)
        changed["session_context"]["session_id"] = (
            "urn:private-match:test:session:other"
        )
        changed = canonical.populate_digests(changed)
        self.assertEqual("ACCEPTED", registry.classify(changed))

    def test_same_message_id_for_a_and_b_is_independent(self) -> None:
        a = self.duplicates["party_exact"]
        b = copy.deepcopy(a)
        b["sender"] = {
            "actor": "party_b_client",
            "participant_id": "urn:private-match:test:participant:b",
            "key_id": "urn:private-match:test:key:party-b:v0.1",
        }
        b["identity"]["sender_participant_id"] = b["sender"]["participant_id"]
        b["authentication"].update(
            {
                "key_id": "urn:private-match:test:key:party-b:v0.1",
                "verification_material_id": "urn:private-match:test:material:party-b:v0.1",
            }
        )
        b = canonical.populate_digests(b)
        registry = validator.DedupRegistry()
        self.assertEqual("ACCEPTED", registry.classify(a))
        self.assertEqual("ACCEPTED", registry.classify(b))

    def test_timer_event_is_schema_valid_and_deterministic(self) -> None:
        entry = next(item for item in self.entries if item["kind"] == "timer")
        schema = json.loads((ROOT / validator.TIMER_SCHEMA).read_text())
        self.assertEqual(
            [],
            list(
                Draft202012Validator(
                    schema, format_checker=FormatChecker()
                ).iter_errors(entry["timer_event"])
            ),
        )
        first = canonical.timer_event_digest(entry["timer_event"])
        second = canonical.timer_event_digest(copy.deepcopy(entry["timer_event"]))
        self.assertEqual(first, second)

    def test_timer_no_op_does_not_append(self) -> None:
        timer = next(
            item["timer_event"] for item in self.entries if item["kind"] == "timer"
        )
        state = validator.TranscriptState(head=timer["prior_transcript_digest"])
        before = (state.head, state.accepted_event_index)
        self.assertEqual("NO_OP", state.accept_timer(timer, mutates=False))
        self.assertEqual(before, (state.head, state.accepted_event_index))

    def test_timer_append_failures_are_exception_atomic(self) -> None:
        valid = copy.deepcopy(
            next(
                item["timer_event"] for item in self.entries if item["kind"] == "timer"
            )
        )
        cases = []
        invalid_time = copy.deepcopy(valid)
        invalid_time["new_authoritative_time"] = "not-a-time"
        cases.append(("invalid time", invalid_time))
        unsupported = copy.deepcopy(valid)
        unsupported["reason_or_source_class"] = "UNSUPPORTED"
        cases.append(("unsupported value", unsupported))
        extra = copy.deepcopy(valid)
        extra["unexpected"] = True
        cases.append(("noncanonical contract", extra))
        for name, timer in cases:
            state = validator.TranscriptState(head=valid["prior_transcript_digest"])
            before = (state.head, state.accepted_event_index)
            with (
                self.subTest(name=name),
                self.assertRaises(canonical.CanonicalMessageError),
            ):
                state.accept_timer(timer)
            self.assertEqual(before, (state.head, state.accepted_event_index))

        state = validator.TranscriptState(
            head=valid["prior_transcript_digest"], accepted_event_index=2**64 - 1
        )
        before = (state.head, state.accepted_event_index)
        with self.assertRaises(canonical.CanonicalMessageError):
            state.accept_timer(valid)
        self.assertEqual(before, (state.head, state.accepted_event_index))

        state = validator.TranscriptState(head=valid["prior_transcript_digest"])
        before = (state.head, state.accepted_event_index)
        with (
            mock.patch.object(
                validator,
                "timer_event_digest",
                side_effect=canonical.CanonicalMessageError("digest"),
            ),
            self.assertRaises(canonical.CanonicalMessageError),
        ):
            state.accept_timer(valid)
        self.assertEqual(before, (state.head, state.accepted_event_index))

        state = validator.TranscriptState(head=valid["prior_transcript_digest"])
        before = (state.head, state.accepted_event_index)
        with (
            mock.patch.object(
                validator,
                "append_transcript",
                side_effect=canonical.CanonicalMessageError("bounds"),
            ),
            self.assertRaises(canonical.CanonicalMessageError),
        ):
            state.accept_timer(valid)
        self.assertEqual(before, (state.head, state.accepted_event_index))

    def test_valid_timer_commits_index_and_head_once(self) -> None:
        timer = next(
            item["timer_event"] for item in self.entries if item["kind"] == "timer"
        )
        state = validator.TranscriptState(head=timer["prior_transcript_digest"])
        self.assertEqual("ACCEPTED", state.accept_timer(timer))
        self.assertEqual(1, state.accepted_event_index)
        self.assertNotEqual(timer["prior_transcript_digest"], state.head)

    def test_derived_notice_is_excluded_from_accepted_transcript(self) -> None:
        notice = canonical.strict_loads(
            (
                ROOT / "conformance/messages/valid/normalized-error-notice.json"
            ).read_bytes()
        )
        state = validator.TranscriptState(head=notice["prior_transcript_digest"])
        before = (state.head, state.accepted_event_index)
        self.assertEqual("EXCLUDED", state.accept_message(notice))
        self.assertEqual(before, (state.head, state.accepted_event_index))

    def test_transcript_digest_does_not_hash_plaintext_result(self) -> None:
        rendered = canonical.canonicalize(self.vectors)
        self.assertNotIn(b'"MATCH"', rendered)
        self.assertNotIn(b'"NO_MATCH"', rendered)
        self.assertNotIn(b'"INDETERMINATE"', rendered)

    def test_event_index_is_fixed_width_and_bounds_checked(self) -> None:
        prior = canonical.transcript_genesis_digest()
        digest = self.entries[0]["message"]["message_digest"]
        self.assertNotEqual(
            canonical.append_transcript(prior, 1, digest),
            canonical.append_transcript(prior, 256, digest),
        )
        for invalid in (0, -1, 2**64):
            with self.assertRaises(canonical.CanonicalMessageError):
                canonical.append_transcript(prior, invalid, digest)


def yaml_load(path: Path):
    return strict_yaml_load(path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
