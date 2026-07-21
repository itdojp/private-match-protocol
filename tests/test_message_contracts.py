from __future__ import annotations

import copy
import json
import struct
import subprocess
import sys
import tempfile
import unittest
import unicodedata
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import canonicalize_message as canonical  # noqa: E402
import validate_messages as validator  # noqa: E402
from strict_yaml import strict_yaml_load  # noqa: E402


class MessageContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.message_schema = json.loads(
            (ROOT / validator.MESSAGE_SCHEMA).read_text(encoding="utf-8")
        )
        cls.timer_schema = json.loads(
            (ROOT / validator.TIMER_SCHEMA).read_text(encoding="utf-8")
        )
        cls.registry_schema = json.loads(
            (ROOT / validator.REGISTRY_SCHEMA).read_text(encoding="utf-8")
        )
        cls.material_schema = json.loads(
            (ROOT / validator.MATERIAL_SCHEMA).read_text(encoding="utf-8")
        )
        cls.registry = strict_yaml_load(
            (ROOT / validator.REGISTRY_PATH).read_text(encoding="utf-8")
        )
        cls.materials = strict_yaml_load(
            (ROOT / validator.MATERIAL_PATH).read_text(encoding="utf-8")
        )
        cls.context = strict_yaml_load(
            (ROOT / validator.CONTEXT_PATH).read_text(encoding="utf-8")
        )
        cls.valid_paths = sorted((ROOT / "conformance/messages/valid").glob("*.json"))
        cls.messages = {
            path.stem: canonical.strict_loads(path.read_bytes())
            for path in cls.valid_paths
        }
        cls.expected = canonical.strict_loads(
            (ROOT / validator.EXPECTED_DIGESTS).read_bytes()
        )
        cls.trace_messages = [
            entry["message"]
            for entry in cls.expected["entries"]
            if entry["kind"] == "message"
        ]

    def runner_before(
        self, message_type: str, actor: str | None = None
    ) -> tuple[validator.AbstractStateRunner, validator.TranscriptState, dict]:
        runner = validator.AbstractStateRunner(copy.deepcopy(self.context))
        transcript = validator.TranscriptState()
        for entry in self.expected["entries"]:
            if entry["kind"] == "timer":
                self.assertEqual(
                    "ACCEPTED", transcript.accept_timer(entry["timer_event"])
                )
                runner.base_context["authoritative_time"] = entry["timer_event"][
                    "new_authoritative_time"
                ]
                continue
            message = entry["message"]
            if message["message_type"] == message_type and (
                actor is None or message["sender"]["actor"] == actor
            ):
                return runner, transcript, copy.deepcopy(message)
            self.assertEqual(
                [], runner.apply(message, self.registry, self.materials), message_type
            )
            self.assertEqual("ACCEPTED", transcript.accept_message(message))
        self.fail(f"trace message not found: {message_type} {actor}")

    def assert_runner_rejects_without_mutation(
        self, runner: validator.AbstractStateRunner, message: dict
    ) -> None:
        transcript = validator.TranscriptState(head=message["prior_transcript_digest"])
        before_runner = copy.deepcopy(runner.__dict__)
        before_transcript = copy.deepcopy(transcript.__dict__)
        outcome, findings = validator.apply_trace_message_atomically(
            runner, transcript, message, self.registry, self.materials
        )
        self.assertEqual("REJECTED", outcome)
        self.assertIn("state-trace", {item.code for item in findings})
        self.assertEqual(before_runner, runner.__dict__)
        self.assertEqual(before_transcript, transcript.__dict__)

    def test_repository_message_contract_is_valid(self) -> None:
        self.assertEqual([], validator.validate_repository(ROOT))

    def test_all_json_schemas_are_valid_draft_2020_12(self) -> None:
        for schema in (
            self.message_schema,
            self.timer_schema,
            self.registry_schema,
            self.material_schema,
        ):
            Draft202012Validator.check_schema(schema)
            self.assertEqual(
                "https://json-schema.org/draft/2020-12/schema", schema["$schema"]
            )

    def test_registry_is_unique_and_fail_closed(self) -> None:
        entries = self.registry["messages"]
        names = [entry["message_type"] for entry in entries]
        self.assertEqual(18, len(names))
        self.assertEqual(len(names), len(set(names)))
        self.assertEqual("fail-closed", self.registry["unknown_type_behavior"])
        self.assertTrue(all(entry["message_version"] == "0.1" for entry in entries))

    def test_required_message_types_are_registered(self) -> None:
        expected = {
            "session_proposal",
            "session_acceptance",
            "participant_binding",
            "policy_acceptance",
            "commitment_registration",
            "query_budget_reservation",
            "evaluation_start",
            "evaluation_contribution",
            "opaque_receipt_ack",
            "result_acceptance_notice",
            "consent_grant",
            "consent_withdrawal",
            "disclosure_extension_authorization",
            "disclosure_completion_notice",
            "abort_notice",
            "normalized_error_notice",
            "close_notice",
            "expiry_notice",
        }
        self.assertEqual(expected, set(validator._registry_index(self.registry)))

    def test_every_state_delivery_event_has_a_contract(self) -> None:
        state = strict_yaml_load(
            (ROOT / validator.STATE_MACHINE_PATH).read_text(encoding="utf-8")
        )
        self.assertEqual(
            [],
            validator.registry_findings(self.registry, state, self.message_schema),
        )

    def test_registry_parameter_sources_cover_every_required_field(self) -> None:
        state = strict_yaml_load(
            (ROOT / validator.STATE_MACHINE_PATH).read_text(encoding="utf-8")
        )
        mutated = copy.deepcopy(self.registry)
        mutated["messages"][0]["parameter_sources"].pop(0)
        findings = validator.registry_findings(
            mutated,
            state,
            self.message_schema,
        )
        self.assertIn("parameter-mapping", {item.code for item in findings})

    def test_registry_destinations_are_machine_checked(self) -> None:
        state = strict_yaml_load(
            (ROOT / validator.STATE_MACHINE_PATH).read_text(encoding="utf-8")
        )
        cases = {}
        typo = copy.deepcopy(self.registry)
        typo["messages"][0]["parameter_sources"][0]["destination"]["field"] = (
            "proposal_typo"
        )
        cases["destination typo"] = typo
        wrong_parameter = copy.deepcopy(self.registry)
        wrong_parameter["messages"][0]["parameter_sources"][0]["destination"][
            "parameter"
        ] = "session_acceptance_parameter"
        cases["wrong parameter"] = wrong_parameter
        wrong_transition = copy.deepcopy(self.registry)
        wrong_transition["messages"][0]["parameter_sources"][0]["destination"][
            "consumed_by"
        ][0]["transition"] = "TR-CLOSE"
        cases["wrong transition"] = wrong_transition
        unused = copy.deepcopy(self.registry)
        unused["messages"][0]["parameter_sources"][0]["destination"]["consumed_by"][0][
            "operation"
        ] = "E-AUDIT"
        cases["mapped but unused"] = unused
        duplicate = copy.deepcopy(self.registry)
        duplicate["messages"][0]["parameter_sources"][1]["destination"] = copy.deepcopy(
            duplicate["messages"][0]["parameter_sources"][0]["destination"]
        )
        cases["duplicate destination"] = duplicate
        for name, mutated in cases.items():
            with self.subTest(name=name):
                findings = validator.registry_findings(
                    mutated, state, self.message_schema
                )
                self.assertIn(
                    "parameter-mapping-destination",
                    {item.code for item in findings},
                )

    def test_security_runner_mapping_cannot_be_disconnected(self) -> None:
        state = strict_yaml_load(
            (ROOT / validator.STATE_MACHINE_PATH).read_text(encoding="utf-8")
        )
        mutated = copy.deepcopy(self.registry)
        acceptance = next(
            item
            for item in mutated["messages"]
            if item["message_type"] == "session_acceptance"
        )
        acceptance["parameter_sources"] = [
            item
            for item in acceptance["parameter_sources"]
            if item["source"]
            != "trusted.authenticated_subject.verification_material_id"
        ]
        findings = validator.registry_findings(mutated, state, self.message_schema)
        self.assertIn("state-runner-mapping", {item.code for item in findings})

    def test_semantic_registry_ids_are_duplicate_rejecting(self) -> None:
        state = strict_yaml_load(
            (ROOT / validator.STATE_MACHINE_PATH).read_text(encoding="utf-8")
        )
        duplicate_message = copy.deepcopy(self.registry)
        duplicate_message["messages"].append(
            copy.deepcopy(duplicate_message["messages"][0])
        )
        self.assertIn(
            "registry-duplicate",
            {
                item.code
                for item in validator.registry_findings(
                    duplicate_message, state, self.message_schema
                )
            },
        )
        duplicate_internal = copy.deepcopy(self.registry)
        duplicate_internal["internal_event_contracts"].append(
            copy.deepcopy(duplicate_internal["internal_event_contracts"][0])
        )
        self.assertIn(
            "registry-duplicate",
            {
                item.code
                for item in validator.registry_findings(
                    duplicate_internal, state, self.message_schema
                )
            },
        )
        for field in ("verification_material_id", "subject_binding_id"):
            duplicate_material = copy.deepcopy(self.materials)
            duplicate = copy.deepcopy(duplicate_material["materials"][1])
            duplicate[field] = duplicate_material["materials"][0][field]
            duplicate_material["materials"].append(duplicate)
            self.assertIn(
                "material-duplicate",
                {
                    item.code
                    for item in validator.material_registry_findings(duplicate_material)
                },
                field,
            )

    def test_strict_yaml_rejects_duplicate_mapping_keys(self) -> None:
        with self.assertRaises(yaml.YAMLError):
            strict_yaml_load("schema_version: '0.1'\nschema_version: '0.1'\n")
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            path = Path(directory) / "duplicate.yaml"
            path.write_text("schema_version: '0.1'\nschema_version: '0.1'\n")
            value, findings = validator._load_yaml(path)
        self.assertIsNone(value)
        self.assertEqual(["yaml-parse"], [item.code for item in findings])
        self.assertLessEqual(len(findings[0].message), 320)
        self.assertNotIn("Traceback", findings[0].message)

    def test_registry_and_payload_schema_cannot_drift(self) -> None:
        state = strict_yaml_load(
            (ROOT / validator.STATE_MACHINE_PATH).read_text(encoding="utf-8")
        )
        mutated = copy.deepcopy(self.message_schema)
        mutated["$defs"]["payload_session_proposal"]["required"].remove("clock_policy")
        findings = validator.registry_findings(self.registry, state, mutated)
        self.assertIn("registry-schema-mapping", {item.code for item in findings})

    def test_timer_derived_and_local_relations_are_not_party_inputs(self) -> None:
        internal = {
            item["id"]: item for item in self.registry["internal_event_contracts"]
        }
        self.assertEqual(
            {
                "authoritative_timer_event",
                "reject_message_relation",
                "new_session_guidance",
            },
            set(internal),
        )
        self.assertTrue(
            all(not item["external_party_message"] for item in internal.values())
        )

    def test_positive_vectors_are_canonical_and_valid(self) -> None:
        self.assertGreaterEqual(len(self.valid_paths), 26)
        for path in self.valid_paths:
            raw = path.read_bytes()
            parsed = canonical.strict_loads(raw)
            stage_context = copy.deepcopy(self.context)
            stage_context["session_context"] = copy.deepcopy(parsed["session_context"])
            stage_context["prior_transcript_digest"] = parsed["prior_transcript_digest"]
            message, findings = validator.validate_message_bytes(
                raw,
                self.message_schema,
                self.registry,
                self.materials,
                stage_context,
                path=path.name,
            )
            self.assertEqual([], findings, path.name)
            self.assertEqual(raw, canonical.canonicalize(message), path.name)

    def test_positive_vectors_cover_both_parties(self) -> None:
        for prefix in (
            "session-acceptance",
            "participant-binding",
            "policy-acceptance",
            "commitment-registration",
            "evaluation-contribution",
            "opaque-receipt-ack",
            "consent-grant",
            "consent-withdrawal",
        ):
            self.assertIn(f"{prefix}-a", self.messages)
            self.assertIn(f"{prefix}-b", self.messages)

    def test_all_negative_vector_expectations_are_observed(self) -> None:
        manifest = strict_yaml_load(
            (ROOT / validator.INVALID_MANIFEST).read_text(encoding="utf-8")
        )
        self.assertGreaterEqual(len(manifest["cases"]), 30)
        for case in manifest["cases"]:
            path = ROOT / "conformance/messages/invalid" / case["file"]
            invalid_context = copy.deepcopy(self.context)
            context_reference = canonical.strict_loads(
                (
                    ROOT / "conformance/messages/valid" / case["context_file"]
                ).read_bytes()
            )
            invalid_context["session_context"] = copy.deepcopy(
                context_reference["session_context"]
            )
            invalid_context["prior_transcript_digest"] = context_reference[
                "prior_transcript_digest"
            ]
            _, findings = validator.validate_message_bytes(
                path.read_bytes(),
                self.message_schema,
                self.registry,
                self.materials,
                invalid_context,
                path=case["file"],
            )
            self.assertIn(case["expected_code"], {item.code for item in findings})

    def test_authentication_subject_negative_vectors_are_present(self) -> None:
        manifest = strict_yaml_load(
            (ROOT / validator.INVALID_MANIFEST).read_text(encoding="utf-8")
        )
        identifiers = {item["id"] for item in manifest["cases"]}
        self.assertTrue(
            {
                "same-role-other-active-key",
                "authentication-sender-key-mismatch",
                "material-participant-mismatch",
                "profile-material-instance-mismatch",
                "coordinator-material-for-party",
                "party-a-material-for-party-b",
            }.issubset(identifiers)
        )

    def test_material_validity_uses_issued_and_authoritative_time(self) -> None:
        base = self.messages["session-acceptance-a"]
        stage = copy.deepcopy(self.context)
        stage["session_context"] = copy.deepcopy(base["session_context"])
        stage["prior_transcript_digest"] = base["prior_transcript_digest"]

        def findings_for(not_before: str, not_after: str, authoritative: str):
            materials = copy.deepcopy(self.materials)
            material = next(
                item
                for item in materials["materials"]
                if item["verification_material_id"]
                == base["authentication"]["verification_material_id"]
            )
            material["not_before"] = not_before
            material["not_after"] = not_after
            local_context = copy.deepcopy(stage)
            local_context["authoritative_time"] = authoritative
            return validator.semantic_message_findings(
                base, self.registry, materials, local_context
            )

        self.assertEqual(
            [],
            findings_for(
                base["issued_at"],
                "2026-07-21T00:01:00Z",
                "2026-07-21T00:00:30Z",
            ),
        )
        for name, before, after, authoritative in (
            (
                "issued before not_before",
                "2026-07-21T00:00:01Z",
                "2026-07-21T00:01:00Z",
                "2026-07-21T00:00:30Z",
            ),
            (
                "issued at not_after",
                "2026-07-20T23:59:00Z",
                base["issued_at"],
                "2026-07-20T23:59:30Z",
            ),
            (
                "authoritative at not_after",
                "2026-07-20T23:59:00Z",
                "2026-07-21T00:00:30Z",
                "2026-07-21T00:00:30Z",
            ),
        ):
            with self.subTest(name=name):
                self.assertIn(
                    "verification-material",
                    {item.code for item in findings_for(before, after, authoritative)},
                )

    def test_positive_transcript_is_an_evolving_state_trace(self) -> None:
        expected = canonical.strict_loads(
            (ROOT / validator.EXPECTED_DIGESTS).read_bytes()
        )
        state = validator.TranscriptState()
        runner = validator.AbstractStateRunner(copy.deepcopy(self.context))
        seen = []
        for entry in expected["entries"]:
            if entry["kind"] == "timer":
                self.assertEqual("ACCEPTED", state.accept_timer(entry["timer_event"]))
                runner.base_context["authoritative_time"] = entry["timer_event"][
                    "new_authoritative_time"
                ]
                continue
            message = entry["message"]
            stage = runner.context(state.head)
            self.assertEqual(
                [],
                validator.semantic_message_findings(
                    message, self.registry, self.materials, stage
                ),
            )
            self.assertEqual([], runner.apply(message, self.registry, self.materials))
            self.assertEqual("ACCEPTED", state.accept_message(message))
            seen.append(message["message_type"])
        self.assertLess(
            seen.index("session_acceptance"), seen.index("participant_binding")
        )
        self.assertEqual(2, seen.count("session_acceptance"))
        self.assertEqual(2, seen.count("participant_binding"))
        self.assertEqual("CLOSED", runner.phase)

    def test_session_acceptance_subject_must_equal_later_party_binding(self) -> None:
        runner, _, binding = self.runner_before("participant_binding", "party_a_client")
        self.assertEqual(
            "urn:private-match:test:key:party-a:v0.1",
            runner.session_acceptance["a"]["key_id"],
        )
        self.assertEqual(
            [], runner.apply(copy.deepcopy(binding), self.registry, self.materials)
        )

        runner, _, changed = self.runner_before("participant_binding", "party_a_client")
        changed["sender"]["key_id"] = "urn:private-match:test:key:party-a:other:v0.1"
        changed["payload"]["participant_key_id"] = changed["sender"]["key_id"]
        changed["authentication"].update(
            {
                "key_id": changed["sender"]["key_id"],
                "verification_material_id": "urn:private-match:test:material:party-a-other-key:v0.1",
            }
        )
        changed = canonical.populate_digests(changed)
        self.assert_runner_rejects_without_mutation(runner, changed)

    def test_same_key_with_different_participant_cannot_reuse_acceptance(self) -> None:
        runner, _, changed = self.runner_before("participant_binding", "party_a_client")
        other = "urn:private-match:test:participant:other"
        changed["sender"]["participant_id"] = other
        changed["identity"]["sender_participant_id"] = other
        changed["payload"]["participant_id"] = other
        changed["authentication"]["verification_material_id"] = (
            "urn:private-match:test:material:party-a-wrong-participant:v0.1"
        )
        changed = canonical.populate_digests(changed)
        self.assert_runner_rejects_without_mutation(runner, changed)

    def test_party_a_acceptance_cannot_authorize_party_b_binding(self) -> None:
        runner = validator.AbstractStateRunner(copy.deepcopy(self.context))
        proposal = copy.deepcopy(self.trace_messages[0])
        acceptance_a = copy.deepcopy(self.trace_messages[1])
        binding_b = next(
            copy.deepcopy(item)
            for item in self.trace_messages
            if item["message_type"] == "participant_binding"
            and item["sender"]["actor"] == "party_b_client"
        )
        self.assertEqual([], runner.apply(proposal, self.registry, self.materials))
        self.assertEqual([], runner.apply(acceptance_a, self.registry, self.materials))
        binding_b["identity"]["sequence"] = runner.next_sequence["b"]
        binding_b = canonical.populate_digests(binding_b)
        self.assert_runner_rejects_without_mutation(runner, binding_b)

    def test_exact_duplicate_session_acceptance_is_transcript_idempotent(self) -> None:
        acceptance = copy.deepcopy(self.expected["duplicate_vectors"]["party_exact"])
        state = validator.TranscriptState(head=acceptance["prior_transcript_digest"])
        self.assertEqual("ACCEPTED", state.accept_message(acceptance))
        before = (state.head, state.accepted_event_index)
        self.assertEqual(
            "EXACT_DUPLICATE", state.accept_message(copy.deepcopy(acceptance))
        )
        self.assertEqual(before, (state.head, state.accepted_event_index))

    def test_commitment_pair_digest_binds_complete_context(self) -> None:
        base = {
            "protocol_profile": "private-match-core/v0.1",
            "policy_binding": copy.deepcopy(self.context["session_context"]["policy"]),
            "session_id": self.context["session_context"]["session_id"],
            "participant_binding": {
                "party_a": {
                    "participant_id": "urn:private-match:test:participant:a",
                    "key_id": "urn:private-match:test:key:party-a:v0.1",
                },
                "party_b": {
                    "participant_id": "urn:private-match:test:participant:b",
                    "key_id": "urn:private-match:test:key:party-b:v0.1",
                },
            },
            "selected_integration_profile_binding": {
                "profile_id": "urn:private-match:test:profile:synthetic",
                "profile_version": "0.1",
                "profile_instance_id": "urn:private-match:test:profile-instance:0001",
            },
            "commitment_a": "urn:private-match:test:opaque-commitment:a",
            "commitment_b": "urn:private-match:test:opaque-commitment:b",
        }
        expected = canonical.commitment_pair_digest(**base)
        self.assertRegex(expected, r"^sha256:[0-9a-f]{64}$")
        mutations = {
            "commitment A": ("commitment_a", "urn:test:changed:a"),
            "commitment B": ("commitment_b", "urn:test:changed:b"),
            "session": ("session_id", "urn:test:session:changed"),
            "policy": (
                "policy_binding",
                {"policy_id": "urn:test:policy:other", "policy_version": "0.1"},
            ),
            "participants": (
                "participant_binding",
                {
                    **base["participant_binding"],
                    "party_b": {
                        "participant_id": "urn:test:participant:changed",
                        "key_id": "urn:private-match:test:key:party-b:v0.1",
                    },
                },
            ),
            "profile": (
                "selected_integration_profile_binding",
                {
                    **base["selected_integration_profile_binding"],
                    "profile_instance_id": "urn:test:profile-instance:changed",
                },
            ),
        }
        for name, (field, value) in mutations.items():
            with self.subTest(name=name):
                changed = copy.deepcopy(base)
                changed[field] = value
                self.assertNotEqual(
                    expected, canonical.commitment_pair_digest(**changed)
                )

    def test_commitment_pair_is_derived_once_in_canonical_party_order(self) -> None:
        runner, _, commitment_a = self.runner_before(
            "commitment_registration", "party_a_client"
        )
        commitment_b = next(
            copy.deepcopy(item)
            for item in self.trace_messages
            if item["message_type"] == "commitment_registration"
            and item["sender"]["actor"] == "party_b_client"
        )
        reverse = copy.deepcopy(runner)

        self.assertEqual([], runner.apply(commitment_a, self.registry, self.materials))
        self.assertIsNone(runner.commitment_pair_id)
        self.assertEqual([], runner.apply(commitment_b, self.registry, self.materials))
        forward_digest = runner.commitment_pair_id

        self.assertEqual([], reverse.apply(commitment_b, self.registry, self.materials))
        self.assertIsNone(reverse.commitment_pair_id)
        self.assertEqual([], reverse.apply(commitment_a, self.registry, self.materials))
        self.assertEqual(forward_digest, reverse.commitment_pair_id)
        self.assertRegex(forward_digest, r"^sha256:[0-9a-f]{64}$")

        changed = copy.deepcopy(commitment_a)
        changed["payload"]["opaque_commitment"] = "urn:test:commitment:mutated"
        changed = canonical.populate_digests(changed)
        self.assert_runner_rejects_without_mutation(runner, changed)

    def test_party_supplied_commitment_pair_identifier_is_rejected(self) -> None:
        message = copy.deepcopy(self.messages["commitment-registration-a"])
        message["payload"]["commitment_pair_id"] = "sha256:" + "a" * 64
        findings = validator._schema_findings(
            message, self.message_schema, "commitment-registration"
        )
        self.assertIn("schema", {item.code for item in findings})
        manifest = strict_yaml_load(
            (ROOT / validator.INVALID_MANIFEST).read_text(encoding="utf-8")
        )
        self.assertIn(
            "party-supplied-commitment-pair-id",
            {item["id"] for item in manifest["cases"]},
        )

    def test_policy_acceptance_executes_exact_binding_guard_atomically(self) -> None:
        runner, _, policy = self.runner_before("policy_acceptance", "party_a_client")
        for field, value in (
            ("policy_id", "urn:test:policy:other"),
            ("policy_version", "9.9"),
        ):
            with self.subTest(field=field):
                changed = copy.deepcopy(policy)
                changed["payload"][field] = value
                changed = canonical.populate_digests(changed)
                self.assert_runner_rejects_without_mutation(
                    copy.deepcopy(runner), changed
                )

    def test_receipt_guards_require_contributions_status_and_equal_refs(self) -> None:
        runner, _, contribution_b = self.runner_before(
            "evaluation_contribution", "party_b_client"
        )
        receipt_a = next(
            copy.deepcopy(item)
            for item in self.trace_messages
            if item["message_type"] == "opaque_receipt_ack"
            and item["sender"]["actor"] == "party_a_client"
        )
        self.assert_runner_rejects_without_mutation(runner, receipt_a)
        self.assertEqual(
            [], runner.apply(contribution_b, self.registry, self.materials)
        )
        self.assertEqual([], runner.apply(receipt_a, self.registry, self.materials))

        receipt_b = next(
            copy.deepcopy(item)
            for item in self.trace_messages
            if item["message_type"] == "opaque_receipt_ack"
            and item["sender"]["actor"] == "party_b_client"
        )
        wrong_ref = copy.deepcopy(receipt_b)
        wrong_ref["payload"]["opaque_receipt_ref"] = "urn:test:receipt:other"
        wrong_ref = canonical.populate_digests(wrong_ref)
        self.assert_runner_rejects_without_mutation(runner, wrong_ref)

        wrong_status = copy.deepcopy(receipt_b)
        wrong_status["payload"]["acknowledgment_status"] = "BOTH_ACKNOWLEDGED"
        wrong_status = canonical.populate_digests(wrong_status)
        self.assert_runner_rejects_without_mutation(runner, wrong_status)

    def test_result_callback_requires_bilateral_matching_acknowledgments(self) -> None:
        runner, _, receipt_a = self.runner_before(
            "opaque_receipt_ack", "party_a_client"
        )
        callback = next(
            copy.deepcopy(item)
            for item in self.trace_messages
            if item["message_type"] == "result_acceptance_notice"
        )
        self.assert_runner_rejects_without_mutation(runner, callback)
        self.assertEqual([], runner.apply(receipt_a, self.registry, self.materials))
        receipt_b = next(
            copy.deepcopy(item)
            for item in self.trace_messages
            if item["message_type"] == "opaque_receipt_ack"
            and item["sender"]["actor"] == "party_b_client"
        )
        self.assertEqual([], runner.apply(receipt_b, self.registry, self.materials))
        for field, value in (
            ("opaque_receipt_ref", "urn:test:receipt:other"),
            ("acknowledgment_status", "ACKNOWLEDGED"),
        ):
            with self.subTest(field=field):
                changed = copy.deepcopy(callback)
                changed["payload"][field] = value
                changed = canonical.populate_digests(changed)
                self.assert_runner_rejects_without_mutation(
                    copy.deepcopy(runner), changed
                )
        for field, value in (
            ("profile_instance_id", "urn:test:profile-instance:other"),
            ("session_id", "urn:test:session:other"),
            ("evaluation_attempt_id", "urn:test:attempt:other"),
        ):
            with self.subTest(identity_field=field):
                changed = copy.deepcopy(callback)
                changed["identity"][field] = value
                changed = canonical.populate_digests(changed)
                self.assert_runner_rejects_without_mutation(
                    copy.deepcopy(runner), changed
                )
        self.assertEqual([], runner.apply(callback, self.registry, self.materials))

    def test_consent_guard_executes_receipt_profile_scope_audience_and_time(
        self,
    ) -> None:
        runner, _, consent_a = self.runner_before("consent_grant", "party_a_client")
        self.assertEqual([], runner.apply(consent_a, self.registry, self.materials))
        consent_b = next(
            copy.deepcopy(item)
            for item in self.trace_messages
            if item["message_type"] == "consent_grant"
            and item["sender"]["actor"] == "party_b_client"
        )
        mutations = {
            "receipt": ("opaque_receipt_ref", "urn:test:receipt:other"),
            "profile id": ("disclosure_profile_id", "urn:test:profile:other"),
            "profile version": ("disclosure_profile_version", "9.9"),
            "scope": ("scope", ["urn:test:scope:other"]),
            "audience": ("audience", ["party_b_client"]),
            "expired": ("expires_at", "2026-07-21T00:00:20Z"),
        }
        for name, (field, value) in mutations.items():
            with self.subTest(name=name):
                changed = copy.deepcopy(consent_b)
                changed["payload"][field] = value
                changed = canonical.populate_digests(changed)
                self.assert_runner_rejects_without_mutation(
                    copy.deepcopy(runner), changed
                )
        self.assertEqual([], runner.apply(consent_b, self.registry, self.materials))

    def test_future_state_context_and_binding_bypass_fail_closed(self) -> None:
        expected = canonical.strict_loads(
            (ROOT / validator.EXPECTED_DIGESTS).read_bytes()
        )
        messages = [
            entry["message"]
            for entry in expected["entries"]
            if entry["kind"] == "message"
        ]
        proposal = messages[0]
        self.assertIsNone(proposal["session_context"]["selected_integration_profile"])
        self.assertIsNotNone(proposal["payload"]["selected_integration_profile"])
        acceptance_a = messages[1]
        self.assertEqual(
            proposal["payload"]["selected_integration_profile"],
            acceptance_a["session_context"]["selected_integration_profile"],
        )
        binding_a = next(
            item
            for item in messages
            if item["message_type"] == "participant_binding"
            and item["sender"]["actor"] == "party_a_client"
        )
        runner = validator.AbstractStateRunner(copy.deepcopy(self.context))
        self.assertEqual([], runner.apply(proposal, self.registry, self.materials))
        bypass = copy.deepcopy(runner)
        self.assertIn(
            "state-trace",
            {
                item.code
                for item in bypass.apply(binding_a, self.registry, self.materials)
            },
        )
        self.assertEqual([], runner.apply(acceptance_a, self.registry, self.materials))
        wrong_proposal = copy.deepcopy(messages[2])
        wrong_proposal["payload"]["proposal_digest"] = "sha256:" + "f" * 64
        self.assertIn(
            "state-trace",
            {
                item.code
                for item in runner.apply(wrong_proposal, self.registry, self.materials)
            },
        )
        for field, value in (
            ("commitment_pair_id", "urn:private-match:test:commitment-pair:future"),
            ("evaluation_attempt_id", "urn:private-match:test:evaluation:future"),
        ):
            changed = copy.deepcopy(acceptance_a)
            changed["session_context"][field] = value
            changed = canonical.populate_digests(changed)
            self.assertIn(
                "context-binding",
                {
                    item.code
                    for item in validator.semantic_message_findings(
                        changed,
                        self.registry,
                        self.materials,
                        validator.AbstractStateRunner(
                            copy.deepcopy(self.context)
                        ).context(changed["prior_transcript_digest"]),
                    )
                },
            )
        future_profile = copy.deepcopy(proposal)
        future_profile["session_context"]["selected_integration_profile"] = (
            copy.deepcopy(proposal["payload"]["selected_integration_profile"])
        )
        future_profile = canonical.populate_digests(future_profile)
        self.assertIn(
            "context-binding",
            {
                item.code
                for item in validator.semantic_message_findings(
                    future_profile,
                    self.registry,
                    self.materials,
                    validator.AbstractStateRunner(copy.deepcopy(self.context)).context(
                        future_profile["prior_transcript_digest"]
                    ),
                )
            },
        )

    def test_duplicate_json_key_is_rejected_before_object_construction(self) -> None:
        with self.assertRaises(canonical.DuplicateJSONKeyError):
            canonical.strict_loads(b'{"a":1,"a":2}')

    def test_nan_and_infinity_are_rejected(self) -> None:
        for raw in (b'{"n":NaN}', b'{"n":Infinity}', b'{"n":-Infinity}'):
            with self.assertRaises(canonical.CanonicalMessageError):
                canonical.strict_loads(raw)

    def test_negative_zero_is_rejected_for_integer_float_and_programmatic_input(
        self,
    ) -> None:
        for raw in (b'{"n":-0}', b'{"n":-0.0}', b'{"n":-0e0}'):
            with self.assertRaises(canonical.CanonicalMessageError):
                canonical.strict_loads(raw)
        with self.assertRaises(canonical.CanonicalMessageError):
            canonical.canonicalize({"n": -0.0})

    def test_rfc_8785_appendix_b_number_vectors(self) -> None:
        samples = {
            "0000000000000000": b"0",
            "0000000000000001": b"5e-324",
            "8000000000000001": b"-5e-324",
            "7fefffffffffffff": b"1.7976931348623157e+308",
            "ffefffffffffffff": b"-1.7976931348623157e+308",
            "44b52d02c7e14af6": b"1e+23",
            "3eb0c6f7a0b5ed8d": b"0.000001",
            "43143ff3c1cb0959": b"1424953923781206.2",
        }
        for hexadecimal, expected in samples.items():
            value = struct.unpack(">d", bytes.fromhex(hexadecimal))[0]
            self.assertEqual(expected, canonical.canonicalize(value))

    def test_rfc_8785_canonical_sample(self) -> None:
        value = {
            "numbers": [333333333.33333329, 1e30, 4.50, 2e-3, 1e-27],
            "string": '€$\u000f\nA\'B"\\\\"/',
            "literals": [None, True, False],
        }
        expected = (
            b'{"literals":[null,true,false],"numbers":[333333333.3333333,'
            b'1e+30,4.5,0.002,1e-27],"string":"\xe2\x82\xac$\\u000f\\nA\'B\\"\\\\\\\\\\"/"}'
        )
        self.assertEqual(expected, canonical.canonicalize(value))

    def test_unicode_is_preserved_without_normalization(self) -> None:
        nfc = unicodedata.normalize("NFC", "Cafe\u0301")
        nfd = unicodedata.normalize("NFD", nfc)
        self.assertNotEqual(canonical.canonicalize(nfc), canonical.canonicalize(nfd))
        self.assertNotEqual(
            canonical.payload_digest(nfc), canonical.payload_digest(nfd)
        )

    def test_lone_unicode_surrogate_is_a_bounded_parse_error(self) -> None:
        with self.assertRaisesRegex(
            canonical.CanonicalMessageError,
            "lone Unicode surrogate",
        ):
            canonical.strict_loads('"\ud800"')

    def test_key_order_and_whitespace_do_not_change_canonical_digest(self) -> None:
        first = canonical.strict_loads(b'{"b":2,"a":1}')
        second = canonical.strict_loads(b'{ "a" : 1, "b" : 2 }')
        self.assertEqual(canonical.canonicalize(first), canonical.canonicalize(second))
        self.assertEqual(
            canonical.payload_digest(first), canonical.payload_digest(second)
        )

    def test_payload_change_changes_payload_and_message_digest(self) -> None:
        message = self.messages["session-acceptance-a"]
        changed = copy.deepcopy(message)
        changed["payload"]["acceptance_digest"] = "sha256:" + "a" * 64
        changed = canonical.populate_digests(changed)
        self.assertNotEqual(message["payload_digest"], changed["payload_digest"])
        self.assertNotEqual(message["message_digest"], changed["message_digest"])

    def test_every_authenticated_routing_field_changes_message_digest(self) -> None:
        base = self.messages["session-acceptance-a"]
        mutations = {
            "protocol_version": lambda m: m.__setitem__("protocol_version", "9.9"),
            "message_type": lambda m: m.__setitem__(
                "message_type", "participant_binding"
            ),
            "session": lambda m: m["session_context"].__setitem__(
                "session_id", "urn:private-match:test:session:other"
            ),
            "policy": lambda m: m["session_context"]["policy"].__setitem__(
                "policy_id", "urn:private-match:test:policy:other"
            ),
            "audience": lambda m: m.__setitem__("audience", ["party_b_client"]),
            "sequence": lambda m: m["identity"].__setitem__("sequence", 99),
            "nonce": lambda m: m["identity"].__setitem__(
                "nonce", "urn:private-match:test:nonce:other"
            ),
            "prior": lambda m: m.__setitem__(
                "prior_transcript_digest", "sha256:" + "f" * 64
            ),
            "algorithm": lambda m: m["authentication"].__setitem__(
                "algorithm_id", "urn:private-match:test:algorithm:other"
            ),
            "key": lambda m: m["authentication"].__setitem__(
                "key_id", "urn:private-match:test:key:other"
            ),
            "material": lambda m: m["authentication"].__setitem__(
                "verification_material_id", "urn:private-match:test:material:other"
            ),
        }
        for name, mutate in mutations.items():
            changed = copy.deepcopy(base)
            mutate(changed)
            self.assertNotEqual(
                base["message_digest"], canonical.message_digest(changed), name
            )

    def test_authentication_value_is_the_only_authentication_field_excluded(
        self,
    ) -> None:
        message = self.messages["session-acceptance-a"]
        changed = copy.deepcopy(message)
        changed["authentication"]["value"] = "DIFFERENT-SYNTHETIC-VALUE"
        self.assertEqual(message["message_digest"], canonical.message_digest(changed))
        auth_input = canonical.authentication_input(message)
        self.assertNotIn("value", auth_input["authentication"])
        self.assertNotIn("message_digest", auth_input)
        self.assertNotIn("payload", auth_input)

    def test_coordinator_receipts_never_contain_plaintext_outcome_or_secret_input(
        self,
    ) -> None:
        for name in (
            "opaque-receipt-ack-a",
            "opaque-receipt-ack-b",
            "result-acceptance-notice",
        ):
            message = self.messages[name]
            self.assertEqual([], validator._walk_prohibited(message))
            self.assertEqual([], validator._walk_plaintext_result(message))
            rendered = canonical.canonicalize(message)
            for token in (b'"MATCH"', b'"NO_MATCH"', b'"INDETERMINATE"'):
                self.assertNotIn(token, rendered)

    def test_core_messages_never_contain_actual_disclosure_payload(self) -> None:
        for message in self.messages.values():
            self.assertNotIn(
                b"actual_disclosure_payload", canonical.canonicalize(message)
            )

    def test_party_error_notice_contains_category_not_raw_failure(self) -> None:
        notice = self.messages["normalized-error-notice"]
        self.assertIn("party_error_category", notice["payload"])
        self.assertNotIn("failure_code", notice["payload"])
        self.assertNotIn("internal_failure_code", notice["payload"])

    def test_unknown_expired_and_revoked_material_fail_closed(self) -> None:
        manifest = strict_yaml_load(
            (ROOT / validator.INVALID_MANIFEST).read_text(encoding="utf-8")
        )
        ids = {item["id"] for item in manifest["cases"]}
        self.assertTrue(
            {
                "unknown-verification-material",
                "expired-verification-material",
                "revoked-verification-material",
            }.issubset(ids)
        )

    def test_rfc8785_dependency_is_exact_and_hash_locked(self) -> None:
        direct = (ROOT / "requirements-dev.in").read_text(encoding="utf-8")
        lock = (ROOT / "requirements-dev.txt").read_text(encoding="utf-8")
        self.assertIn("rfc8785==0.1.4", direct)
        self.assertIn("rfc8785==0.1.4", lock)
        self.assertIn(
            "520d690b448ecf0703691c76e1a34a24ddcd4fc5bc41d589cb7c58ec651bcd48",
            lock,
        )

    def test_workflow_preserves_minimum_permissions_and_supply_chain_controls(
        self,
    ) -> None:
        workflow = (ROOT / ".github/workflows/protocol-spec.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("permissions:\n  contents: read", workflow)
        self.assertIn("persist-credentials: false", workflow)
        self.assertIn("runs-on: ubuntu-24.04", workflow)
        self.assertIn("python-version: '3.12.11'", workflow)
        self.assertIn("pip install --require-hashes", workflow)
        self.assertIn("generate_message_vectors.py --root . --check", workflow)
        self.assertIn("validate_messages.py --root .", workflow)
        self.assertNotIn("upload-artifact", workflow)
        self.assertNotIn("deploy", workflow.lower())
        for line in workflow.splitlines():
            if "uses:" not in line:
                continue
            reference = line.split("@", 1)[1].split()[0]
            self.assertRegex(reference, r"^[0-9a-f]{40}$")
            self.assertRegex(line, r"# v\d")

    def test_cli_parse_failure_is_bounded_without_traceback(self) -> None:
        path = ROOT / "conformance/messages/invalid/duplicate-json-key.json"
        result = subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts/validate_messages.py"),
                "--root",
                str(ROOT),
                "--file",
                str(path),
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(1, result.returncode)
        self.assertIn("json-parse", result.stdout)
        self.assertNotIn("Traceback", result.stdout + result.stderr)

    def test_canonicalizer_cli_emits_exact_jcs_bytes_without_delimiter(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            path = Path(directory) / "input.json"
            path.write_bytes(b'{ "b": 2, "a": 1 }')
            result = subprocess.run(
                [sys.executable, str(ROOT / "scripts/canonicalize_message.py"), path],
                check=False,
                capture_output=True,
            )
        self.assertEqual(0, result.returncode)
        self.assertEqual(b'{"a":1,"b":2}', result.stdout)
        self.assertEqual(b"", result.stderr)


if __name__ == "__main__":
    unittest.main()
