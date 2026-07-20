from __future__ import annotations

import contextlib
import copy
import datetime
import io
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import yaml
from jsonschema import Draft202012Validator

from scripts.validate_session_state_machine import (
    ARTIFACT_PATH,
    SCHEMA_PATH,
    NoDatesSafeLoader,
    canonical_digest,
    disclosure_authorization_guard_failures,
    load_json,
    load_yaml,
    main,
    schema_findings,
    semantic_findings,
    validate,
)


ROOT = Path(__file__).resolve().parents[1]


class SessionStateMachineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.model, load_errors = load_yaml(ROOT / ARTIFACT_PATH)
        cls.schema, schema_errors = load_json(ROOT / SCHEMA_PATH)
        if load_errors or schema_errors or cls.model is None or cls.schema is None:
            raise AssertionError(load_errors + schema_errors)

    def setUp(self):
        self.model_copy = copy.deepcopy(self.model)

    def transition(self, transition_id, model=None):
        source = model or self.model_copy
        return next(
            item for item in source["transitions"] if item["id"] == transition_id
        )

    def invariant(self, invariant_id, model=None):
        source = model or self.model_copy
        return next(item for item in source["invariants"] if item["id"] == invariant_id)

    def semantic_codes(self, model=None):
        return {finding.code for finding in semantic_findings(model or self.model_copy)}

    def schema_codes(self, model=None):
        return {
            finding.code
            for finding in schema_findings(model or self.model_copy, self.schema)
        }

    def assert_phase_trace(self, transition_ids, expected_phase):
        phase = "UNINITIALIZED"
        for transition_id in transition_ids:
            transition = self.transition(transition_id)
            self.assertIn(phase, transition["from_phase"], transition_id)
            if transition["to_phase"] != "SAME":
                phase = transition["to_phase"]
        self.assertEqual(phase, expected_phase)

    def base_result_trace(self):
        return [
            "TR-CREATE",
            "TR-BIND-A-FIRST",
            "TR-BIND-B-COMPLETE",
            "TR-ACCEPT-POLICY-A",
            "TR-ACCEPT-POLICY-B",
            "TR-RESERVE-BUDGET",
            "TR-COMMIT-A-FIRST",
            "TR-COMMIT-B-COMPLETE",
            "TR-START-EVALUATION",
            "TR-SUBMIT-CONTRIBUTION-A",
            "TR-SUBMIT-CONTRIBUTION-B",
            "TR-ACK-RECEIPT-A",
            "TR-ACK-RECEIPT-B",
            "TR-ACCEPT-SYMMETRIC-RESULT",
        ]

    def synthetic_disclosure_state(self):
        participants = {
            "A": {"participant_id": "fixture-a", "key_id": "fixture-key-a"},
            "B": {"participant_id": "fixture-b", "key_id": "fixture-key-b"},
        }
        state = {
            "phase": "CONSENT_PENDING",
            "accepted_result_state": {"A": "MATCH", "B": "MATCH"},
            "session_id": "fixture-session",
            "participant_binding": participants,
            "opaque_receipt_ref": "fixture-high-entropy-opaque-reference",
            "disclosure_profile_ref": "fixture-disclosure/v0.1",
            "disclosure_scope": ["fixture-field"],
            "intended_audience": ["fixture-a", "fixture-b"],
            "authoritative_time": 100,
            "session_expires_at": 200,
        }
        consent = {
            "status": "valid",
            "session_id": state["session_id"],
            "participant_set": participants,
            "opaque_receipt_ref": state["opaque_receipt_ref"],
            "disclosure_profile_ref": state["disclosure_profile_ref"],
            "scope": state["disclosure_scope"],
            "audience": state["intended_audience"],
            "issued_at": 90,
            "expires_at": 150,
            "consent_nonce": "fixture-consent-nonce",
            "artifact_digest": "a" * 64,
        }
        state["consent"] = {"A": copy.deepcopy(consent), "B": copy.deepcopy(consent)}
        return state

    def test_repository_state_machine_is_valid(self):
        model, findings = validate(ROOT)
        self.assertIsNotNone(model)
        self.assertEqual(findings, [])

    def test_json_schema_is_valid_draft_2020_12(self):
        Draft202012Validator.check_schema(self.schema)

    def test_custom_loader_preserves_safe_loader_global_date_resolution(self):
        document = "created_at: 2026-07-21\n"
        custom_value = yaml.load(document, Loader=NoDatesSafeLoader)["created_at"]
        safe_value = yaml.safe_load(document)["created_at"]
        self.assertEqual(custom_value, "2026-07-21")
        self.assertIsInstance(custom_value, str)
        self.assertEqual(safe_value, datetime.date(2026, 7, 21))

    def test_canonical_digest_is_deterministic(self):
        first = canonical_digest(self.model)
        second = canonical_digest(copy.deepcopy(self.model))
        self.assertEqual(first, second)
        self.assertRegex(first, r"^[0-9a-f]{64}$")

    def test_positive_match_trace_reaches_result_accepted(self):
        self.assert_phase_trace(self.base_result_trace(), "RESULT_ACCEPTED")
        self.assertIn("MATCH", self.model["artifact"]["decision_output"])

    def test_positive_no_match_trace_reaches_result_accepted(self):
        self.assert_phase_trace(self.base_result_trace(), "RESULT_ACCEPTED")
        self.assertIn("NO_MATCH", self.model["artifact"]["decision_output"])

    def test_positive_indeterminate_trace_reaches_result_accepted(self):
        self.assert_phase_trace(self.base_result_trace(), "RESULT_ACCEPTED")
        self.assertIn("INDETERMINATE", self.model["artifact"]["decision_output"])
        self.assertIn(
            "never a disclosure condition",
            self.model["result_acceptance_semantics"]["indeterminate_rule"],
        )

    def test_exact_duplicate_is_no_op_with_prior_response(self):
        for party in ("A", "B"):
            transition = self.transition(f"TR-RETRY-EXACT-DUPLICATE-{party}")
            self.assertFalse(transition["mutating"])
            self.assertEqual(transition["to_phase"], "SAME")
            self.assertEqual(
                [effect["writes"] for effect in transition["effects"]], [[]]
            )
            self.assertIn(
                f"G-EXACT-DUPLICATE-{party}",
                {guard["id"] for guard in transition["guards"]},
            )

    def test_valid_timeout_goes_to_fail_closed_terminal_state(self):
        transition = self.transition("TR-EVALUATION-TIMEOUT")
        self.assertEqual(transition["from_phase"], ["EVALUATING"])
        self.assertEqual(transition["to_phase"], "ABORTED")
        self.assertIn("EVALUATION_TIMEOUT", transition["failure_code"])

    def test_bilateral_consent_artifacts_are_registered_after_result(self):
        for party in ("A", "B"):
            transition = self.transition(f"TR-GRANT-CONSENT-{party}")
            self.assertEqual(
                set(transition["from_phase"]), {"RESULT_ACCEPTED", "CONSENT_PENDING"}
            )
            self.assertIn(
                "G-CONSENT-BINDING", {guard["id"] for guard in transition["guards"]}
            )

    def test_synthetic_reviewed_extension_can_satisfy_authorization_guard(self):
        state = self.synthetic_disclosure_state()
        self.assertEqual(
            disclosure_authorization_guard_failures(state, {"fixture-disclosure/v0.1"}),
            [],
        )

    def test_core_profile_disclosure_completion_is_unreachable(self):
        self.assertEqual(self.model["scope"]["core_disclosure_profile"], "NONE")
        self.assertEqual(
            self.model["scope"]["actual_disclosure_completion"],
            "unreachable in private-match-core/v0.1",
        )
        for transition_id in (
            "TR-AUTHORIZE-DISCLOSURE-EXTENSION",
            "TR-RECORD-DISCLOSURE-COMPLETION",
        ):
            self.assertTrue(self.transition(transition_id)["extension_only"])

    def test_close_and_expiry_are_terminal(self):
        phases = {item["id"]: item for item in self.model["phases"]}
        self.assertTrue(phases["CLOSED"]["terminal"])
        self.assertTrue(phases["EXPIRED"]["terminal"])
        self.assertEqual(self.transition("TR-CLOSE")["to_phase"], "CLOSED")
        self.assertEqual(self.transition("TR-EXPIRE")["to_phase"], "EXPIRED")

    def test_participant_binding_is_required(self):
        invariant = self.invariant("INV-SESSION-BINDING")
        context = next(
            item
            for item in invariant["conditions"]
            if item["id"] == "G-CONTEXT-BINDING"
        )
        context["reads"].remove("participant_binding")
        self.assertIn("session-binding", self.semantic_codes())

    def test_cross_session_substitution_is_rejected(self):
        invariant = self.invariant("INV-SESSION-BINDING")
        context = next(
            item
            for item in invariant["conditions"]
            if item["id"] == "G-CONTEXT-BINDING"
        )
        context["reads"].remove("session_id")
        self.assertIn("session-binding", self.semantic_codes())

    def test_protocol_version_mismatch_is_declared(self):
        invariant = self.invariant("INV-SESSION-BINDING")
        context = next(
            item
            for item in invariant["conditions"]
            if item["id"] == "G-CONTEXT-BINDING"
        )
        context["reads"].remove("protocol_profile")
        self.assertIn("session-binding", self.semantic_codes())

    def test_policy_version_binding_is_required(self):
        invariant = self.invariant("INV-SESSION-BINDING")
        context = next(
            item
            for item in invariant["conditions"]
            if item["id"] == "G-CONTEXT-BINDING"
        )
        context["reads"].remove("policy_binding")
        self.assertIn("session-binding", self.semantic_codes())

    def test_audience_binding_is_required(self):
        invariant = self.invariant("INV-SESSION-BINDING")
        context = next(
            item
            for item in invariant["conditions"]
            if item["id"] == "G-CONTEXT-BINDING"
        )
        context["reads"].remove("intended_audience")
        self.assertIn("session-binding", self.semantic_codes())

    def test_duplicate_nonce_with_altered_payload_is_replay_conflict(self):
        event = next(
            item for item in self.model_copy["events"] if item["id"] == "accept_policy"
        )
        event["duplicate_behavior"] = "accept altered payload"
        self.assertIn("idempotency", self.semantic_codes())

    def test_same_message_id_with_altered_payload_is_replay_conflict(self):
        self.model_copy["replay_and_ordering"]["conflicting_duplicate"] = (
            "accept replacement"
        )
        self.assertIn("idempotency", self.semantic_codes())

    def test_stale_message_does_not_change_state(self):
        self.model_copy["replay_and_ordering"]["stale_sequence"] = (
            "accept stale message"
        )
        self.assertIn("ordering-semantics", self.semantic_codes())

    def test_future_sequence_gap_is_out_of_order_without_buffering(self):
        self.model_copy["replay_and_ordering"]["future_sequence_gap"] = (
            "buffer for later"
        )
        self.assertIn("ordering-semantics", self.semantic_codes())

    def test_out_of_order_failure_is_declared(self):
        self.model_copy["failure_taxonomy"] = [
            item
            for item in self.model_copy["failure_taxonomy"]
            if item["code"] != "OUT_OF_ORDER"
        ]
        self.assertIn("required-set", self.semantic_codes())

    def test_commitment_mutation_after_evaluation_is_rejected(self):
        transition = self.transition("TR-ACK-RECEIPT-A")
        transition["effects"].append(
            {
                "id": "E-ILLEGAL-COMMITMENT-WRITE",
                "operation": "set",
                "writes": ["commitment"],
                "arguments": ["replace A"],
            }
        )
        self.assertIn("commitment-immutability", self.semantic_codes())

    def test_second_accepted_evaluation_guard_is_required(self):
        transition = self.transition("TR-ACCEPT-SYMMETRIC-RESULT")
        transition["guards"] = [
            guard
            for guard in transition["guards"]
            if guard["id"] != "G-ONE-ACCEPTED-EVALUATION"
        ]
        self.assertIn("result-symmetry", self.semantic_codes())

    def test_missing_query_budget_is_rejected(self):
        transition = self.transition("TR-START-EVALUATION")
        transition["guards"] = [
            guard
            for guard in transition["guards"]
            if guard["id"] != "G-BUDGET-RESERVED"
        ]
        self.assertIn("query-budget", self.semantic_codes())

    def test_exhausted_query_budget_failure_is_required(self):
        transition = self.transition("TR-START-EVALUATION")
        transition["failure_code"].remove("QUERY_BUDGET_EXHAUSTED")
        self.assertIn("query-budget", self.semantic_codes())

    def test_missing_verification_material_fails_closed(self):
        transition = self.transition("TR-START-EVALUATION")
        transition["failure_code"].remove("VERIFICATION_MATERIAL_MISSING")
        self.assertIn("query-budget", self.semantic_codes())

    def test_expired_verification_material_fails_closed(self):
        transition = self.transition("TR-START-EVALUATION")
        transition["failure_code"].remove("VERIFICATION_MATERIAL_EXPIRED")
        self.assertIn("query-budget", self.semantic_codes())

    def test_partial_party_failure_is_terminal(self):
        transition = self.transition("TR-PARTIAL-PARTY-FAILURE")
        transition["to_phase"] = "EVALUATING"
        self.assertIn("expiry", self.semantic_codes())

    def test_party_result_conflict_fails_closed(self):
        transition = self.transition("TR-RESULT-CONFLICT")
        transition["to_phase"] = "RESULT_ACCEPTED"
        self.assertIn("result-symmetry", self.semantic_codes())

    def test_asymmetric_result_acceptance_is_rejected(self):
        transition = self.transition("TR-ACCEPT-SYMMETRIC-RESULT")
        transition["guards"] = [
            guard
            for guard in transition["guards"]
            if guard["id"] != "G-SAME-PARTY-RESULT"
        ]
        self.assertIn("result-symmetry", self.semantic_codes())

    def test_coordinator_plaintext_outcome_state_is_rejected(self):
        variable = next(
            item
            for item in self.model_copy["state_variables"]
            if item["id"] == "accepted_result_state"
        )
        variable["coordinator_access"] = "read-write"
        variable["visibility"].append("coordinator")
        self.assertIn("coordinator-plaintext-outcome", self.semantic_codes())

    def test_minimum_disclosure_prohibitions_cannot_be_removed(self):
        self.model_copy["authority_model"]["coordinator_prohibited_state"].remove(
            "exact intersection count"
        )
        self.assertIn("minimum-disclosure", self.semantic_codes())

    def test_actual_disclosure_payload_cannot_enter_core_scope(self):
        self.model_copy["scope"]["excludes"].remove(
            "actual identity, private-data, or disclosure payload"
        )
        self.assertIn("minimum-disclosure", self.semantic_codes())

    def test_party_specific_result_prohibition_cannot_be_removed(self):
        self.model_copy["result_acceptance_semantics"]["forbidden"].remove(
            "party-specific accepted result"
        )
        self.assertIn("minimum-disclosure", self.semantic_codes())

    def test_consent_artifact_digest_binding_is_required(self):
        self.model_copy["consent_semantics"]["required_binding_fields"].remove(
            "consent artifact digest"
        )
        self.assertIn("disclosure-guard", self.semantic_codes())

    def test_coordinator_plaintext_outcome_visibility_is_rejected(self):
        transition = self.transition("TR-ACCEPT-SYMMETRIC-RESULT")
        coordinator = next(
            item for item in transition["visibility"] if item["actor"] == "coordinator"
        )
        coordinator["data"].append("plaintext MATCH outcome")
        self.assertIn("coordinator-plaintext-outcome", self.semantic_codes())

    def test_bare_hash_of_match_is_rejected(self):
        for value in ("MATCH", "NO_MATCH", "INDETERMINATE"):
            with self.subTest(value=value):
                candidate = copy.deepcopy(self.model)
                candidate["authority_model"]["opaque_receipt_reference"][
                    "construction_policy"
                ] = f"hash({value})"
                self.assertIn(
                    "opaque-receipt",
                    {finding.code for finding in semantic_findings(candidate)},
                )

    def test_consent_before_result_acceptance_is_rejected(self):
        transition = self.transition("TR-GRANT-CONSENT-A")
        transition["from_phase"].append("EVALUATING")
        self.assertIn("disclosure-guard", self.semantic_codes())

    def test_consent_for_wrong_receipt_is_rejected(self):
        state = self.synthetic_disclosure_state()
        state["consent"]["B"]["opaque_receipt_ref"] = "different-receipt"
        self.assertIn(
            "G-CONSENT-RECEIPT-BINDING",
            disclosure_authorization_guard_failures(state, {"fixture-disclosure/v0.1"}),
        )

    def test_consent_for_wrong_scope_is_rejected(self):
        state = self.synthetic_disclosure_state()
        state["consent"]["A"]["scope"] = ["different-field"]
        self.assertIn(
            "G-CONSENT-SCOPE-BINDING",
            disclosure_authorization_guard_failures(state, {"fixture-disclosure/v0.1"}),
        )

    def test_consent_for_wrong_profile_is_rejected(self):
        state = self.synthetic_disclosure_state()
        state["consent"]["A"]["disclosure_profile_ref"] = "other/v0.1"
        self.assertIn(
            "G-CONSENT-PROFILE-BINDING",
            disclosure_authorization_guard_failures(state, {"fixture-disclosure/v0.1"}),
        )

    def test_consent_for_wrong_audience_is_rejected(self):
        state = self.synthetic_disclosure_state()
        state["consent"]["B"]["audience"] = ["fixture-b"]
        self.assertIn(
            "G-CONSENT-AUDIENCE-BINDING",
            disclosure_authorization_guard_failures(state, {"fixture-disclosure/v0.1"}),
        )

    def test_expired_consent_is_rejected(self):
        state = self.synthetic_disclosure_state()
        state["authoritative_time"] = 151
        self.assertIn(
            "G-CONSENT-EXPIRY",
            disclosure_authorization_guard_failures(state, {"fixture-disclosure/v0.1"}),
        )

    def test_consent_withdrawal_before_completion_invalidates_authorization(self):
        transition = self.transition("TR-WITHDRAW-CONSENT-A")
        self.assertIn("DISCLOSURE_AUTHORIZED", transition["from_phase"])
        self.assertEqual(transition["to_phase"], "RESULT_ACCEPTED")
        self.assertIn(
            "G-WITHDRAWAL-BEFORE-COMPLETION",
            {guard["id"] for guard in transition["guards"]},
        )

    def test_withdrawal_completion_order_is_authoritative(self):
        transition = self.transition("TR-RECORD-DISCLOSURE-COMPLETION")
        self.assertIn(
            "G-NO-EARLIER-WITHDRAWAL",
            {guard["id"] for guard in transition["guards"]},
        )

    def test_disclosure_on_no_match_is_rejected(self):
        state = self.synthetic_disclosure_state()
        state["accepted_result_state"] = {"A": "NO_MATCH", "B": "NO_MATCH"}
        self.assertIn(
            "G-DISCLOSURE-MATCH",
            disclosure_authorization_guard_failures(state, {"fixture-disclosure/v0.1"}),
        )

    def test_disclosure_on_indeterminate_is_rejected(self):
        state = self.synthetic_disclosure_state()
        state["accepted_result_state"] = {
            "A": "INDETERMINATE",
            "B": "INDETERMINATE",
        }
        self.assertIn(
            "G-DISCLOSURE-MATCH",
            disclosure_authorization_guard_failures(state, {"fixture-disclosure/v0.1"}),
        )

    def test_disclosure_without_bilateral_consent_is_rejected(self):
        state = self.synthetic_disclosure_state()
        state["consent"]["B"] = None
        self.assertIn(
            "G-BILATERAL-CONSENT",
            disclosure_authorization_guard_failures(state, {"fixture-disclosure/v0.1"}),
        )

    def test_disclosure_without_profile_is_rejected(self):
        state = self.synthetic_disclosure_state()
        state["disclosure_profile_ref"] = "NONE"
        self.assertIn(
            "G-PROFILE-REVIEWED",
            disclosure_authorization_guard_failures(state, set()),
        )

    def test_disclosure_after_session_expiry_is_rejected(self):
        state = self.synthetic_disclosure_state()
        state["authoritative_time"] = state["session_expires_at"]
        failures = disclosure_authorization_guard_failures(
            state, {"fixture-disclosure/v0.1"}
        )
        self.assertIn("G-ACTIVE-SESSION", failures)

    def test_mutating_transition_after_close_is_rejected(self):
        self.transition("TR-START-EVALUATION")["from_phase"].append("CLOSED")
        self.assertIn("terminal-transition", self.semantic_codes())

    def test_mutating_transition_after_abort_is_rejected(self):
        self.transition("TR-START-EVALUATION")["from_phase"].append("ABORTED")
        self.assertIn("terminal-transition", self.semantic_codes())

    def test_unknown_state_reference_is_rejected(self):
        self.transition("TR-CREATE")["to_phase"] = "UNKNOWN_PHASE"
        self.assertIn("reference", self.semantic_codes())

    def test_unknown_event_reference_is_rejected(self):
        self.transition("TR-CREATE")["event"] = "unknown_event_fixture"
        self.assertIn("reference", self.semantic_codes())

    def test_unknown_version_is_rejected_by_schema(self):
        self.model_copy["schema_version"] = "9.9"
        self.assertIn("schema", self.schema_codes())

    def test_result_value_outside_core_set_is_rejected(self):
        self.model_copy["artifact"]["decision_output"].append("EXACT_COUNT")
        self.assertIn("schema", self.schema_codes())

    def test_unknown_field_is_rejected_by_schema(self):
        self.model_copy["unexpected_fixture_field"] = True
        self.assertIn("schema", self.schema_codes())

    def test_malformed_yaml_is_structured_without_traceback(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            path = Path(directory) / "malformed.yaml"
            path.write_text("transitions: [\n", encoding="utf-8")
            model, findings = load_yaml(path)
        self.assertIsNone(model)
        self.assertEqual(findings[0].code, "yaml-parse")
        self.assertLessEqual(len(findings[0].message), 320)

    def test_duplicate_yaml_mapping_key_is_rejected(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            path = Path(directory) / "duplicate.yaml"
            path.write_text(
                "schema_version: '0.1'\nschema_version: '9.9'\n", encoding="utf-8"
            )
            model, findings = load_yaml(path)
        self.assertIsNone(model)
        self.assertEqual(findings[0].code, "yaml-parse")
        self.assertIn("duplicate key", findings[0].message)

    def test_unique_key_loader_does_not_change_safe_loader_constructor(self):
        document = "value: first\nvalue: second\n"
        with self.assertRaises(yaml.YAMLError):
            yaml.load(document, Loader=NoDatesSafeLoader)
        self.assertEqual(yaml.safe_load(document), {"value": "second"})

    def test_malformed_json_schema_is_structured_without_traceback(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            path = Path(directory) / "malformed.json"
            path.write_text('{"type": ', encoding="utf-8")
            schema, findings = load_json(path)
        self.assertIsNone(schema)
        self.assertEqual(findings[0].code, "json-parse")
        self.assertLessEqual(len(findings[0].message), 320)

    def test_file_read_error_is_structured(self):
        with mock.patch.object(Path, "read_text", side_effect=OSError("simulated")):
            model, findings = load_yaml(ROOT / "fixture.yaml")
        self.assertIsNone(model)
        self.assertEqual(findings[0].code, "file-read")

    def test_invalid_utf8_is_structured(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            path = Path(directory) / "invalid.yaml"
            path.write_bytes(b"\xff\xfe")
            model, findings = load_yaml(path)
        self.assertIsNone(model)
        self.assertEqual(findings[0].code, "text-decode")

    def test_cli_reports_parse_error_and_exit_one_without_traceback(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            path = Path(directory) / "malformed.yaml"
            path.write_text("artifact: [\n", encoding="utf-8")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                exit_code = main(["--root", str(ROOT), "--artifact", str(path)])
        self.assertEqual(exit_code, 1)
        self.assertIn("[yaml-parse]", output.getvalue())
        self.assertNotIn("Traceback", output.getvalue())

    def test_duplicate_transition_id_is_rejected(self):
        duplicate = copy.deepcopy(self.model_copy["transitions"][0])
        self.model_copy["transitions"].append(duplicate)
        self.assertIn("duplicate-id", self.semantic_codes())

    def test_duplicate_phase_id_is_rejected(self):
        duplicate = copy.deepcopy(self.model_copy["phases"][0])
        self.model_copy["phases"].append(duplicate)
        self.assertIn("duplicate-id", self.semantic_codes())

    def test_duplicate_event_id_is_rejected(self):
        duplicate = copy.deepcopy(self.model_copy["events"][0])
        self.model_copy["events"].append(duplicate)
        self.assertIn("duplicate-id", self.semantic_codes())

    def test_undefined_abstract_event_parameter_is_rejected(self):
        self.model_copy["events"][0]["parameters"].append("unknown_parameter")
        self.assertIn("reference", self.semantic_codes())

    def test_undefined_invariant_reference_is_rejected(self):
        self.transition("TR-CREATE")["related_invariants"].append("INV-UNDEFINED")
        self.assertIn("reference", self.semantic_codes())

    def test_terminal_state_illegal_outgoing_transition_is_rejected(self):
        transition = self.transition("TR-CLOSE")
        transition["from_phase"].append("EXPIRED")
        self.assertIn("terminal-transition", self.semantic_codes())

    def test_all_declared_failures_define_terminal_retry_and_visibility_semantics(self):
        required = {
            "disposition",
            "retryable",
            "requires_new_message",
            "requires_new_session",
            "query_budget_effect",
            "party_error_category",
            "detail_visibility",
        }
        for failure in self.model["failure_taxonomy"]:
            with self.subTest(code=failure["code"]):
                self.assertTrue(required.issubset(failure))

    def test_every_event_has_actor_visibility_audit_and_idempotency_metadata(self):
        required = {
            "initiator",
            "verifier",
            "authoritative_state_owner",
            "visibility",
            "prohibited_data",
            "audit_fields",
            "idempotency_behavior",
            "duplicate_behavior",
            "retry_class",
        }
        for event in self.model["events"]:
            with self.subTest(event=event["id"]):
                self.assertTrue(required.issubset(event))

    def test_cli_positive_output_is_deterministic(self):
        outputs = []
        for _ in range(2):
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                exit_code = main(["--root", str(ROOT), "--print-digest"])
            self.assertEqual(exit_code, 0)
            outputs.append(output.getvalue())
        self.assertEqual(outputs[0], outputs[1])


if __name__ == "__main__":
    unittest.main()
