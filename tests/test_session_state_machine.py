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
    apply_generic_abort,
    authoritative_time_transition,
    canonical_digest,
    disclosure_authorization_guard_failures,
    duplicate_delivery_outcome,
    generic_abort_guard_failures,
    load_json,
    load_yaml,
    main,
    message_time_failures,
    schema_findings,
    semantic_findings,
    terminal_budget_disposition,
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
        self.assertEqual(
            self.transition("TR-ADVANCE-TIME-EXPIRE")["to_phase"], "EXPIRED"
        )

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
        transition = self.transition("TR-ABORT")
        transition["failure_code"].remove("PARTIAL_PARTY_FAILURE")
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
        self.assertEqual(transition["to_phase"], "ABORTED")
        self.assertIn("CONSENT_WITHDRAWN", transition["failure_code"])
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
            "delivery_class",
            "required_envelope",
            "deduplication_domain",
        }
        for event in self.model["events"]:
            with self.subTest(event=event["id"]):
                self.assertTrue(required.issubset(event))

    def test_party_a_cannot_read_party_b_proposal(self):
        variable = next(
            item
            for item in self.model_copy["state_variables"]
            if item["id"] == "proposed_result_state"
        )
        variable["entry_visibility"]["B"].append("party_a_client")
        self.assertIn("result-visibility", self.semantic_codes())

    def test_party_b_cannot_read_party_a_proposal(self):
        variable = next(
            item
            for item in self.model_copy["state_variables"]
            if item["id"] == "proposed_result_state"
        )
        variable["entry_visibility"]["A"].append("party_b_client")
        self.assertIn("result-visibility", self.semantic_codes())

    def test_peer_local_result_binding_is_not_event_visible(self):
        event = next(
            item
            for item in self.model_copy["events"]
            if item["id"] == "acknowledge_opaque_receipt_a"
        )
        event["visibility"].append(
            {"actor": "party_b_client", "data": ["peer local-result binding"]}
        )
        self.assertIn("result-visibility", self.semantic_codes())

    def test_coordinator_cannot_receive_local_result_binding(self):
        variable = next(
            item
            for item in self.model_copy["state_variables"]
            if item["id"] == "result_ack"
        )
        variable["coordinator_projection"]["permitted_fields"].append(
            "local_result_binding"
        )
        self.assertIn("result-visibility", self.semantic_codes())

    def test_each_party_own_entry_visibility_is_schema_valid(self):
        for identifier in (
            "proposed_result_state",
            "accepted_result_state",
            "result_ack",
        ):
            variable = next(
                item
                for item in self.model["state_variables"]
                if item["id"] == identifier
            )
            self.assertEqual(variable["entry_visibility"]["A"], ["party_a_client"])
            self.assertEqual(variable["entry_visibility"]["B"], ["party_b_client"])
            self.assertFalse(
                variable["global_invariant_observer"]["implementation_actor_access"]
            )

    def test_sensitive_result_visibility_fields_are_schema_required(self):
        variable = next(
            item
            for item in self.model_copy["state_variables"]
            if item["id"] == "result_ack"
        )
        del variable["entry_visibility"]
        self.assertIn("schema", self.schema_codes())

    def test_accepted_result_symmetry_invariant_is_preserved(self):
        invariant = self.invariant("INV-RESULT-SYMMETRY", self.model)
        self.assertIn("accepted_result_state", invariant["state_variables"])
        self.assertIn(
            "G-SAME-PARTY-RESULT",
            {
                guard["id"]
                for guard in self.transition("TR-ACCEPT-SYMMETRIC-RESULT", self.model)[
                    "guards"
                ]
            },
        )

    def test_event_and_state_visibility_mismatch_is_rejected(self):
        transition = self.transition("TR-ACK-RECEIPT-A")
        transition["visibility"].append(
            {"actor": "party_b_client", "data": ["peer proposed result"]}
        )
        self.assertIn("result-visibility", self.semantic_codes())

    @staticmethod
    def time_state(**overrides):
        state = {
            "phase": "COMMITTED",
            "authoritative_time": 100,
            "session_expires_at": 200,
            "evaluation_started": False,
            "evaluation_deadline": None,
            "query_budget_state": "RESERVED",
            "disclosure_state": "NONE",
            "terminal_reason": "NONE",
            "consent": {"A": None, "B": None},
        }
        state.update(overrides)
        return state

    def test_authoritative_time_increases(self):
        state, failures = authoritative_time_transition(self.time_state(), 110, 20)
        self.assertEqual(failures, [])
        self.assertEqual(state["authoritative_time"], 110)
        self.assertEqual(state["phase"], "COMMITTED")

    def test_authoritative_time_same_value_is_no_op(self):
        original = self.time_state()
        state, failures = authoritative_time_transition(original, 100, 20)
        self.assertEqual(failures, [])
        self.assertEqual(state, original)
        transition = self.transition("TR-ADVANCE-TIME-NOOP", self.model)
        self.assertFalse(transition["mutating"])
        self.assertEqual(transition["effects"][0]["writes"], [])

    def test_authoritative_time_rollback_is_rejected(self):
        state, failures = authoritative_time_transition(self.time_state(), 99, 20)
        self.assertEqual(failures, ["TIME_ROLLBACK"])
        self.assertEqual(state["authoritative_time"], 100)

    def test_terminal_phase_rejects_time_mutation(self):
        original = self.time_state(phase="CLOSED")
        state, failures = authoritative_time_transition(original, 110, 20)
        self.assertEqual(failures, ["TERMINAL_STATE"])
        self.assertEqual(state, original)

    def test_authoritative_time_jump_is_bounded(self):
        _, failures = authoritative_time_transition(self.time_state(), 150, 20)
        self.assertEqual(failures, ["TIME_JUMP_EXCEEDED"])

    def test_session_expiry_crossing_is_atomic(self):
        state, failures = authoritative_time_transition(self.time_state(), 200, 100)
        self.assertEqual(failures, [])
        self.assertEqual(state["authoritative_time"], 200)
        self.assertEqual(state["phase"], "EXPIRED")
        self.assertEqual(state["terminal_reason"], "SESSION_EXPIRED")
        self.assertEqual(state["query_budget_state"], "EXPIRED")

    def test_evaluation_deadline_crossing_aborts(self):
        original = self.time_state(
            phase="EVALUATING",
            evaluation_started=True,
            evaluation_deadline=120,
            query_budget_state="CONSUMED",
        )
        state, failures = authoritative_time_transition(original, 120, 20)
        self.assertEqual(failures, [])
        self.assertEqual(state["phase"], "ABORTED")
        self.assertEqual(state["terminal_reason"], "EVALUATION_TIMEOUT")
        self.assertEqual(state["query_budget_state"], "CONSUMED")

    def test_consent_expiry_after_time_advance_aborts(self):
        consent = {"status": "valid", "expires_at": 110}
        original = self.time_state(
            phase="CONSENT_PENDING",
            evaluation_started=True,
            query_budget_state="CONSUMED",
            consent={"A": consent, "B": {"status": "valid", "expires_at": 150}},
        )
        state, failures = authoritative_time_transition(original, 110, 20)
        self.assertEqual(failures, [])
        self.assertEqual(state["phase"], "ABORTED")
        self.assertEqual(state["terminal_reason"], "CONSENT_EXPIRED")

    def test_verification_material_expiry_is_decidable_after_time_advance(self):
        original = self.time_state(
            verification_material_validity={"not_before": 80, "not_after": 105}
        )
        state, failures = authoritative_time_transition(original, 106, 20)
        self.assertEqual(failures, [])
        self.assertGreaterEqual(
            state["authoritative_time"],
            state["verification_material_validity"]["not_after"],
        )

    def test_stale_message_is_rejected_by_authoritative_time(self):
        self.assertEqual(message_time_failures(100, 79, 5, 20), ["STALE_MESSAGE"])

    def test_future_message_outside_skew_is_rejected(self):
        self.assertEqual(message_time_failures(100, 106, 5, 20), ["STALE_MESSAGE"])

    def test_message_within_time_window_passes(self):
        self.assertEqual(message_time_failures(100, 95, 5, 20), [])

    def test_missing_time_relation_is_semantic_failure(self):
        self.model_copy["transitions"] = [
            item
            for item in self.model_copy["transitions"]
            if item["id"] != "TR-ADVANCE-TIME-LIVE"
        ]
        relation = next(
            item
            for item in self.model_copy["formalization"]["event_relation"]
            if item["event"] == "advance_authoritative_time"
        )
        relation["transitions"].remove("TR-ADVANCE-TIME-LIVE")
        self.assertIn("authoritative-time", self.semantic_codes())

    def test_party_message_without_replay_envelope_fails(self):
        event = next(
            item for item in self.model_copy["events"] if item["id"] == "accept_policy"
        )
        event["parameters"].remove("replay_envelope")
        self.assertIn("schema", self.schema_codes())

    def test_coordinator_command_without_operation_envelope_fails(self):
        event = next(
            item
            for item in self.model_copy["events"]
            if item["id"] == "reserve_query_budget"
        )
        event["parameters"].remove("operation_envelope")
        self.assertIn("schema", self.schema_codes())

    def test_mutating_coordinator_command_without_dedup_effect_fails(self):
        transition = self.transition("TR-RESERVE-BUDGET")
        transition["effects"] = [
            item for item in transition["effects"] if item["id"] != "E-ACCEPT-OPERATION"
        ]
        self.assertIn("delivery-class", self.semantic_codes())

    def test_mutating_party_message_must_record_replay_envelope(self):
        transition = self.transition("TR-WITHDRAW-CONSENT-A")
        transition["effects"] = [
            item for item in transition["effects"] if item["id"] != "E-ACCEPT-MESSAGE"
        ]
        self.assertIn("message-time", self.semantic_codes())

    def test_profile_callback_without_callback_envelope_fails(self):
        event = next(
            item
            for item in self.model_copy["events"]
            if item["id"] == "accept_symmetric_result"
        )
        event["parameters"].remove("profile_callback_envelope")
        self.assertIn("schema", self.schema_codes())

    def test_mutating_profile_callback_without_dedup_guard_fails(self):
        transition = self.transition("TR-ACCEPT-SYMMETRIC-RESULT")
        transition["guards"] = [
            item
            for item in transition["guards"]
            if item["id"] != "G-PROFILE-CALLBACK-DEDUP"
        ]
        self.assertIn("delivery-class", self.semantic_codes())

    def test_timer_cannot_require_message_nonce(self):
        event = next(
            item
            for item in self.model_copy["events"]
            if item["id"] == "advance_authoritative_time"
        )
        event["parameters"].append("replay_envelope")
        event["idempotency_behavior"] = "same nonce returns prior response"
        self.assertIn("schema", self.schema_codes())

    def test_duplicate_coordinator_commands_are_exact(self):
        for event_id in ("create_session", "reserve_query_budget", "start_evaluation"):
            with self.subTest(event=event_id):
                registry = {("coordinator", event_id, "key"): "digest"}
                self.assertEqual(
                    duplicate_delivery_outcome(
                        registry, "coordinator", event_id, "key", "digest"
                    ),
                    "exact-duplicate",
                )

    def test_duplicate_profile_callbacks_are_exact(self):
        for callback_id in ("profile-result", "disclosure-completion"):
            with self.subTest(callback=callback_id):
                registry = {
                    ("profile-instance/session/attempt", callback_id, "key"): "digest"
                }
                self.assertEqual(
                    duplicate_delivery_outcome(
                        registry,
                        "profile-instance/session/attempt",
                        callback_id,
                        "key",
                        "digest",
                    ),
                    "exact-duplicate",
                )

    def test_same_operation_id_with_different_digest_conflicts(self):
        registry = {("coordinator", "operation-1", "key"): "digest-a"}
        self.assertEqual(
            duplicate_delivery_outcome(
                registry, "coordinator", "operation-1", "key", "digest-b"
            ),
            "REPLAY_CONFLICT",
        )

    def test_operation_ids_are_actor_scoped(self):
        registry = {("actor-a", "operation-1", "key"): "digest-a"}
        self.assertEqual(
            duplicate_delivery_outcome(
                registry, "actor-b", "operation-1", "key", "digest-b"
            ),
            "new",
        )

    def test_exact_actor_retries_never_write_terminal_state(self):
        for transition_id in (
            "TR-RETRY-EXACT-OPERATION",
            "TR-RETRY-EXACT-PROFILE-CALLBACK",
        ):
            transition = self.transition(transition_id, self.model)
            self.assertIn("CLOSED", transition["from_phase"])
            self.assertFalse(transition["mutating"])
            self.assertFalse(any(effect["writes"] for effect in transition["effects"]))

    def test_generic_abort_valid_parameter_is_applied(self):
        state, failures = apply_generic_abort(
            self.model,
            self.time_state(),
            "coordinator",
            "PARTIAL_PARTY_FAILURE",
        )
        self.assertEqual(failures, [])
        self.assertEqual(state["phase"], "ABORTED")
        self.assertEqual(state["terminal_reason"], "PARTIAL_PARTY_FAILURE")
        self.assertEqual(state["query_budget_state"], "RELEASED")

    def test_generic_abort_undeclared_failure_is_rejected(self):
        self.assertEqual(
            generic_abort_guard_failures(
                self.model, "coordinator", "UNDECLARED_FIXTURE"
            ),
            ["UNDECLARED_FAILURE"],
        )

    def test_generic_abort_rejects_message_only_failure(self):
        self.assertEqual(
            generic_abort_guard_failures(
                self.model, "coordinator", "PARTICIPANT_MISMATCH"
            ),
            ["NON_ABORT_DISPOSITION"],
        )

    def test_generic_abort_never_leaves_terminal_reason_none(self):
        state, failures = apply_generic_abort(
            self.model, self.time_state(), "coordinator", "RESULT_CONFLICT"
        )
        self.assertEqual(failures, [])
        self.assertNotEqual(state["terminal_reason"], "NONE")
        self.assertEqual(state["terminal_reason"], "RESULT_CONFLICT")

    def test_generic_abort_guard_cannot_read_old_terminal_reason(self):
        transition = self.transition("TR-ABORT")
        guard = next(
            item for item in transition["guards"] if item["id"] == "G-ABORT-REASON"
        )
        guard["reads"] = ["terminal_reason"]
        guard["parameter_reads"] = []
        self.assertIn("generic-abort", self.semantic_codes())

    def test_party_cannot_select_generic_abort_failure(self):
        self.assertEqual(
            generic_abort_guard_failures(
                self.model, "party_a_client", "RESULT_CONFLICT"
            ),
            ["ABORT_AUTHORITY"],
        )

    def test_terminal_session_cannot_be_aborted_again(self):
        original = self.time_state(phase="CLOSED")
        state, failures = apply_generic_abort(
            self.model, original, "coordinator", "RESULT_CONFLICT"
        )
        self.assertEqual(failures, ["TERMINAL_STATE"])
        self.assertEqual(state, original)

    def test_generic_abort_invalidates_disclosure_authorization(self):
        state, failures = apply_generic_abort(
            self.model,
            self.time_state(disclosure_state="AUTHORIZED"),
            "coordinator",
            "RESULT_CONFLICT",
        )
        self.assertEqual(failures, [])
        self.assertEqual(state["disclosure_state"], "NONE")

    def test_unused_reserved_budget_is_released_on_close(self):
        self.assertEqual(
            terminal_budget_disposition("RESERVED", False, "close"), "RELEASED"
        )

    def test_unused_reserved_budget_expires_on_session_expiry(self):
        self.assertEqual(
            terminal_budget_disposition("RESERVED", False, "expire"), "EXPIRED"
        )

    def test_unused_reserved_budget_is_released_on_abort(self):
        self.assertEqual(
            terminal_budget_disposition("RESERVED", False, "abort"), "RELEASED"
        )

    def test_consumed_budget_is_never_terminally_refunded(self):
        for event in ("close", "abort", "expire", "timeout"):
            with self.subTest(event=event):
                self.assertEqual(
                    terminal_budget_disposition("CONSUMED", True, event), "CONSUMED"
                )

    def test_exact_terminal_duplicate_does_not_release_twice(self):
        for transition_id in (
            "TR-RETRY-EXACT-DUPLICATE-A",
            "TR-RETRY-EXACT-OPERATION",
            "TR-RETRY-EXACT-PROFILE-CALLBACK",
        ):
            writes = {
                variable
                for effect in self.transition(transition_id, self.model)["effects"]
                for variable in effect["writes"]
            }
            self.assertNotIn("query_budget_state", writes)

    def test_close_must_record_unused_reservation_disposition(self):
        transition = self.transition("TR-CLOSE")
        transition["effects"] = [
            item
            for item in transition["effects"]
            if "query_budget_state" not in item["writes"]
        ]
        self.assertIn("query-budget", self.semantic_codes())

    def test_released_reservation_cannot_be_reused_in_session(self):
        self.assertIn(
            "forbidden",
            self.model["query_budget_semantics"]["released_reservation_reuse"],
        )
        self.assertNotIn(
            "RELEASED",
            next(
                guard
                for guard in self.transition("TR-START-EVALUATION", self.model)[
                    "guards"
                ]
                if guard["id"] == "G-BUDGET-RESERVED"
            )["arguments"],
        )

    def test_consent_expiry_requires_new_session(self):
        self.assertEqual(
            self.model["consent_semantics"]["expiry_or_withdrawal_policy"],
            "new-session-required",
        )
        failure = next(
            item
            for item in self.model["failure_taxonomy"]
            if item["code"] == "CONSENT_EXPIRED"
        )
        self.assertTrue(failure["requires_new_session"])

    def test_same_session_consent_replacement_policy_cannot_be_weakened(self):
        self.model_copy["consent_semantics"]["expiry_or_withdrawal_policy"] = (
            "same-session-replacement"
        )
        self.assertIn("consent-lifecycle", self.semantic_codes())

    def test_one_expired_consent_invalidates_both_party_authorization(self):
        consent_a = {"status": "valid", "expires_at": 110}
        consent_b = {"status": "valid", "expires_at": 150}
        state, failures = authoritative_time_transition(
            self.time_state(
                phase="CONSENT_PENDING",
                evaluation_started=True,
                query_budget_state="CONSUMED",
                consent={"A": consent_a, "B": consent_b},
            ),
            110,
            20,
        )
        self.assertEqual(failures, [])
        self.assertEqual(state["phase"], "ABORTED")

    def test_withdrawal_after_authorization_requires_new_session(self):
        for party in ("A", "B"):
            transition = self.transition(f"TR-WITHDRAW-CONSENT-{party}", self.model)
            self.assertIn("DISCLOSURE_AUTHORIZED", transition["from_phase"])
            self.assertEqual(transition["to_phase"], "ABORTED")

    def test_withdrawal_after_completion_is_not_a_mutating_transition(self):
        for party in ("A", "B"):
            transition = self.transition(f"TR-WITHDRAW-CONSENT-{party}", self.model)
            self.assertNotIn("CLOSED", transition["from_phase"])

    def test_stale_consent_nonce_uses_party_replay_domain(self):
        event = next(
            item for item in self.model["events"] if item["id"] == "grant_consent_a"
        )
        self.assertEqual(event["delivery_class"], "party_message")
        self.assertIn("replay_envelope", event["parameters"])
        self.assertEqual(
            event["deduplication_domain"], "(session_id,sender_participant_id)"
        )

    def test_old_and_new_consent_generations_cannot_mix(self):
        self.assertIn(
            "cannot authorize together",
            self.model["consent_semantics"]["mixed_generation_policy"],
        )
        for party in ("A", "B"):
            guards = {
                item["id"]
                for item in self.transition(f"TR-GRANT-CONSENT-{party}", self.model)[
                    "guards"
                ]
            }
            self.assertIn(f"G-CONSENT-SLOT-EMPTY-{party}", guards)

    def test_schema_version_remains_draft_zero_one(self):
        self.assertEqual(self.model["schema_version"], "0.1")
        self.assertEqual(self.model["artifact"]["status"], "draft")

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
