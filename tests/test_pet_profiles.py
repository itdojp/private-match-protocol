# SPDX-License-Identifier: Apache-2.0
"""Experimental PET integration-profile and Product handoff regressions."""

from __future__ import annotations

import copy
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from generate_pet_profiles import main as generate_main  # noqa: E402
from pet_profiles import (  # noqa: E402
    AUTHORITY_PATH,
    ABORT_PHASE_ORDER,
    BINDING_PATH,
    CANONICAL_CALLBACK_PATH,
    CALLBACK_BINDINGS,
    CASE_CATALOG_PATH,
    COMPLETE_PROFILE_IDS,
    COMPONENT_PROFILE_IDS,
    GENERATED_PATHS,
    HANDOFF_PATH,
    ERROR_CODE_CATALOG_PATH,
    EVALUATING_ACKNOWLEDGMENT_SUBSTATE_ORDER,
    INVALID_CASE_CODES,
    MESSAGE_REGISTRY_DIGEST,
    NITRO_RECEIPT_BINDINGS,
    PROFILE_PATHS,
    PROHIBITED_OUTPUTS,
    PROTOCOL_OUTPUTS,
    RECEIPT_BINDINGS,
    RESEARCH_COMMIT,
    RESEARCH_FILES,
    SCHEMAS,
    STATE_MACHINE_DIGEST,
    STAGE_CONTRACT_PATH,
    PetProfileError,
    conformance_input_for_mutation,
    detached_digest,
    generated_files,
    load_repository,
    operation_input_for_case,
    operation_stage_contract_bytes,
    expected_operation_stage_contract,
    expected_protocol_operations,
    validate_case_catalog,
    validate_conformance_input,
    validate_operation_input,
    validate_repository,
    validate_error_code_authority,
    validate_semantics,
    _acknowledgment_evidence_digest,
    _execution_authorization_digest,
    _execute_invalid_case,
)
from strict_yaml import strict_yaml_load  # noqa: E402
from canonicalize_message import canonicalize, populate_digests, strict_loads  # noqa: E402


class PetProfileTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.values = load_repository(ROOT)

    def test_repository_authority_and_generated_artifacts_are_valid(self) -> None:
        validate_repository(ROOT)

    def test_new_schemas_self_validate_and_close_nested_objects(self) -> None:
        for relative in SCHEMAS.values():
            with self.subTest(path=relative):
                Draft202012Validator.check_schema(
                    json.loads((ROOT / relative).read_text(encoding="utf-8"))
                )
        schema = self.values["schemas"]["profile"]
        mutated = copy.deepcopy(
            self.values["profiles"]["private-match-experimental-secretflow-kkrt"]
        )
        mutated["security_model"]["unstated_claim"] = True
        self.assertTrue(list(Draft202012Validator(schema).iter_errors(mutated)))

    def test_research_authority_is_exact_offline_reviewed_snapshot(self) -> None:
        authority = self.values["authority"]
        self.assertEqual(RESEARCH_COMMIT, authority["commit"])
        self.assertEqual(
            RESEARCH_FILES,
            {item["path"]: item["digest"] for item in authority["artifacts"]},
        )
        self.assertEqual("not-run", authority["local_result_status"])
        self.assertEqual("not-selected", authority["production_selection_status"])
        self.assertEqual(
            authority["authority_digest"],
            detached_digest("authority", authority, "authority_digest"),
        )

    def test_research_authority_redigest_does_not_promote_changed_snapshot(
        self,
    ) -> None:
        values = copy.deepcopy(self.values)
        values["authority"]["artifacts"][0]["digest"] = "sha256:" + "f" * 64
        values["authority"]["authority_digest"] = detached_digest(
            "authority", values["authority"], "authority_digest"
        )
        with self.assertRaisesRegex(PetProfileError, "PET-RESEARCH-ARTIFACT-DIGEST"):
            validate_semantics(values)

    def test_two_complete_profiles_are_materially_different(self) -> None:
        profiles = self.values["profiles"]
        observed = {
            (
                profiles[item]["security_model"]["model_id"],
                profiles[item]["trust_model"]["model_id"],
            )
            for item in COMPLETE_PROFILE_IDS
        }
        self.assertEqual(2, len(observed))
        self.assertEqual(
            {"psi", "trusted-execution-environment"},
            {profiles[item]["technology_family"] for item in COMPLETE_PROFILE_IDS},
        )

    def test_complete_profiles_expose_only_minimum_symmetric_result(self) -> None:
        for identifier in COMPLETE_PROFILE_IDS:
            with self.subTest(profile=identifier):
                profile = self.values["profiles"][identifier]
                self.assertEqual(
                    PROTOCOL_OUTPUTS,
                    profile["protocol_contract"]["supported_decision_outputs"],
                )
                self.assertTrue(
                    profile["protocol_contract"]["result_symmetry"]["required"]
                )
                self.assertEqual(
                    PROHIBITED_OUTPUTS,
                    profile["privacy_and_operations"]["prohibited_output_classes"],
                )
                self.assertEqual(
                    "prohibited",
                    profile["complete_decision_contract"][
                        "coordinator_plaintext_result"
                    ],
                )
                self.assertFalse(profile["production_eligible"])

    def test_secretflow_profile_does_not_escalate_research_security(self) -> None:
        profile = self.values["profiles"]["private-match-experimental-secretflow-kkrt"]
        self.assertEqual("semi-honest", profile["security_model"]["model_id"])
        self.assertEqual(
            "not-established", profile["security_model"]["malicious_party_security"]
        )
        self.assertIn(
            "broad host privileges and host networking require separate review",
            profile["privacy_and_operations"]["environment_assumptions"],
        )

    def test_nitro_profile_requires_closed_attestation_and_human_authority(
        self,
    ) -> None:
        profile = self.values["profiles"]["private-match-experimental-nitro-enclave"]
        requirements = " ".join(profile["setup_authority"]["requirements"])
        self.assertIn("non-debug mode", requirements)
        self.assertIn("fresh verifier nonce", requirements)
        self.assertIn("expected PCR policy", requirements)
        self.assertIn("enclave image/source/artifact digest", requirements)
        self.assertEqual(
            "human-required-not-provided", profile["execution_authorization"]
        )

    def test_voprf_is_component_only_and_not_selectable(self) -> None:
        profile = self.values["profiles"][next(iter(COMPONENT_PROFILE_IDS))]
        self.assertEqual("component-only", profile["profile_class"])
        self.assertFalse(profile["component_contract"]["complete_engine"])
        self.assertFalse(
            profile["component_contract"]["selectable_as_complete_profile"]
        )
        self.assertFalse(profile["component_contract"]["set_semantics_defined"])
        self.assertFalse(profile["component_contract"]["symmetric_decision_defined"])
        self.assertEqual([], profile["protocol_contract"]["supported_decision_outputs"])

    def test_protocol_mapping_references_exact_live_events_messages_transitions(
        self,
    ) -> None:
        state_machine = strict_yaml_load(
            (
                ROOT / "specs/state-machines/private-match-core-session-v0.1.yaml"
            ).read_text()
        )
        message_registry = strict_yaml_load(
            (ROOT / "registry/message-types.v0.1.yaml").read_text()
        )
        binding = self.values["binding"]
        self.assertEqual(STATE_MACHINE_DIGEST, binding["state_machine_digest"])
        self.assertEqual(MESSAGE_REGISTRY_DIGEST, binding["message_registry_digest"])
        expected = expected_protocol_operations(message_registry, state_machine)
        observed = {
            item["operation"]: (
                tuple(item["events"]),
                item["message_type"],
                item["message_version"],
                item["delivery_class"],
                item["direction"],
                tuple(item["allowed_senders"]),
                item["verifier"],
                tuple(item["intended_audience"]),
                tuple(item["transition_ids"]),
                item["transcript_participation"],
                item["replay_idempotency_domain"],
            )
            for item in binding["operations"]
        }
        self.assertEqual(expected, observed)
        self.assertEqual(CALLBACK_BINDINGS, binding["callback_required_bindings"])

    def test_receipt_and_callback_bind_every_substitution_domain(self) -> None:
        for identifier in COMPLETE_PROFILE_IDS:
            profile = self.values["profiles"][identifier]
            expected_receipt = (
                NITRO_RECEIPT_BINDINGS
                if identifier == "private-match-experimental-nitro-enclave"
                else RECEIPT_BINDINGS
            )
            self.assertEqual(
                expected_receipt,
                profile["protocol_contract"]["opaque_receipt"]["binding_fields"],
            )
            self.assertEqual(
                CALLBACK_BINDINGS,
                profile["protocol_contract"]["callback"]["required_bindings"],
            )

    def test_product_handoff_covers_every_issue_six_concern(self) -> None:
        handoff = self.values["handoff"]
        self.assertEqual(20, len(handoff["port_fields"]))
        self.assertTrue(handoff["selection_rule"]["complete_profile_required"])
        self.assertTrue(handoff["selection_rule"]["component_only_rejected"])
        self.assertEqual(9, len(handoff["operation_stage_projection"]))
        self.assertEqual(
            {item["operation_id"] for item in self.values["stage"]["operations"]},
            {item["operation"] for item in handoff["operation_stage_projection"]},
        )
        serialized = json.dumps(handoff)
        self.assertNotIn("private-match-product/", serialized)
        self.assertNotIn("src/", serialized)

    def test_valid_synthetic_cases_never_execute_a_candidate(self) -> None:
        cases = self.values["cases"]
        self.assertTrue(cases["synthetic"])
        self.assertEqual("prohibited", cases["network_execution"])
        self.assertFalse(cases["candidate_execution"])
        self.assertFalse(cases["paid_resource_use"])
        self.assertEqual(25, len(cases["valid_cases"]))
        self.assertEqual(
            {"accepted", "no-op", "terminal"},
            {item["expected_protocol_outcome"] for item in cases["valid_cases"]},
        )

    def test_every_valid_case_executes_through_shared_operation_validator(self) -> None:
        results = validate_case_catalog(self.values)
        self.assertEqual(25, len(results))
        self.assertEqual({"pass"}, {item["runner_status"] for item in results})
        self.assertEqual(
            {"accepted", "no-op", "terminal"},
            {item["protocol_outcome"] for item in results},
        )
        manifest = json.loads(
            (ROOT / GENERATED_PATHS["case_results"]).read_text(encoding="utf-8")
        )
        self.assertEqual(25, manifest["status_counts"]["pass"])
        self.assertEqual(15, manifest["status_counts"]["terminal"])
        self.assertEqual(1, manifest["status_counts"]["no_op"])
        self.assertEqual(
            {item["case_id"] for item in self.values["cases"]["valid_cases"]},
            {item["case_id"] for item in manifest["results"]},
        )

    def test_operation_stage_authority_is_exact_state_machine_projection(self) -> None:
        self.assertEqual(
            expected_operation_stage_contract(self.values), self.values["stage"]
        )
        self.assertEqual(
            self.values["stage"]["stage_contract_digest"],
            self.values["binding"]["operation_stage_contract_digest"],
        )
        self.assertEqual(
            STAGE_CONTRACT_PATH.as_posix(),
            self.values["handoff"]["operation_stage_contract_path"],
        )
        self.assertEqual(
            {
                "register-component",
                "select-profile",
                "reserve-query-budget",
                "start-evaluation",
                "submit-contribution",
                "acknowledge-receipt",
                "accept-profile-callback",
                "evaluation-timeout",
                "abort-and-cleanup",
            },
            {item["operation_id"] for item in self.values["stage"]["operations"]},
        )

    def test_operation_stage_authority_generation_is_byte_deterministic(self) -> None:
        first = operation_stage_contract_bytes(self.values)
        second = operation_stage_contract_bytes(self.values)
        self.assertEqual(first, second)
        self.assertEqual(first, (ROOT / STAGE_CONTRACT_PATH).read_bytes())

    def test_early_operations_do_not_fabricate_future_state(self) -> None:
        records = {
            item["operation"]: operation_input_for_case(self.values, item)
            for item in self.values["cases"]["valid_cases"]
        }
        selected = records["select-profile"]["presented_operation"]
        for field in (
            "participant_binding_digest",
            "commitment_pair_id",
            "evaluation_attempt_id",
            "opaque_receipt_ref",
            "result_state",
        ):
            self.assertIsNone(selected[field], field)
        reserved = records["reserve-query-budget"]["presented_operation"]
        self.assertNotIn("opaque_receipt_ref", reserved)
        self.assertNotIn("verification_material_reference", reserved)
        started = records["start-evaluation"]["presented_operation"]
        self.assertNotIn("opaque_receipt_ref", started)
        self.assertNotIn("acknowledgment_status", started)
        for operation in ("select-profile", "reserve-query-budget", "start-evaluation"):
            self.assertNotIn("party_results", records[operation]["presented_operation"])
        acknowledgment_cases = [
            item
            for item in self.values["cases"]["valid_cases"]
            if item["operation"] == "acknowledge-receipt"
        ]
        acknowledgments = {
            item["party_slot"]: operation_input_for_case(self.values, item)
            for item in acknowledgment_cases
        }
        self.assertIsNone(
            acknowledgments["a"]["authoritative_context"]["initial_state"][
                "opaque_receipt_ref"
            ]
        )
        self.assertEqual(
            acknowledgments["b"]["presented_operation"]["opaque_receipt_ref"],
            acknowledgments["b"]["authoritative_context"]["initial_state"][
                "opaque_receipt_ref"
            ],
        )

    def test_presented_operations_never_contain_bilateral_plaintext_results(
        self,
    ) -> None:
        for item in self.values["cases"]["valid_cases"]:
            with self.subTest(case=item["case_id"]):
                record = operation_input_for_case(self.values, item)
                public = record["presented_operation"]
                self.assertNotIn("party_results", public)
                self.assertNotIn("party_a_result", public)
                self.assertNotIn("party_b_result", public)
                observer = record["synthetic_conformance_observer"]
                if item["operation"] == "accept-profile-callback":
                    self.assertEqual(
                        "synthetic-global-observer", observer["visibility"]
                    )
                    self.assertFalse(observer["coordinator_visible"])
                    self.assertFalse(observer["product_port_input"])
                    self.assertFalse(observer["evidence_exported"])
                else:
                    self.assertIsNone(observer)

    def test_plaintext_result_in_callback_or_public_operation_fails_closed(
        self,
    ) -> None:
        item = next(
            entry
            for entry in self.values["cases"]["valid_cases"]
            if entry["operation"] == "accept-profile-callback"
        )
        record = operation_input_for_case(self.values, item)
        public_mutation = copy.deepcopy(record)
        public_mutation["presented_operation"]["party_a_result"] = "MATCH"
        with self.assertRaisesRegex(PetProfileError, "PET-PUBLIC-RESULT-EXPOSURE"):
            validate_operation_input(self.values, public_mutation)

        message = strict_loads((ROOT / CANONICAL_CALLBACK_PATH).read_bytes())
        message["payload"]["local_result"] = "MATCH"
        message = populate_digests(message)
        with self.assertRaisesRegex(PetProfileError, "PET-CANONICAL-MESSAGE-INVALID"):
            validate_operation_input(
                self.values,
                record,
                canonical_message_bytes=canonicalize(message),
            )

    def test_operation_specific_outcomes_are_not_flattened(self) -> None:
        results = {
            item["case_id"]: validate_operation_input(
                self.values, operation_input_for_case(self.values, item)
            )
            for item in self.values["cases"]["valid_cases"]
        }
        registration = next(
            value for key, value in results.items() if "VOPRF-REGISTRATION" in key
        )
        timeout = next(value for key, value in results.items() if "TIMEOUT" in key)
        abort = next(
            results[item["case_id"]]
            for item in self.values["cases"]["valid_cases"]
            if item["operation"] == "abort-and-cleanup"
        )
        self.assertEqual("no-op", registration["protocol_outcome"])
        self.assertEqual("terminal", timeout["protocol_outcome"])
        self.assertEqual("terminal", abort["protocol_outcome"])
        self.assertEqual("ABORTED", timeout["resulting_phase"])
        self.assertEqual("ABORTED", abort["resulting_phase"])

    def test_pre_post_state_and_effect_mutations_fail_closed(self) -> None:
        expected = {
            "incorrect-pre-phase": "PET-STAGE-PRESTATE",
            "incorrect-transition": "PET-STATE-TRANSITION-PARITY",
            "incorrect-post-phase": "PET-STATE-TRANSITION-PARITY",
            "timeout-ordinary-accepted": "PET-STATE-TRANSITION-PARITY",
            "abort-ordinary-accepted": "PET-STATE-TRANSITION-PARITY",
            "transcript-mutation-mismatch": "PET-STATE-TRANSITION-PARITY",
            "query-budget-effect-mismatch": "PET-STATE-TRANSITION-PARITY",
        }
        for mutation, code in expected.items():
            with self.subTest(mutation=mutation):
                record = conformance_input_for_mutation(self.values, mutation)
                with self.assertRaises(PetProfileError) as caught:
                    validate_operation_input(self.values, record)
                self.assertEqual(code, caught.exception.code)

    def test_product_projection_excludes_synthetic_observer_surface(self) -> None:
        projection = json.loads(
            (ROOT / GENERATED_PATHS["handoff"]).read_text(encoding="utf-8")
        )
        serialized = json.dumps(projection, sort_keys=True)
        self.assertNotIn("synthetic_conformance_observer", serialized)
        fields = {item["field"] for item in projection["port_fields"]}
        self.assertTrue(
            {
                "operation-stage",
                "stage-field-availability",
                "party-local-result-visibility",
                "pre-post-state-contract",
            }
            <= fields
        )

    def test_authoritative_context_closes_reproduced_substitutions(self) -> None:
        expected = {
            "callback-session-mismatch": "PET-SESSION-BINDING",
            "callback-policy-mismatch": "PET-POLICY-BINDING",
            "participant-binding-mismatch": "PET-PARTICIPANT-BINDING",
            "commitment-pair-mismatch": "PET-COMMITMENT-BINDING",
            "profile-digest-mismatch": "PET-PROFILE-DIGEST-BINDING",
            "verification-material-reference-mismatch": "PET-VERIFICATION-MATERIAL",
            "verification-material-digest-mismatch": "PET-VERIFICATION-MATERIAL",
            "resource-policy-mismatch": "PET-RESOURCE-POLICY",
        }
        for mutation, code in expected.items():
            with self.subTest(mutation=mutation):
                record = conformance_input_for_mutation(self.values, mutation)
                with self.assertRaises(PetProfileError) as caught:
                    validate_operation_input(self.values, record)
                self.assertEqual(code, caught.exception.code)

    def test_callback_binds_start_authority_without_reconstruction(self) -> None:
        item = next(
            entry
            for entry in self.values["cases"]["valid_cases"]
            if entry["operation"] == "accept-profile-callback"
        )
        record = operation_input_for_case(self.values, item)
        operation = record["presented_operation"]
        state = record["authoritative_context"]["initial_state"]
        for field in (
            "resource_policy_binding",
            "execution_authorization_digest",
        ):
            self.assertEqual(state[field], operation[field])
        for mutation, code in (
            ("callback-resource-policy-substitution", "PET-RESOURCE-POLICY"),
            (
                "callback-execution-authority-substitution",
                "PET-EXECUTION-AUTHORIZATION-BINDING",
            ),
        ):
            with self.subTest(mutation=mutation):
                with self.assertRaises(PetProfileError) as caught:
                    validate_operation_input(
                        self.values,
                        conformance_input_for_mutation(self.values, mutation),
                    )
                self.assertEqual(code, caught.exception.code)

    def test_canonical_callback_carries_evaluation_start_authority(self) -> None:
        item = next(
            entry
            for entry in self.values["cases"]["valid_cases"]
            if entry["operation"] == "accept-profile-callback"
        )
        record = operation_input_for_case(self.values, item)
        message = strict_loads((ROOT / CANONICAL_CALLBACK_PATH).read_bytes())
        self.assertEqual("0.2", message["message_version"])
        for field in (
            "resource_policy_binding",
            "execution_authorization_digest",
        ):
            self.assertEqual(
                record["authoritative_context"]["initial_state"][field],
                message["payload"][field],
            )
            self.assertEqual(
                record["presented_operation"][field], message["payload"][field]
            )

        substituted = copy.deepcopy(record)
        replacement = "sha256:" + "ee" * 32
        substituted["authoritative_context"]["initial_state"][
            "resource_policy_binding"
        ] = replacement
        substituted["authoritative_context"]["expected_presented_operation"][
            "resource_policy_binding"
        ] = replacement
        substituted["presented_operation"]["resource_policy_binding"] = replacement
        with self.assertRaises(PetProfileError) as caught:
            validate_operation_input(self.values, substituted)
        self.assertEqual("PET-RESOURCE-POLICY", caught.exception.code)

        for field, code in (
            ("resource_policy_binding", "PET-RESOURCE-POLICY"),
            (
                "execution_authorization_digest",
                "PET-EXECUTION-AUTHORIZATION-BINDING",
            ),
        ):
            with self.subTest(field=field):
                mutated = copy.deepcopy(message)
                mutated["payload"][field] = "sha256:" + "ef" * 32
                mutated = populate_digests(mutated)
                with self.assertRaises(PetProfileError) as caught:
                    validate_operation_input(
                        self.values,
                        record,
                        canonical_message_bytes=canonicalize(mutated),
                    )
                self.assertEqual(code, caught.exception.code)

    def test_pet_error_code_catalog_has_exact_runtime_and_mutation_parity(self) -> None:
        validate_error_code_authority(self.values)
        catalog = json.loads((ROOT / ERROR_CODE_CATALOG_PATH).read_text())
        codes = [item["code"] for item in catalog["codes"]]
        semantics = {item["code"]: item["semantics"] for item in catalog["codes"]}
        self.assertEqual(len(codes), len(set(codes)))
        self.assertIn("PET-EVALUATION-TIME-AUTHORITY", codes)
        self.assertIn("PET-ABORT-PHASE-AUTHORITY", codes)
        self.assertIn(
            "state and presented timer time", semantics["PET-EVALUATION-TIME-AUTHORITY"]
        )
        self.assertIn(
            "noncanonical, nonmonotonic", semantics["PET-AUTHORITATIVE-TIME-ORDER"]
        )
        self.assertIn("has not reached", semantics["PET-EVALUATION-DEADLINE"])

    def test_timeout_requires_monotonic_time_at_or_after_deadline(self) -> None:
        item = next(
            entry
            for entry in self.values["cases"]["valid_cases"]
            if entry["operation"] == "evaluation-timeout"
        )
        accepted = operation_input_for_case(self.values, item)
        state = accepted["authoritative_context"]["initial_state"]
        operation = accepted["presented_operation"]
        self.assertEqual(state["authoritative_time"], operation["authoritative_time"])
        self.assertEqual(state["evaluation_deadline"], operation["evaluation_deadline"])
        self.assertEqual(
            "terminal",
            validate_operation_input(self.values, accepted)["protocol_outcome"],
        )
        for mutation, code in (
            ("timeout-before-deadline", "PET-EVALUATION-DEADLINE"),
            ("timeout-nonincreasing-time", "PET-AUTHORITATIVE-TIME-ORDER"),
            (
                "timeout-state-message-time-mismatch",
                "PET-EVALUATION-TIME-AUTHORITY",
            ),
            ("timeout-noncanonical-time", "PET-AUTHORITATIVE-TIME-ORDER"),
        ):
            with self.subTest(mutation=mutation):
                with self.assertRaises(PetProfileError) as caught:
                    validate_operation_input(
                        self.values,
                        conformance_input_for_mutation(self.values, mutation),
                    )
                self.assertEqual(code, caught.exception.code)

    def test_receipt_acknowledgment_requires_both_contributions(self) -> None:
        record = conformance_input_for_mutation(
            self.values, "receipt-ack-before-contributions"
        )
        with self.assertRaises(PetProfileError) as caught:
            validate_operation_input(self.values, record)
        self.assertEqual("PET-CONTRIBUTIONS-INCOMPLETE", caught.exception.code)

    def test_abort_accepts_every_reviewed_source_phase_and_preserves_consumed_budget(
        self,
    ) -> None:
        cases = [
            entry
            for entry in self.values["cases"]["valid_cases"]
            if entry["operation"] == "abort-and-cleanup"
        ]
        self.assertEqual(14, len(cases))
        self.assertEqual(
            set(ABORT_PHASE_ORDER), {item["abort_source_phase"] for item in cases}
        )
        for item in cases:
            with self.subTest(phase=item["abort_source_phase"]):
                record = operation_input_for_case(self.values, item)
                result = validate_operation_input(self.values, record)
                self.assertEqual("terminal", result["protocol_outcome"])
                expected_effect = (
                    "preserve-consumed"
                    if item["abort_source_phase"]
                    in {
                        "EVALUATING",
                        "RESULT_ACCEPTED",
                        "CONSENT_PENDING",
                        "DISCLOSURE_AUTHORIZED",
                    }
                    else "release-if-not-started"
                )
                self.assertEqual(expected_effect, result["query_budget_effect"])
        evaluating = [
            item for item in cases if item["abort_source_phase"] == "EVALUATING"
        ]
        self.assertEqual(7, len(evaluating))
        self.assertEqual(
            set(EVALUATING_ACKNOWLEDGMENT_SUBSTATE_ORDER),
            {item["abort_acknowledgment_substate"] for item in evaluating},
        )
        for item in evaluating:
            with self.subTest(substate=item["abort_acknowledgment_substate"]):
                record = operation_input_for_case(self.values, item)
                state = record["authoritative_context"]["initial_state"]
                self.assertEqual(
                    item["abort_acknowledgment_substate"],
                    state["acknowledgment_substate_id"],
                )
                self.assertEqual(
                    "terminal",
                    validate_operation_input(self.values, record)["protocol_outcome"],
                )
        with self.assertRaises(PetProfileError) as caught:
            validate_operation_input(
                self.values,
                conformance_input_for_mutation(
                    self.values, "abort-evaluating-unconsumed"
                ),
            )
        self.assertEqual("PET-QUERY-BUDGET", caught.exception.code)

    def test_abort_evaluating_acknowledgment_state_is_atomic_and_fail_closed(
        self,
    ) -> None:
        evaluating = {
            item["abort_acknowledgment_substate"]: item
            for item in self.values["cases"]["valid_cases"]
            if item["operation"] == "abort-and-cleanup"
            and item["abort_source_phase"] == "EVALUATING"
        }
        expected_slots = {
            "contributions-none": ([], []),
            "contribution-a-only": (["party_a"], []),
            "contribution-b-only": (["party_b"], []),
            "contributions-complete-no-ack": (["party_a", "party_b"], []),
            "party-a-acknowledged": (["party_a", "party_b"], ["party_a"]),
            "party-b-acknowledged": (["party_a", "party_b"], ["party_b"]),
            "both-acknowledged": (
                ["party_a", "party_b"],
                ["party_a", "party_b"],
            ),
        }
        for substate, (contributions, acknowledgments) in expected_slots.items():
            with self.subTest(substate=substate):
                record = operation_input_for_case(self.values, evaluating[substate])
                state = record["authoritative_context"]["initial_state"]
                self.assertEqual(contributions, state["completed_contribution_slots"])
                self.assertEqual(acknowledgments, state["receipt_acknowledgment_slots"])
                self.assertEqual(
                    "sha256:" + "76" * 32 if acknowledgments else None,
                    state["opaque_receipt_ref"],
                )
                self.assertEqual(
                    "PROPOSED" if acknowledgments else None,
                    state["result_state"],
                )
                self.assertEqual(
                    {"party_a": "NONE", "party_b": "NONE"},
                    state["accepted_result_presence"],
                )
                for party in ("party_a", "party_b"):
                    expected = "PRESENT" if party in acknowledgments else "NONE"
                    self.assertEqual(expected, state["proposed_result_presence"][party])
                    binding = state["result_acknowledgment_bindings"][party]
                    self.assertEqual(party in acknowledgments, binding is not None)
                    if binding:
                        self.assertEqual(
                            state["opaque_receipt_ref"], binding["opaque_receipt_ref"]
                        )
                        self.assertEqual(state["session_id"], binding["session_id"])
                        self.assertEqual(
                            state["evaluation_attempt_id"],
                            binding["evaluation_attempt_id"],
                        )
                        self.assertEqual(
                            _acknowledgment_evidence_digest(binding),
                            binding["profile_evidence_binding_digest"],
                        )
                self.assertEqual(
                    "terminal",
                    validate_operation_input(self.values, record)["protocol_outcome"],
                )

        for mutation, expected in (
            ("abort-evaluating-ack-missing-receipt", "PET-RECEIPT-BINDING"),
            (
                "abort-evaluating-ack-missing-proposed-result",
                "PET-ABORT-PHASE-AUTHORITY",
            ),
            (
                "abort-evaluating-unacknowledged-future-receipt",
                "PET-RECEIPT-BINDING",
            ),
        ):
            with self.subTest(mutation=mutation):
                with self.assertRaises(PetProfileError) as caught:
                    validate_operation_input(
                        self.values,
                        conformance_input_for_mutation(self.values, mutation),
                    )
                self.assertEqual(expected, caught.exception.code)

        changed = copy.deepcopy(self.values)
        ack_a = next(
            transition
            for transition in changed["state_machine"]["transitions"]
            if transition["id"] == "TR-ACK-RECEIPT-A"
        )
        effect = next(
            item for item in ack_a["effects"] if item["id"] == "E-ACK-RECEIPT-A"
        )
        effect["writes"].remove("opaque_receipt_ref")
        with self.assertRaisesRegex(PetProfileError, "PET-ABORT-PHASE-AUTHORITY"):
            expected_operation_stage_contract(changed)

        changed = copy.deepcopy(self.values)
        contribution_a = next(
            transition
            for transition in changed["state_machine"]["transitions"]
            if transition["id"] == "TR-SUBMIT-CONTRIBUTION-A"
        )
        contribution_effect = next(
            item
            for item in contribution_a["effects"]
            if item["id"] == "E-CONTRIBUTION-A"
        )
        contribution_effect["writes"] = []
        with self.assertRaisesRegex(PetProfileError, "PET-ABORT-PHASE-AUTHORITY"):
            expected_operation_stage_contract(changed)

        changed = copy.deepcopy(self.values)
        abort = next(
            transition
            for transition in changed["state_machine"]["transitions"]
            if transition["id"] == "TR-ABORT"
        )
        abort["effects"][0]["writes"].append("opaque_receipt_ref")
        with self.assertRaisesRegex(PetProfileError, "PET-ABORT-PHASE-AUTHORITY"):
            expected_operation_stage_contract(changed)

    def test_acknowledged_abort_state_never_exposes_party_local_results(self) -> None:
        cases = [
            item
            for item in self.values["cases"]["valid_cases"]
            if item.get("abort_acknowledgment_substate")
            in {
                "party-a-acknowledged",
                "party-b-acknowledged",
                "both-acknowledged",
            }
        ]
        self.assertEqual(3, len(cases))
        for item in cases:
            record = operation_input_for_case(self.values, item)
            serialized = json.dumps(record["authoritative_context"]["initial_state"])
            for prohibited in (*PROTOCOL_OUTPUTS, "party_local_result", "exact_count"):
                self.assertNotIn(prohibited, serialized)
            self.assertNotIn("synthetic_conformance_observer", serialized)

    def test_party_decision_vocabulary_is_closed_before_symmetry(self) -> None:
        record = conformance_input_for_mutation(
            self.values, "unknown-symmetric-decision"
        )
        with self.assertRaises(PetProfileError) as caught:
            validate_operation_input(self.values, record)
        self.assertEqual("PET-DECISION-UNKNOWN", caught.exception.code)
        callback_case = next(
            item
            for item in self.values["cases"]["valid_cases"]
            if item["operation"] == "accept-profile-callback"
        )
        accepted = operation_input_for_case(self.values, callback_case)
        self.assertEqual(
            {"party_a": "MATCH", "party_b": "MATCH"},
            accepted["synthetic_conformance_observer"][
                "party_local_result_observations"
            ],
        )
        self.assertNotIn("party_results", accepted["presented_operation"])
        validate_operation_input(self.values, accepted)

    def test_party_result_slots_and_types_fail_closed(self) -> None:
        item = next(
            entry
            for entry in self.values["cases"]["valid_cases"]
            if entry["operation"] == "accept-profile-callback"
        )
        for name, results, code in (
            ("missing", {"party_a": "MATCH"}, "PET-PARTY-SLOT-SET"),
            (
                "extra",
                {"party_a": "MATCH", "party_b": "MATCH", "party_c": "MATCH"},
                "PET-PARTY-SLOT-SET",
            ),
            (
                "lowercase",
                {"party_a": "match", "party_b": "match"},
                "PET-DECISION-UNKNOWN",
            ),
            (
                "null",
                {"party_a": None, "party_b": None},
                "PET-DECISION-UNKNOWN",
            ),
            (
                "numeric",
                {"party_a": 1, "party_b": 1},
                "PET-DECISION-UNKNOWN",
            ),
        ):
            with self.subTest(name=name):
                record = operation_input_for_case(self.values, item)
                record["synthetic_conformance_observer"][
                    "party_local_result_observations"
                ] = results
                with self.assertRaises(PetProfileError) as caught:
                    validate_operation_input(self.values, record)
                self.assertEqual(code, caught.exception.code)

    def test_policy_and_execution_contracts_are_closed(self) -> None:
        for identifier in COMPLETE_PROFILE_IDS:
            profile = self.values["profiles"][identifier]
            policy = profile["decision_derivation"]
            self.assertEqual("Protocol-policy-binding", policy["authority"])
            self.assertTrue(policy["exact_policy_binding_required"])
            self.assertFalse(policy["profile_may_select_default_policy"])
            self.assertFalse(policy["profile_may_change_policy_after_evaluation_start"])
        for profile in self.values["profiles"].values():
            execution = profile["execution_contract"]
            self.assertTrue(execution["contract_registration_allowed"])
            self.assertTrue(execution["synthetic_contract_fixture_allowed"])
            self.assertFalse(execution["candidate_execution_authorized"])
            self.assertFalse(execution["production_execution_authorized"])

    def test_redigested_execution_authorization_substitution_fails(self) -> None:
        item = next(
            entry
            for entry in self.values["cases"]["valid_cases"]
            if entry["operation"] == "start-evaluation"
        )
        record = operation_input_for_case(self.values, item)
        context = record["authoritative_context"]
        operation = record["presented_operation"]
        context["execution_authorization"]["environment_id"] = "unreviewed-live"
        profile = self.values["profiles"][context["profile_authority"]["profile_id"]]
        digest = _execution_authorization_digest(
            profile,
            context["profile_authority"]["profile_instance_id"],
            context["execution_authorization"],
        )
        context["execution_authorization"]["authority_digest"] = digest
        operation["execution_authorization_digest"] = digest
        with self.assertRaisesRegex(
            PetProfileError, "PET-EXECUTION-AUTHORIZATION-BINDING"
        ):
            validate_operation_input(self.values, record)

    def test_one_canonical_callback_operation_and_no_alias_exists(self) -> None:
        binding = self.values["binding"]
        callback = [
            item
            for item in binding["operations"]
            if item["message_type"] == "result_acceptance_notice"
        ]
        self.assertEqual(
            ["accept-profile-callback"], [item["operation"] for item in callback]
        )
        self.assertNotIn(
            "accept-symmetric-result",
            {item["operation"] for item in binding["operations"]},
        )
        self.assertEqual(["accept_symmetric_result"], callback[0]["events"])

    def test_redigested_duplicate_alias_and_unrelated_mapping_fail_closed(self) -> None:
        duplicate = copy.deepcopy(self.values)
        alias = copy.deepcopy(
            next(
                item
                for item in duplicate["binding"]["operations"]
                if item["operation"] == "accept-profile-callback"
            )
        )
        alias["operation"] = "unreviewed-callback-alias"
        duplicate["binding"]["operations"].append(alias)
        duplicate["binding"]["binding_digest"] = detached_digest(
            "binding", duplicate["binding"], "binding_digest"
        )
        with self.assertRaisesRegex(PetProfileError, "PET-BINDING-DUPLICATE-ALIAS"):
            validate_semantics(duplicate)

        unrelated = copy.deepcopy(self.values)
        callback = next(
            item
            for item in unrelated["binding"]["operations"]
            if item["operation"] == "accept-profile-callback"
        )
        callback["message_type"] = "abort_notice"
        unrelated["binding"]["binding_digest"] = detached_digest(
            "binding", unrelated["binding"], "binding_digest"
        )
        with self.assertRaisesRegex(
            PetProfileError, "PET-(BINDING-SEMANTICS|STAGE-MESSAGE-PARITY)"
        ):
            validate_semantics(unrelated)

    def test_canonical_result_acceptance_notice_passes_both_validators(self) -> None:
        item = next(
            entry
            for entry in self.values["cases"]["valid_cases"]
            if entry["canonical_message_path"] is not None
        )
        record = operation_input_for_case(self.values, item)
        self.assertEqual(
            "accepted",
            validate_operation_input(self.values, record)["protocol_outcome"],
        )
        raw = (ROOT / CANONICAL_CALLBACK_PATH).read_bytes()
        self.assertEqual(canonicalize(strict_loads(raw)), raw)

    def test_canonical_callback_substitutions_fail_closed(self) -> None:
        item = next(
            entry
            for entry in self.values["cases"]["valid_cases"]
            if entry["canonical_message_path"] is not None
        )
        record = operation_input_for_case(self.values, item)
        original = strict_loads((ROOT / CANONICAL_CALLBACK_PATH).read_bytes())
        mutations = {
            "session": lambda message: message["identity"].__setitem__(
                "session_id", "urn:private-match:test:session:other"
            ),
            "policy": lambda message: message["session_context"]["policy"].__setitem__(
                "policy_id", "urn:private-match:test:policy:other"
            ),
            "profile": lambda message: message["identity"].__setitem__(
                "profile_id", "private-match-experimental-secretflow-kkrt"
            ),
            "instance": lambda message: message["identity"].__setitem__(
                "profile_instance_id", "urn:private-match:test:profile-instance:other"
            ),
            "attempt": lambda message: message["identity"].__setitem__(
                "evaluation_attempt_id", "urn:private-match:test:evaluation:other"
            ),
            "receipt": lambda message: message["payload"].__setitem__(
                "opaque_receipt_ref", "sha256:" + "99" * 32
            ),
            "transcript": lambda message: message.__setitem__(
                "prior_transcript_digest", "sha256:" + "98" * 32
            ),
            "material": lambda message: message["authentication"].__setitem__(
                "verification_material_id", "urn:private-match:test:material:other"
            ),
            "delivery": lambda message: message.__setitem__(
                "delivery_class", "party_message"
            ),
            "sender": lambda message: message["sender"].__setitem__(
                "actor", "coordinator"
            ),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                message = copy.deepcopy(original)
                mutate(message)
                message = populate_digests(message)
                with self.assertRaises(PetProfileError) as caught:
                    validate_operation_input(
                        self.values,
                        record,
                        canonical_message_bytes=canonicalize(message),
                    )
                self.assertIn(
                    caught.exception.code,
                    {"PET-CANONICAL-MESSAGE-INVALID", "PET-RECEIPT-BINDING"},
                )

    def test_every_catalogued_negative_case_fails_with_stable_code(self) -> None:
        catalog = {
            item["mutation"]: item["expected_error"]
            for item in self.values["cases"]["invalid_cases"]
        }
        self.assertEqual(INVALID_CASE_CODES, catalog)
        for mutation in INVALID_CASE_CODES:
            with self.subTest(mutation=mutation):
                item = next(
                    x
                    for x in self.values["cases"]["invalid_cases"]
                    if x["mutation"] == mutation
                )
                self.assertEqual(INVALID_CASE_CODES[mutation], item["expected_error"])
        # validate_case_catalog executes all invalid paths through the shared validator.
        self.assertEqual(25, len(validate_case_catalog(self.values)))

    def test_cross_profile_instance_attempt_receipt_and_transcript_fail_closed(
        self,
    ) -> None:
        selected = {
            "cross-profile-callback",
            "wrong-profile-instance",
            "wrong-evaluation-attempt",
            "wrong-receipt",
            "wrong-transcript-head",
        }
        for mutation in selected:
            with self.subTest(mutation=mutation):
                record = conformance_input_for_mutation(self.values, mutation)
                with self.assertRaises(PetProfileError):
                    validate_conformance_input(self.values, record)

    def test_profile_redigest_cannot_enable_production_or_weaken_cleanup(self) -> None:
        for mutation in ("production", "cleanup"):
            with self.subTest(mutation=mutation):
                values = copy.deepcopy(self.values)
                profile = values["profiles"][
                    "private-match-experimental-secretflow-kkrt"
                ]
                if mutation == "production":
                    profile["production_eligible"] = True
                else:
                    profile["privacy_and_operations"]["cleanup"]["required"] = False
                profile["profile_digest"] = detached_digest(
                    "profile", profile, "profile_digest"
                )
                with self.assertRaises(PetProfileError):
                    validate_semantics(values)

    def test_fully_redigested_binding_and_profile_policy_mutations_fail(self) -> None:
        for mutation, expected in (
            ("binding-event", "PET-(BINDING-SEMANTICS|STAGE-MESSAGE-PARITY)"),
            ("profile-exchange", "PET-PROTOCOL-EXCHANGE-BINDING"),
            ("second-secret-evidence-hook", "PET-EVIDENCE-SECRET"),
        ):
            with self.subTest(mutation=mutation):
                values = copy.deepcopy(self.values)
                if mutation == "binding-event":
                    values["binding"]["operations"][0]["events"] = ["abort_session"]
                    values["binding"]["binding_digest"] = detached_digest(
                        "binding", values["binding"], "binding_digest"
                    )
                else:
                    identifier = "private-match-experimental-secretflow-kkrt"
                    profile = values["profiles"][identifier]
                    if mutation == "profile-exchange":
                        profile["protocol_contract"]["exchange_steps"][0]["events"] = [
                            "abort_session"
                        ]
                    else:
                        added = copy.deepcopy(
                            profile["protocol_contract"]["evidence_hooks"][0]
                        )
                        added["hook_id"] = "unreviewed-second-hook"
                        added["allowed_fields"] = ["private_input"]
                        profile["protocol_contract"]["evidence_hooks"].append(added)
                    profile["profile_digest"] = detached_digest(
                        "profile", profile, "profile_digest"
                    )
                    for entry in values["registry"]["complete_profiles"]:
                        if entry["profile_id"] == identifier:
                            entry["digest"] = profile["profile_digest"]
                    values["registry"]["registry_digest"] = detached_digest(
                        "registry", values["registry"], "registry_digest"
                    )
                with self.assertRaisesRegex(PetProfileError, expected):
                    validate_semantics(values)

    def test_unknown_failure_and_secret_evidence_never_expose_values(self) -> None:
        for mutation in ("unknown-error-category", "secret-evidence-hook"):
            with self.assertRaises(PetProfileError) as caught:
                _execute_invalid_case(self.values, mutation)
            message = str(caught.exception)
            self.assertLessEqual(len(message), 128)
            self.assertNotIn("VENDOR_RAW_FAILURE", message)
            self.assertNotIn("private_input", message)

    def test_generator_is_byte_deterministic_and_check_only(self) -> None:
        first = generated_files(ROOT)
        second = generated_files(ROOT)
        self.assertEqual(first, second)
        self.assertEqual(30, len(first))
        self.assertTrue(set(GENERATED_PATHS.values()) <= set(first))
        for relative, content in first.items():
            self.assertEqual(content, (ROOT / relative).read_bytes(), relative)
        self.assertEqual(0, generate_main(["--root", str(ROOT), "--check"]))

    def test_generated_manifest_binds_every_behavior_input_and_output(self) -> None:
        manifest = json.loads(
            (ROOT / GENERATED_PATHS["manifest"]).read_text(encoding="utf-8")
        )
        input_paths = {item["path"] for item in manifest["behavior_inputs"]}
        self.assertTrue({str(path) for path in PROFILE_PATHS.values()} <= input_paths)
        self.assertTrue({str(path) for path in SCHEMAS.values()} <= input_paths)
        self.assertIn(str(HANDOFF_PATH), input_paths)
        self.assertIn(str(BINDING_PATH), input_paths)
        self.assertIn(str(CASE_CATALOG_PATH), input_paths)
        self.assertIn("scripts/canonicalize_message.py", input_paths)
        self.assertIn("scripts/strict_yaml.py", input_paths)
        self.assertIn("requirements-build.txt", input_paths)
        self.assertIn("requirements-dev.txt", input_paths)
        self.assertIn(
            "specs/state-machines/private-match-core-session-v0.1.yaml", input_paths
        )
        self.assertIn("registry/message-types.v0.1.yaml", input_paths)
        self.assertIn("schemas/messages/envelope.v0.1.schema.json", input_paths)
        self.assertIn("scripts/validate_messages.py", input_paths)
        self.assertIn("scripts/generate_message_vectors.py", input_paths)
        self.assertIn("tests/test_message_contracts.py", input_paths)
        self.assertIn(
            "conformance/source/message-conformance-inputs.v0.1.json", input_paths
        )
        self.assertEqual(29, len(manifest["generated_outputs"]))

    def _repository_copy(self):
        scratch = ROOT / "artifacts"
        scratch.mkdir(exist_ok=True)
        temporary = tempfile.TemporaryDirectory(dir=scratch)
        base = Path(temporary.name) / "repository"
        shutil.copytree(
            ROOT,
            base,
            ignore=shutil.ignore_patterns(
                ".git",
                ".codex-local",
                ".worktrees",
                "artifacts",
                "__pycache__",
                "*.pyc",
            ),
        )
        return temporary, base

    def test_missing_changed_and_symlinked_authority_files_fail_closed(self) -> None:
        for mutation in ("missing", "changed", "symlink"):
            with self.subTest(mutation=mutation):
                temporary, base = self._repository_copy()
                try:
                    target = (
                        base
                        / PROFILE_PATHS["private-match-experimental-secretflow-kkrt"]
                    )
                    if mutation == "missing":
                        target.unlink()
                    elif mutation == "changed":
                        target.write_bytes(target.read_bytes() + b" ")
                    else:
                        target.unlink()
                        target.symlink_to(base / AUTHORITY_PATH)
                    with self.assertRaises(PetProfileError):
                        validate_repository(base)
                finally:
                    temporary.cleanup()

    def test_public_contract_code_has_no_candidate_network_or_cloud_execution(
        self,
    ) -> None:
        source = (ROOT / "scripts/pet_profiles.py").read_text(encoding="utf-8")
        for forbidden in (
            "subprocess.",
            "socket.",
            "requests.",
            "boto3",
            "aws nitro-enclaves",
            "secretflow.psi",
            "circl.oprf",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, source)

    def test_workflow_keeps_profile_validation_read_only_and_offline(self) -> None:
        workflow = (ROOT / ".github/workflows/protocol-spec.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("permissions:\n  contents: read", workflow)
        self.assertIn("persist-credentials: false", workflow)
        self.assertIn("timeout-minutes: 10", workflow)
        self.assertIn("generate_pet_profiles.py --root . --check", workflow)
        self.assertIn("validate_pet_profiles.py --root .", workflow)
        for forbidden in (
            "actions/upload-artifact",
            "aws-actions/",
            "configure-aws-credentials",
            "gh release",
            "git push",
            "repository:",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, workflow)

    def test_registry_is_child_only_experimental_and_component_closed(self) -> None:
        registry = self.values["registry"]
        self.assertEqual(
            sorted(COMPLETE_PROFILE_IDS),
            [item["profile_id"] for item in registry["complete_profiles"]],
        )
        self.assertEqual(
            sorted(COMPONENT_PROFILE_IDS),
            [item["profile_id"] for item in registry["component_profiles"]],
        )
        self.assertEqual(
            "fail-closed",
            registry["compatibility"]["component_selection_behavior"],
        )

    def test_registry_schema_closes_complete_and_component_profile_classes(
        self,
    ) -> None:
        schema = self.values["schemas"]["registry"]
        for collection, wrong_class in (
            ("complete_profiles", "component-only"),
            ("component_profiles", "complete-decision-profile"),
        ):
            with self.subTest(collection=collection):
                mutated = copy.deepcopy(self.values["registry"])
                mutated[collection][0]["profile_class"] = wrong_class
                self.assertTrue(list(Draft202012Validator(schema).iter_errors(mutated)))


if __name__ == "__main__":
    unittest.main()
