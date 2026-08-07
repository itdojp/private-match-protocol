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
    BINDING_PATH,
    CALLBACK_BINDINGS,
    CASE_CATALOG_PATH,
    COMPLETE_PROFILE_IDS,
    COMPONENT_PROFILE_IDS,
    GENERATED_PATHS,
    HANDOFF_PATH,
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
    PetProfileError,
    conformance_input_for_mutation,
    detached_digest,
    generated_files,
    load_repository,
    validate_conformance_input,
    validate_repository,
    validate_semantics,
)
from strict_yaml import strict_yaml_load  # noqa: E402


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
        events = {item["id"] for item in state_machine["events"]}
        transitions = {item["id"] for item in state_machine["transitions"]}
        messages = {item["message_type"] for item in message_registry["messages"]}
        binding = self.values["binding"]
        self.assertEqual(STATE_MACHINE_DIGEST, binding["state_machine_digest"])
        self.assertEqual(MESSAGE_REGISTRY_DIGEST, binding["message_registry_digest"])
        for operation in binding["operations"]:
            with self.subTest(operation=operation["operation"]):
                self.assertIn(operation["event"], events)
                self.assertTrue(set(operation["transition_ids"]) <= transitions)
                if operation["message_type"] is not None:
                    self.assertIn(operation["message_type"], messages)
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
        self.assertEqual(14, len(handoff["port_fields"]))
        self.assertTrue(handoff["selection_rule"]["complete_profile_required"])
        self.assertTrue(handoff["selection_rule"]["component_only_rejected"])
        serialized = json.dumps(handoff)
        self.assertNotIn("private-match-product/", serialized)
        self.assertNotIn("src/", serialized)

    def test_valid_synthetic_cases_never_execute_a_candidate(self) -> None:
        cases = self.values["cases"]
        self.assertTrue(cases["synthetic"])
        self.assertEqual("prohibited", cases["network_execution"])
        self.assertEqual(8, len(cases["valid_cases"]))
        self.assertEqual(
            {"accepted"}, {item["expected"] for item in cases["valid_cases"]}
        )

    def test_every_catalogued_negative_case_fails_with_stable_code(self) -> None:
        profiles = self.values["profiles"]
        for mutation, expected in INVALID_CASE_CODES.items():
            with self.subTest(mutation=mutation):
                record = conformance_input_for_mutation(profiles, mutation)
                with self.assertRaises(PetProfileError) as caught:
                    validate_conformance_input(profiles, record)
                self.assertEqual(expected, caught.exception.code)
                self.assertNotIn(str(ROOT), str(caught.exception))

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
                record = conformance_input_for_mutation(
                    self.values["profiles"], mutation
                )
                with self.assertRaises(PetProfileError):
                    validate_conformance_input(self.values["profiles"], record)

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
            ("binding-event", "PET-BINDING-SEMANTICS"),
            ("profile-exchange", "PET-PROTOCOL-EXCHANGE-BINDING"),
            ("second-secret-evidence-hook", "PET-EVIDENCE-SECRET"),
        ):
            with self.subTest(mutation=mutation):
                values = copy.deepcopy(self.values)
                if mutation == "binding-event":
                    values["binding"]["operations"][0]["event"] = "abort_session"
                    values["binding"]["binding_digest"] = detached_digest(
                        "binding", values["binding"], "binding_digest"
                    )
                else:
                    identifier = "private-match-experimental-secretflow-kkrt"
                    profile = values["profiles"][identifier]
                    if mutation == "profile-exchange":
                        profile["protocol_contract"]["exchange_steps"][0]["event"] = (
                            "abort_session"
                        )
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
            record = conformance_input_for_mutation(self.values["profiles"], mutation)
            with self.assertRaises(PetProfileError) as caught:
                validate_conformance_input(self.values["profiles"], record)
            message = str(caught.exception)
            self.assertLessEqual(len(message), 128)
            self.assertNotIn("VENDOR_RAW_FAILURE", message)
            self.assertNotIn("private_input", message)

    def test_generator_is_byte_deterministic_and_check_only(self) -> None:
        first = generated_files(ROOT)
        second = generated_files(ROOT)
        self.assertEqual(first, second)
        self.assertEqual(set(GENERATED_PATHS.values()), set(first))
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
        self.assertEqual(3, len(manifest["generated_outputs"]))

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


if __name__ == "__main__":
    unittest.main()
