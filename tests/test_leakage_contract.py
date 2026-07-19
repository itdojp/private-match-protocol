from __future__ import annotations

import copy
import datetime
import json
import unittest
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator

from scripts.validate_leakage_contract import NoDatesSafeLoader, load_contract, validate

ROOT = Path(__file__).resolve().parents[1]


class LeakageContractTests(unittest.TestCase):
    def test_repository_contract_is_valid(self):
        self.assertEqual(validate(ROOT), [])

    def test_no_dates_loader_does_not_change_safe_loader_date_resolution(self):
        document = "observed_at: 2026-07-19\n"

        custom_value = yaml.load(document, Loader=NoDatesSafeLoader)["observed_at"]
        safe_value = yaml.safe_load(document)["observed_at"]

        self.assertEqual(custom_value, "2026-07-19")
        self.assertIsInstance(custom_value, str)
        self.assertEqual(safe_value, datetime.date(2026, 7, 19))
        self.assertIsInstance(safe_value, datetime.date)

    def test_core_contract_prohibits_raw_input_and_exact_count(self):
        contract = load_contract(ROOT / "privacy" / "leakage-contract.v0.1.yaml")
        self.assertEqual(
            contract["artifact"]["decision_output"],
            "MATCH | NO_MATCH | INDETERMINATE",
        )
        self.assertEqual(
            contract["private_data_classes"]["raw_identifiers"]["allowed_transmission"],
            "none in core profile",
        )
        self.assertEqual(
            contract["minimum_disclosure_policy"]["exact_count"], "prohibited"
        )
        self.assertEqual(
            contract["minimum_disclosure_policy"]["matching_elements"], "prohibited"
        )
        self.assertEqual(
            contract["minimum_disclosure_policy"]["identity_reveal"],
            "prohibited in core profile",
        )
        self.assertEqual(
            contract["minimum_disclosure_policy"]["asymmetric_results"], "prohibited"
        )
        self.assertEqual(
            contract["shared_protocol_data"]["decision_receipt"]["allowed_values"],
            ["MATCH", "NO_MATCH", "INDETERMINATE"],
        )

    def test_coordinator_raw_input_and_outcome_are_not_permitted(self):
        contract = load_contract(ROOT / "privacy" / "leakage-contract.v0.1.yaml")
        prohibited = contract["actors"]["coordinator"]["prohibited_from_receiving"]
        self.assertIn("raw identifiers", prohibited)
        self.assertIn("normalized private inputs", prohibited)
        self.assertEqual(
            contract["actors"]["coordinator"]["outcome_visibility"],
            "prohibited-target; evidence required",
        )

    def test_claim_boundaries_remain_explicit(self):
        contract = load_contract(ROOT / "privacy" / "leakage-contract.v0.1.yaml")
        unsupported = contract["claims_not_supported_by_this_contract"]
        self.assertIn("zero leakage", unsupported)
        self.assertIn("malicious-party security", unsupported)
        self.assertIn("production readiness", unsupported)

    def test_authority_and_unresolved_boundaries_remain_explicit(self):
        contract = load_contract(ROOT / "privacy" / "leakage-contract.v0.1.yaml")
        self.assertEqual(
            contract["actors"]["coordinator"]["role"],
            "authoritative session, replay, query-budget, and audit-state coordinator",
        )
        self.assertEqual(
            contract["input_authenticity_and_completeness"]["protocol_guarantee"],
            "none in the core profile",
        )
        self.assertEqual(
            contract["collusion_and_compromise"]["coordinator_and_party_collusion"][
                "protection"
            ],
            "unresolved until PET integration profile selects a security model",
        )
        unresolved = contract["unresolved_decisions"]
        self.assertIn("selected PET and trust profile", unresolved)
        self.assertIn("coordinator outcome-confidentiality mechanism", unresolved)
        self.assertIn("authoritative dataset completeness mechanism", unresolved)
        self.assertIn("collusion threshold", unresolved)

    def test_schema_rejects_missing_required_disclosure_policy(self):
        schema = json.loads(
            (ROOT / "schema" / "leakage-contract.schema.json").read_text(
                encoding="utf-8"
            )
        )
        contract = copy.deepcopy(
            load_contract(ROOT / "privacy" / "leakage-contract.v0.1.yaml")
        )
        contract.pop("minimum_disclosure_policy")

        errors = list(Draft202012Validator(schema).iter_errors(contract))

        self.assertTrue(
            any(
                "'minimum_disclosure_policy' is a required property" in error.message
                for error in errors
            )
        )

    def test_schema_rejects_weakened_nested_security_controls(self):
        schema = json.loads(
            (ROOT / "schema" / "leakage-contract.schema.json").read_text(
                encoding="utf-8"
            )
        )
        contract = load_contract(ROOT / "privacy" / "leakage-contract.v0.1.yaml")
        cases = []

        weakened = copy.deepcopy(contract)
        weakened["minimum_disclosure_policy"]["exact_count"] = "allowed"
        cases.append(("exact count", weakened))

        weakened = copy.deepcopy(contract)
        weakened["minimum_disclosure_policy"]["matching_elements"] = "allowed"
        cases.append(("matching elements", weakened))

        weakened = copy.deepcopy(contract)
        weakened["minimum_disclosure_policy"]["identity_reveal"] = "allowed"
        cases.append(("identity reveal", weakened))

        weakened = copy.deepcopy(contract)
        weakened["minimum_disclosure_policy"]["asymmetric_results"] = "allowed"
        cases.append(("asymmetric result", weakened))

        weakened = copy.deepcopy(contract)
        weakened["repeated_query_controls"]["required_controls"].remove(
            "authoritative query budget per organization, participant, policy, and time window"
        )
        cases.append(("query budget", weakened))

        weakened = copy.deepcopy(contract)
        weakened["minimum_disclosure_policy"][
            "one_accepted_evaluation_per_commitment_pair"
        ] = "optional"
        cases.append(("commitment-pair replay", weakened))

        weakened = copy.deepcopy(contract)
        weakened["private_data_classes"]["raw_identifiers"]["allowed_transmission"] = (
            "coordinator"
        )
        cases.append(("raw input transmission", weakened))

        weakened = copy.deepcopy(contract)
        weakened["retention"].pop("raw_identifiers")
        cases.append(("raw identifier retention", weakened))

        weakened = copy.deepcopy(contract)
        weakened["collusion_and_compromise"]["coordinator_and_party_collusion"][
            "protection"
        ] = "provided"
        cases.append(("collusion status", weakened))

        weakened = copy.deepcopy(contract)
        weakened["input_authenticity_and_completeness"]["protocol_guarantee"] = (
            "complete and truthful"
        )
        cases.append(("input completeness", weakened))

        weakened = copy.deepcopy(contract)
        weakened["shared_protocol_data"]["decision_receipt"]["allowed_values"].append(
            "EXACT_COUNT"
        )
        cases.append(("decision output", weakened))

        weakened = copy.deepcopy(contract)
        weakened["unresolved_decisions"].remove(
            "coordinator outcome-confidentiality mechanism"
        )
        cases.append(("outcome confidentiality", weakened))

        for label, candidate in cases:
            with self.subTest(control=label):
                self.assertTrue(
                    list(Draft202012Validator(schema).iter_errors(candidate)),
                    f"schema accepted weakened control: {label}",
                )


if __name__ == "__main__":
    unittest.main()
