from __future__ import annotations

import unittest
from pathlib import Path

from scripts.validate_leakage_contract import load_contract, validate

ROOT = Path(__file__).resolve().parents[1]


class LeakageContractTests(unittest.TestCase):
    def test_repository_contract_is_valid(self):
        self.assertEqual(validate(ROOT), [])

    def test_core_contract_prohibits_raw_input_and_exact_count(self):
        contract = load_contract(ROOT / "privacy" / "leakage-contract.v0.1.yaml")
        self.assertEqual(
            contract["private_data_classes"]["raw_identifiers"]["allowed_transmission"],
            "none in core profile",
        )
        self.assertEqual(contract["minimum_disclosure_policy"]["exact_count"], "prohibited")
        self.assertEqual(contract["minimum_disclosure_policy"]["matching_elements"], "prohibited")
        self.assertEqual(contract["minimum_disclosure_policy"]["asymmetric_results"], "prohibited")

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


if __name__ == "__main__":
    unittest.main()
