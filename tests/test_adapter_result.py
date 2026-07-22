# SPDX-License-Identifier: Apache-2.0
"""Offline adapter-result contract tests."""

from __future__ import annotations

import copy
import json
import sys
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from compare_adapter_result import compare  # noqa: E402
from conformance_common import SUITE_ROOT, result_digest  # noqa: E402


class AdapterResultTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.manifest = json.loads(
            (ROOT / SUITE_ROOT / "suite-manifest.v0.1.json").read_text()
        )
        entry = cls.manifest["cases"][0]
        cls.case = json.loads((ROOT / SUITE_ROOT / entry["path"]).read_text())
        cls.adapter = json.loads(
            (
                ROOT
                / SUITE_ROOT
                / "fixtures/adapter-results/valid-end-to-end.v0.1.json"
            ).read_text()
        )
        cls.schema = json.loads(
            (ROOT / "schema/conformance-adapter-result.v0.1.schema.json").read_text()
        )

    def test_fixed_adapter_result_matches(self) -> None:
        self.assertEqual([], compare(ROOT, self.adapter, self.case, self.manifest))
        self.assertFalse(
            list(Draft202012Validator(self.schema).iter_errors(self.adapter))
        )

    def test_result_digest_tamper_is_rejected(self) -> None:
        changed = copy.deepcopy(self.adapter)
        changed["final_state_digest"] = "sha256:" + "f" * 64
        self.assertIn(
            "CONFORMANCE-ADAPTER-RESULT-DIGEST",
            compare(ROOT, changed, self.case, self.manifest),
        )

    def test_recomputed_tamper_still_mismatches_expected(self) -> None:
        changed = copy.deepcopy(self.adapter)
        changed["protocol_outcome"] = "rejected"
        changed["result_digest"] = result_digest(changed)
        self.assertIn(
            "CONFORMANCE-EXPECTED-MISMATCH",
            compare(ROOT, changed, self.case, self.manifest),
        )

    def test_suite_and_case_substitution_are_rejected(self) -> None:
        for field, code in (
            ("suite", "CONFORMANCE-SUITE-DIGEST"),
            ("case", "CONFORMANCE-CASE-DIGEST"),
        ):
            with self.subTest(field=field):
                changed = copy.deepcopy(self.adapter)
                changed[field]["digest"] = "sha256:" + "e" * 64
                changed["result_digest"] = result_digest(changed)
                self.assertIn(code, compare(ROOT, changed, self.case, self.manifest))

    def test_unknown_field_fails_closed_schema(self) -> None:
        changed = copy.deepcopy(self.adapter)
        changed["command"] = "not-allowed"
        self.assertTrue(list(Draft202012Validator(self.schema).iter_errors(changed)))

    def test_statuses_are_not_collapsed_by_schema(self) -> None:
        for status in ("pass", "fail", "skip", "unsupported", "timeout", "tool-error"):
            with self.subTest(status=status):
                changed = copy.deepcopy(self.adapter)
                changed["status"] = status
                changed["result_digest"] = result_digest(changed)
                self.assertFalse(
                    list(Draft202012Validator(self.schema).iter_errors(changed))
                )
                if status != "pass":
                    self.assertIn(
                        "CONFORMANCE-STATUS-MISMATCH",
                        compare(ROOT, changed, self.case, self.manifest),
                    )

    def test_contract_has_no_executable_or_network_surface(self) -> None:
        wire = json.dumps(self.schema, sort_keys=True)
        self.assertNotIn("executable_path", wire)
        self.assertNotIn("command", wire)
        self.assertNotIn("network_endpoint", wire)


if __name__ == "__main__":
    unittest.main()
