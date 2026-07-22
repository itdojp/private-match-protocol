# SPDX-License-Identifier: Apache-2.0
"""Execution and result tests for the reference verifier."""

from __future__ import annotations

import json
import tempfile
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from conformance_common import (  # noqa: E402
    SUITE_ROOT,
    case_digest,
    input_digest,
    result_digest,
)
from conformance_engine import execute_case  # noqa: E402
from run_conformance import build_result, main as run_main  # noqa: E402


class ReferenceVerifierTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.manifest = json.loads(
            (ROOT / SUITE_ROOT / "suite-manifest.v0.1.json").read_text()
        )

    def _case(self, vector_class: str) -> dict:
        entry = next(
            item
            for item in self.manifest["cases"]
            if item["vector_class"] == vector_class
        )
        return json.loads((ROOT / SUITE_ROOT / entry["path"]).read_text())

    def test_every_fixed_case_matches_reference_execution(self) -> None:
        for entry in self.manifest["cases"]:
            with self.subTest(case=entry["case_id"]):
                case = json.loads((ROOT / SUITE_ROOT / entry["path"]).read_text())
                actual = execute_case(ROOT, ROOT / SUITE_ROOT, case)
                self.assertEqual(case["expected"]["runner_status"], actual.status)
                self.assertEqual(
                    case["expected"]["protocol_outcome"], actual.protocol_outcome
                )
                self.assertEqual(case["expected"]["error_codes"], actual.error_codes)
                self.assertEqual(
                    case["expected"]["state_digest"], actual.final_state_digest
                )
                self.assertEqual(
                    case["expected"]["transcript_head"], actual.final_transcript_head
                )

    def test_all_six_runner_statuses_are_preserved(self) -> None:
        statuses = {
            self._case(item["vector_class"])["expected"]["runner_status"]
            for item in self.manifest["cases"]
        }
        self.assertEqual(
            {"pass", "fail", "skip", "unsupported", "timeout", "tool-error"},
            statuses,
        )

    def test_expected_negative_rejection_is_runner_pass(self) -> None:
        case = self._case("CV-WRONG-SESSION")
        self.assertEqual("pass", case["expected"]["runner_status"])
        self.assertEqual("rejected", case["expected"]["protocol_outcome"])

    def test_valid_outcome_variants_do_not_expose_plaintext_to_coordinator(
        self,
    ) -> None:
        for vector_class in (
            "CV-VALID-END-TO-END",
            "CV-VALID-NO-MATCH",
            "CV-VALID-INDETERMINATE",
        ):
            case = self._case(vector_class)
            wire = json.dumps(case, sort_keys=True)
            self.assertNotIn('"plaintext_result"', wire)
            self.assertIn(
                "plaintext Coordinator result", case["prohibited_observations"]
            )

    def test_exact_duplicate_is_noop_after_later_entries(self) -> None:
        case = self._case("CV-VALID-EXACT-DUPLICATE")
        actual = execute_case(ROOT, ROOT / SUITE_ROOT, case)
        trace = self._case("CV-VALID-END-TO-END")
        baseline = execute_case(ROOT, ROOT / SUITE_ROOT, trace)
        self.assertEqual("no-op", actual.protocol_outcome)
        self.assertEqual(baseline.final_transcript_head, actual.final_transcript_head)
        self.assertEqual(baseline.accepted_event_count, actual.accepted_event_count)

    def test_rejected_conflict_does_not_mutate_after_trace(self) -> None:
        case = self._case("CV-DUPLICATE-CONFLICT")
        actual = execute_case(ROOT, ROOT / SUITE_ROOT, case)
        baseline = execute_case(
            ROOT, ROOT / SUITE_ROOT, self._case("CV-VALID-END-TO-END")
        )
        self.assertEqual("rejected", actual.protocol_outcome)
        self.assertEqual(baseline.final_state_digest, actual.final_state_digest)
        self.assertEqual(baseline.final_transcript_head, actual.final_transcript_head)

    def test_session_expiry_is_atomic_terminal_transition(self) -> None:
        case = self._case("CV-VALID-EXPIRY")
        actual = execute_case(ROOT, ROOT / SUITE_ROOT, case)
        self.assertEqual("terminal", actual.protocol_outcome)
        self.assertEqual("EXPIRED", actual.terminal_phase)
        self.assertTrue(actual.mutation_summary["state"])
        self.assertTrue(actual.mutation_summary["transcript"])

    def test_result_bytes_and_digest_are_deterministic(self) -> None:
        case = self._case("CV-VALID-END-TO-END")
        first = build_result(ROOT, self.manifest, case)
        second = build_result(ROOT, self.manifest, case)
        self.assertEqual(first, second)
        self.assertEqual(first["result_digest"], result_digest(first))
        self.assertNotIn("timestamp", first)
        self.assertNotIn("hostname", first)

    def test_unknown_algorithm_remains_unsupported(self) -> None:
        case = self._case("CV-UNKNOWN-ALGORITHM")
        result = build_result(ROOT, self.manifest, case)
        self.assertEqual("unsupported", result["status"])
        self.assertEqual("not-evaluated", result["protocol_outcome"])
        self.assertIn("CONFORMANCE-ADAPTER-UNSUPPORTED", result["error_codes"])

    def test_unknown_case_and_absolute_output_fail_without_output(self) -> None:
        scratch = ROOT / "artifacts"
        scratch.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as temporary:
            output = Path(temporary) / "unknown"
            self.assertEqual(
                1,
                run_main(
                    [
                        "--root",
                        str(ROOT),
                        "--case-id",
                        "PMC-UNKNOWN-V0-1",
                        "--output-dir",
                        output.relative_to(ROOT).as_posix(),
                    ]
                ),
            )
            self.assertFalse(output.exists())
            self.assertEqual(
                1,
                run_main(
                    [
                        "--root",
                        str(ROOT),
                        "--case-id",
                        "PMC-VALID-END-TO-END-V0-1",
                        "--output-dir",
                        str(output.resolve()),
                    ]
                ),
            )

    def test_fixture_digest_is_part_of_input_and_case_identity(self) -> None:
        case = self._case("CV-VALID-END-TO-END")
        changed = json.loads(json.dumps(case))
        changed["ordered_inputs"][0]["fixture_digest"] = "sha256:" + "f" * 64
        self.assertNotEqual(case["conformance_input_digest"], input_digest(changed))
        self.assertNotEqual(case["case_digest"], case_digest(changed))


if __name__ == "__main__":
    unittest.main()
