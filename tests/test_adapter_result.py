# SPDX-License-Identifier: Apache-2.0
"""Offline adapter-result comparison and safe-path contract tests."""

from __future__ import annotations

import copy
import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from compare_adapter_result import _load, compare, main  # noqa: E402
from conformance_common import (  # noqa: E402
    ConformanceError,
    FILE_SIZE_LIMIT,
    SUITE_ROOT,
    result_digest,
)


class AdapterResultTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.manifest = json.loads(
            (ROOT / SUITE_ROOT / "suite-manifest.v0.1.json").read_text()
        )
        entry = cls.manifest["cases"][0]
        cls.case = json.loads((ROOT / SUITE_ROOT / entry["path"]).read_text())
        cls.adapter_relative = (
            SUITE_ROOT / "fixtures/adapter-results/valid-end-to-end.v0.1.json"
        ).as_posix()
        cls.adapter = json.loads((ROOT / cls.adapter_relative).read_text())
        cls.schema = json.loads(
            (ROOT / "schema/conformance-adapter-result.v0.1.schema.json").read_text()
        )

    def _compare(self, adapter: dict | None = None) -> list[str]:
        return compare(
            ROOT,
            adapter or self.adapter,
            self.case,
            self.manifest,
            mode="test-fixture",
        )

    def test_fixed_adapter_result_matches_complete_surface(self) -> None:
        self.assertEqual([], self._compare())
        self.assertFalse(
            list(Draft202012Validator(self.schema).iter_errors(self.adapter))
        )

    def test_every_declared_binding_mutation_is_rejected_even_with_new_digest(
        self,
    ) -> None:
        mutations = {
            "suite": (
                lambda x: x["suite"].update(digest="sha256:" + "e" * 64),
                "CONFORMANCE-SUITE-DIGEST",
            ),
            "case": (
                lambda x: x["case"].update(digest="sha256:" + "e" * 64),
                "CONFORMANCE-CASE-DIGEST",
            ),
            "input": (
                lambda x: x["case"].update(input_digest="sha256:" + "e" * 64),
                "CONFORMANCE-CASE-DIGEST",
            ),
            "status": (
                lambda x: x.update(status="fail"),
                "CONFORMANCE-STATUS-MISMATCH",
            ),
            "outcome": (
                lambda x: x.update(protocol_outcome="rejected"),
                "CONFORMANCE-EXPECTED-MISMATCH",
            ),
            "errors": (
                lambda x: x.update(error_codes=["REPLAY_CONFLICT"]),
                "CONFORMANCE-ERROR-CODE-MISMATCH",
            ),
            "initial-state": (
                lambda x: x.update(initial_state_digest="sha256:" + "e" * 64),
                "CONFORMANCE-INITIAL-STATE-DIGEST-MISMATCH",
            ),
            "final-state": (
                lambda x: x.update(final_state_digest="sha256:" + "e" * 64),
                "CONFORMANCE-STATE-DIGEST-MISMATCH",
            ),
            "initial-head": (
                lambda x: x.update(initial_transcript_head="sha256:" + "e" * 64),
                "CONFORMANCE-INITIAL-TRANSCRIPT-DIGEST-MISMATCH",
            ),
            "final-head": (
                lambda x: x.update(final_transcript_head="sha256:" + "e" * 64),
                "CONFORMANCE-TRANSCRIPT-DIGEST-MISMATCH",
            ),
            "count": (
                lambda x: x.update(accepted_event_count=x["accepted_event_count"] + 1),
                "CONFORMANCE-ACCEPTED-COUNT-MISMATCH",
            ),
            "mutation": (
                lambda x: x["mutation_summary"].update(
                    state=not x["mutation_summary"]["state"]
                ),
                "CONFORMANCE-MUTATION-MISMATCH",
            ),
            "cached": (
                lambda x: x.update(cached_response_authorized=True),
                "CONFORMANCE-CACHED-RESPONSE-MISMATCH",
            ),
        }
        for name, (mutate, code) in mutations.items():
            with self.subTest(name=name):
                changed = copy.deepcopy(self.adapter)
                mutate(changed)
                changed["result_digest"] = result_digest(changed)
                self.assertIn(code, self._compare(changed))

    def test_result_digest_tamper_is_rejected(self) -> None:
        changed = copy.deepcopy(self.adapter)
        changed["result_digest"] = "sha256:" + "f" * 64
        self.assertIn("CONFORMANCE-ADAPTER-RESULT-DIGEST", self._compare(changed))

    def test_test_fixture_and_normal_modes_are_separate(self) -> None:
        self.assertIn(
            "CONFORMANCE-ADAPTER-MODE",
            compare(ROOT, self.adapter, self.case, self.manifest, mode="normal"),
        )
        changed = copy.deepcopy(self.adapter)
        changed["adapter_mode"] = "independent-result"
        changed["artifact_status"] = "draft"
        changed["adapter"]["id"] = "reviewed-independent-adapter"
        changed["limitations"] = ["Draft independent adapter limitation."]
        changed["result_digest"] = result_digest(changed)
        self.assertEqual(
            [], compare(ROOT, changed, self.case, self.manifest, mode="normal")
        )

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
                    self.assertIn("CONFORMANCE-STATUS-MISMATCH", self._compare(changed))

    def test_adapter_input_path_boundary_and_canonical_parse(self) -> None:
        scratch = ROOT / "artifacts"
        scratch.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as temporary:
            base = Path(temporary)
            relative_base = base.relative_to(ROOT)
            (base / "good.json").write_text("{}", encoding="utf-8")
            self.assertEqual({}, _load(ROOT, (relative_base / "good.json").as_posix()))
            (base / "noncanonical.json").write_text('{"x": 1}', encoding="utf-8")
            (base / "invalid.json").write_bytes(b"\xff")
            (base / "oversized.json").write_bytes(b" " * (FILE_SIZE_LIMIT + 1))
            (base / "directory").mkdir()
            (base / "final-link.json").symlink_to(base / "good.json")
            (base / "inside").mkdir()
            (base / "inside/value.json").write_text("{}", encoding="utf-8")
            (base / "intermediate-in").symlink_to(
                base / "inside", target_is_directory=True
            )
            (base / "intermediate-out").symlink_to(
                ROOT / "schema", target_is_directory=True
            )
            invalid = [
                "/absolute.json",
                "C:/windows.json",
                "a\\b.json",
                "a//b.json",
                "a/./b.json",
                "../escape.json",
                "a/../b.json",
                (relative_base / "missing.json").as_posix(),
                (relative_base / "directory").as_posix(),
                (relative_base / "final-link.json").as_posix(),
                (relative_base / "intermediate-in/value.json").as_posix(),
                (
                    relative_base / "intermediate-out/conformance-case.v0.1.schema.json"
                ).as_posix(),
                (relative_base / "noncanonical.json").as_posix(),
                (relative_base / "invalid.json").as_posix(),
                (relative_base / "oversized.json").as_posix(),
            ]
            for value in invalid:
                with self.subTest(value=value), self.assertRaises(ConformanceError):
                    _load(ROOT, value)

    def test_cli_path_failure_is_bounded_and_value_free(self) -> None:
        output = io.StringIO()
        with redirect_stderr(output):
            self.assertEqual(
                1,
                main(
                    [
                        "--root",
                        str(ROOT),
                        "--adapter-result",
                        "../private-value.json",
                        "--case-id",
                        self.case["case_id"],
                        "--mode",
                        "test-fixture",
                    ]
                ),
            )
        self.assertEqual("adapter-compare: error [bounded]\n", output.getvalue())
        self.assertNotIn("private-value", output.getvalue())

    def test_contract_has_no_executable_or_network_surface(self) -> None:
        wire = json.dumps(self.schema, sort_keys=True)
        self.assertNotIn("executable_path", wire)
        self.assertNotIn("command", wire)
        self.assertNotIn("network_endpoint", wire)


if __name__ == "__main__":
    unittest.main()
