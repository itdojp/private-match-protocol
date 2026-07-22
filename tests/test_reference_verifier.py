# SPDX-License-Identifier: Apache-2.0
"""Executable vector, status derivation, oracle, and transaction tests."""

from __future__ import annotations

import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))
from conformance_common import (  # noqa: E402
    ConformanceError,
    SUITE_ROOT,
    conformance_state_projection,
    result_digest,
    run_set_digest,
    sha256_bytes,
    state_digest,
)
from conformance_engine import compare_actual_to_expected, execute_case  # noqa: E402
from run_conformance import (  # noqa: E402
    _result_name,
    _run_set_manifest,
    build_result,
    main as run_main,
    validate_staged_run_set,
)
from validate_messages import AbstractStateRunner, TranscriptState  # noqa: E402


class ReferenceVerifierTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.manifest = json.loads(
            (ROOT / SUITE_ROOT / "suite-manifest.v0.1.json").read_text()
        )
        cls.case_schema = json.loads(
            (ROOT / "schema/conformance-case.v0.1.schema.json").read_text()
        )

    def _case(self, vector_class: str) -> dict:
        entry = next(
            item
            for item in self.manifest["cases"]
            if item["vector_class"] == vector_class
        )
        return json.loads((ROOT / SUITE_ROOT / entry["path"]).read_text())

    def _initial(self):
        context = json.loads(
            (ROOT / SUITE_ROOT / "fixtures/context.v0.1.json").read_text()
        )
        return AbstractStateRunner(context), TranscriptState()

    def test_state_projection_is_closed_interoperable_and_order_independent(
        self,
    ) -> None:
        runner, transcript = self._initial()
        schema = json.loads(
            (ROOT / "schema/conformance-state-projection.v0.1.schema.json").read_text()
        )
        projection = conformance_state_projection(runner, transcript.dedup)
        self.assertFalse(list(Draft202012Validator(schema).iter_errors(projection)))

        def alternate(value):
            if isinstance(value, dict):
                return SimpleNamespace(
                    **{
                        key: alternate(item)
                        for key, item in reversed(list(value.items()))
                    }
                )
            if isinstance(value, list):
                return [alternate(item) for item in value]
            return value

        alternate_runner = alternate(runner.__dict__)
        alternate_runner.base_context.session_context.intended_audience = list(
            reversed(runner.base_context["session_context"]["intended_audience"])
        )
        self.assertEqual(
            projection,
            conformance_state_projection(alternate_runner, {}),
        )
        runner.implementation_only_cache = {"opaque": object()}
        self.assertEqual(
            projection, conformance_state_projection(runner, transcript.dedup)
        )

        changed = copy.deepcopy(projection)
        changed["unexpected"] = "closed"
        self.assertTrue(list(Draft202012Validator(schema).iter_errors(changed)))

    def test_state_projection_digest_separates_transcript_and_logical_state(
        self,
    ) -> None:
        runner, transcript = self._initial()
        baseline = state_digest(runner, transcript)
        initial_head = transcript.head
        transcript.head = "sha256:" + "f" * 64
        transcript.accepted_event_index = 99
        self.assertEqual(baseline, state_digest(runner, transcript))
        self.assertEqual(
            {"state": False, "transcript": True},
            {
                "state": baseline != state_digest(runner, transcript),
                "transcript": initial_head != transcript.head,
            },
        )
        runner.phase = "CREATED"
        self.assertNotEqual(baseline, state_digest(runner, transcript))

        match = execute_case(ROOT, ROOT / SUITE_ROOT, self._case("CV-VALID-END-TO-END"))
        no_match = execute_case(
            ROOT, ROOT / SUITE_ROOT, self._case("CV-VALID-NO-MATCH")
        )
        self.assertNotEqual(match.final_state_digest, no_match.final_state_digest)
        self.assertEqual(
            match.initial_state_digest,
            self._case("CV-VALID-END-TO-END")["expected"]["initial_state_digest"],
        )

    def test_all_oracle_state_projections_and_adapter_use_v01_digest(self) -> None:
        schema = json.loads(
            (ROOT / "schema/conformance-state-projection.v0.1.schema.json").read_text()
        )
        for entry in self.manifest["cases"]:
            case = json.loads((ROOT / SUITE_ROOT / entry["path"]).read_text())
            actual = execute_case(ROOT, ROOT / SUITE_ROOT, case)
            with self.subTest(case=case["case_id"]):
                self.assertFalse(
                    list(
                        Draft202012Validator(schema).iter_errors(
                            actual.final_state_projection
                        )
                    )
                )
                self.assertEqual(
                    case["expected"]["initial_state_digest"],
                    actual.initial_state_digest,
                )
                self.assertEqual(
                    case["expected"]["state_digest"], actual.final_state_digest
                )
        adapter = json.loads(
            (
                ROOT
                / SUITE_ROOT
                / "fixtures/adapter-results/valid-end-to-end.v0.1.json"
            ).read_text()
        )
        case = self._case("CV-VALID-END-TO-END")
        self.assertEqual(
            case["expected"]["initial_state_digest"], adapter["initial_state_digest"]
        )
        self.assertEqual(
            case["expected"]["state_digest"], adapter["final_state_digest"]
        )

    def test_every_fixed_case_has_reviewed_expected_comparison(self) -> None:
        for entry in self.manifest["cases"]:
            case = json.loads((ROOT / SUITE_ROOT / entry["path"]).read_text())
            actual = execute_case(ROOT, ROOT / SUITE_ROOT, case)
            status, _, matched = compare_actual_to_expected(actual, case["expected"])
            intentional = case["vector_class"] == "CV-RUNNER-EXPECTED-MISMATCH"
            with self.subTest(case=case["case_id"]):
                self.assertEqual(not intentional, matched)
                self.assertEqual(case["result_status_expectation"], status)

    def test_three_result_variants_execute_distinct_party_local_state(self) -> None:
        values = {}
        digests = {}
        paths = {}
        for vector in (
            "CV-VALID-END-TO-END",
            "CV-VALID-NO-MATCH",
            "CV-VALID-INDETERMINATE",
        ):
            case = self._case(vector)
            actual = execute_case(ROOT, ROOT / SUITE_ROOT, case)
            values[vector] = tuple(actual.local_result_state.values())
            digests[vector] = actual.final_state_digest
            paths[vector] = next(
                item["path"]
                for item in case["ordered_inputs"]
                if item["kind"] == "profile-local-result-fixture"
            )
        self.assertEqual(
            {
                ("MATCH", "MATCH"),
                ("NO_MATCH", "NO_MATCH"),
                ("INDETERMINATE", "INDETERMINATE"),
            },
            set(values.values()),
        )
        self.assertEqual(3, len(set(digests.values())))
        self.assertEqual(3, len(set(paths.values())))

    def test_asymmetric_result_fixture_is_rejected(self) -> None:
        actual = execute_case(
            ROOT, ROOT / SUITE_ROOT, self._case("CV-ASYMMETRIC-RESULT")
        )
        self.assertEqual("rejected", actual.protocol_outcome)
        self.assertIn("RESULT_CONFLICT", actual.error_codes)

    def test_result_values_never_enter_coordinator_visible_wire(self) -> None:
        for vector in (
            "CV-VALID-END-TO-END",
            "CV-VALID-NO-MATCH",
            "CV-VALID-INDETERMINATE",
        ):
            case = self._case(vector)
            for item in case["ordered_inputs"]:
                if item["kind"] == "profile-local-result-fixture":
                    continue
                raw = (ROOT / SUITE_ROOT / item["path"]).read_text(encoding="utf-8")
                for outcome in ('"MATCH"', '"NO_MATCH"', '"INDETERMINATE"'):
                    self.assertNotIn(outcome, raw)

    def test_no_match_indeterminate_and_match_without_consent_cannot_disclose(
        self,
    ) -> None:
        base = self._case("CV-DISCLOSURE-WITHOUT-PROFILE")
        for name in ("match", "no_match", "indeterminate"):
            case = copy.deepcopy(base)
            local = next(
                item
                for item in case["ordered_inputs"]
                if item["kind"] == "profile-local-result-fixture"
            )
            local["path"] = f"fixtures/local-results/{name}.json"
            local["fixture_digest"] = sha256_bytes(
                (ROOT / SUITE_ROOT / local["path"]).read_bytes()
            )
            actual = execute_case(ROOT, ROOT / SUITE_ROOT, case)
            with self.subTest(result=name):
                self.assertEqual("rejected", actual.protocol_outcome)
                self.assertIn("DISCLOSURE_PROFILE_REQUIRED", actual.error_codes)
        result_case = self._case("CV-VALID-END-TO-END")
        result_case["ordered_inputs"] = result_case["ordered_inputs"][:2] + [
            {
                "kind": "trace-fixture",
                "path": "fixtures/traces/result-acceptance-tail.json",
                "fixture_digest": sha256_bytes(
                    (
                        ROOT
                        / SUITE_ROOT
                        / "fixtures/traces/result-acceptance-tail.json"
                    ).read_bytes()
                ),
            }
        ]
        actual = execute_case(ROOT, ROOT / SUITE_ROOT, result_case)
        self.assertEqual("accepted", actual.protocol_outcome)
        self.assertIsNone(actual.terminal_phase)

    def test_delayed_duplicate_and_conflict_paths_are_nonmutating(self) -> None:
        baseline = execute_case(
            ROOT, ROOT / SUITE_ROOT, self._case("CV-VALID-END-TO-END")
        )
        for vector, expected, authorized in (
            ("CV-VALID-EXACT-DUPLICATE", "no-op", True),
            ("CV-DUPLICATE-TRANSCRIPT-APPEND", "no-op", False),
            ("CV-CACHED-RESPONSE-WRONG-REQUESTER", "no-op", False),
            ("CV-DUPLICATE-CONFLICT", "rejected", None),
            ("CV-WIRE-DIGEST-TAMPER", "rejected", None),
        ):
            actual = execute_case(ROOT, ROOT / SUITE_ROOT, self._case(vector))
            with self.subTest(vector=vector):
                self.assertEqual(expected, actual.protocol_outcome)
                self.assertEqual(baseline.final_state_digest, actual.final_state_digest)
                self.assertEqual(
                    baseline.final_transcript_head, actual.final_transcript_head
                )
                self.assertEqual(authorized, actual.cached_response_authorized)

    def test_real_replay_timer_consent_and_leakage_vectors_execute(self) -> None:
        vectors = [
            "CV-NONCE-REUSE",
            "CV-STALE-SEQUENCE",
            "CV-OUT-OF-ORDER",
            "CV-CROSS-SESSION-REPLAY",
            "CV-TRANSCRIPT-REORDER",
            "CV-TRANSCRIPT-OMISSION",
            "CV-CLOCK-ROLLBACK",
            "CV-CLOCK-JUMP",
            "CV-CONSENT-BEFORE-RESULT",
            "CV-CONSENT-WRONG-RECEIPT",
            "CV-CONSENT-WRONG-SCOPE",
            "CV-CONSENT-WRONG-AUDIENCE",
            "CV-DISCLOSURE-WITHOUT-PROFILE",
            "CV-EXACT-COUNT-PROHIBITED",
            "CV-MATCHING-ELEMENT-PROHIBITED",
            "CV-IDENTITY-DISCLOSURE-PROHIBITED",
        ]
        for vector in vectors:
            with self.subTest(vector=vector):
                self.assertEqual(
                    "rejected",
                    execute_case(
                        ROOT, ROOT / SUITE_ROOT, self._case(vector)
                    ).protocol_outcome,
                )
        self.assertEqual(
            "terminal",
            execute_case(
                ROOT, ROOT / SUITE_ROOT, self._case("CV-CONSENT-EXPIRY")
            ).protocol_outcome,
        )
        self.assertEqual(
            "terminal",
            execute_case(
                ROOT, ROOT / SUITE_ROOT, self._case("CV-CONSENT-WITHDRAWAL")
            ).protocol_outcome,
        )

    def test_runner_statuses_arise_from_behavior(self) -> None:
        expected = {
            "CV-VALID-END-TO-END": "pass",
            "CV-RUNNER-EXPECTED-MISMATCH": "fail",
            "CV-RUNNER-REVIEWED-SKIP": "skip",
            "CV-UNKNOWN-ALGORITHM": "unsupported",
            "CV-RUNNER-TIMEOUT": "timeout",
            "CV-RUNNER-TOOL-ERROR": "tool-error",
        }
        for vector, status in expected.items():
            with self.subTest(vector=vector):
                self.assertEqual(
                    status,
                    build_result(ROOT, self.manifest, self._case(vector))["status"],
                )

    def test_timeout_requires_deterministic_budget_exhaustion(self) -> None:
        case = self._case("CV-RUNNER-TIMEOUT")
        self.assertEqual("timeout", execute_case(ROOT, ROOT / SUITE_ROOT, case).status)
        changed = copy.deepcopy(case)
        changed["timeout_policy"]["max_operation_steps"] = 10
        self.assertEqual("pass", execute_case(ROOT, ROOT / SUITE_ROOT, changed).status)

    def test_arbitrary_directive_or_skip_reason_fails_closed(self) -> None:
        case = self._case("CV-RUNNER-TIMEOUT")
        case["ordered_inputs"] = [
            {"kind": "runner-directive", "directive": "force-timeout"}
        ]
        self.assertTrue(list(Draft202012Validator(self.case_schema).iter_errors(case)))
        skip = self._case("CV-RUNNER-REVIEWED-SKIP")
        skip["execution_precondition"]["reason_code"] = "ARBITRARY"
        with self.assertRaises(ConformanceError):
            execute_case(ROOT, ROOT / SUITE_ROOT, skip)

    def test_normative_oracle_remains_fixed_when_actual_changes(self) -> None:
        case = self._case("CV-VALID-END-TO-END")
        before = json.dumps(case["expected"], sort_keys=True)
        actual = execute_case(ROOT, ROOT / SUITE_ROOT, case)
        actual.protocol_outcome = "rejected"
        status, codes, matched = compare_actual_to_expected(actual, case["expected"])
        self.assertFalse(matched)
        self.assertEqual("fail", status)
        self.assertIn("CONFORMANCE-EXPECTED-MISMATCH", codes)
        self.assertEqual(before, json.dumps(case["expected"], sort_keys=True))
        actual = execute_case(ROOT, ROOT / SUITE_ROOT, case)
        actual.error_codes = ["REPLAY_CONFLICT"]
        self.assertFalse(compare_actual_to_expected(actual, case["expected"])[2])
        actual = execute_case(ROOT, ROOT / SUITE_ROOT, case)
        actual.final_state_digest = "sha256:" + "f" * 64
        self.assertFalse(compare_actual_to_expected(actual, case["expected"])[2])

    def test_result_bytes_and_digest_are_deterministic(self) -> None:
        case = self._case("CV-VALID-END-TO-END")
        first = build_result(ROOT, self.manifest, case)
        second = build_result(ROOT, self.manifest, case)
        self.assertEqual(first, second)
        self.assertEqual(first["result_digest"], result_digest(first))
        self.assertNotIn("timestamp", first)
        self.assertNotIn("hostname", first)
        implementation = json.loads(
            (
                ROOT / "conformance/source/reference-verifier-implementation.v0.1.json"
            ).read_text()
        )
        self.assertEqual(
            implementation["implementation_digest"],
            first["verifier"]["implementation_digest"],
        )
        self.assertEqual(
            sha256_bytes(
                (
                    ROOT
                    / "conformance/source/reference-verifier-implementation.v0.1.json"
                ).read_bytes()
            ),
            first["verifier"]["implementation_manifest_digest"],
        )

    def test_all_output_is_exact_and_transactional(self) -> None:
        scratch = ROOT / "artifacts"
        scratch.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as temporary:
            final = Path(temporary) / "all-results"
            relative = final.relative_to(ROOT).as_posix()
            self.assertEqual(
                0, run_main(["--root", str(ROOT), "--all", "--output-dir", relative])
            )
            self.assertEqual(69, len(list(final.iterdir())))
            self.assertTrue((final / "run-set-manifest.v0.1.json").is_file())
            self.assertEqual(
                1, run_main(["--root", str(ROOT), "--all", "--output-dir", relative])
            )

    def test_late_failure_leaves_no_final_or_partial_directory(self) -> None:
        scratch = ROOT / "artifacts"
        scratch.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as temporary:
            final = Path(temporary) / "late"
            counter = {"n": 0}
            real = build_result

            def fail_late(*args, **kwargs):
                counter["n"] += 1
                if counter["n"] == 5:
                    raise ConformanceError("CONFORMANCE-TOOL-ERROR", "late")
                return real(*args, **kwargs)

            with mock.patch("run_conformance.build_result", side_effect=fail_late):
                self.assertEqual(
                    1,
                    run_main(
                        [
                            "--root",
                            str(ROOT),
                            "--all",
                            "--output-dir",
                            final.relative_to(ROOT).as_posix(),
                        ]
                    ),
                )
            self.assertFalse(final.exists())
            self.assertFalse(final.with_name(".late.partial").exists())

    def _staged(self, base: Path):
        base.mkdir()
        cases = [self._case("CV-VALID-END-TO-END"), self._case("CV-UNKNOWN-ALGORITHM")]
        results = []
        for case in cases:
            result = build_result(ROOT, self.manifest, case)
            raw = json.dumps(result, separators=(",", ":"), sort_keys=True).encode()
            name = _result_name(case["case_id"])
            (base / name).write_bytes(raw)
            results.append((name, raw, result))
        run_set = _run_set_manifest(
            self.manifest, results, results[0][2]["verifier"]["implementation_digest"]
        )
        (base / "run-set-manifest.v0.1.json").write_text(
            json.dumps(run_set, separators=(",", ":"), sort_keys=True)
        )
        return run_set, [c["case_id"] for c in cases]

    def test_staged_missing_extra_wrong_digest_and_symlink_are_rejected(self) -> None:
        scratch = ROOT / "artifacts"
        scratch.mkdir(exist_ok=True)
        for mutation in (
            "missing",
            "extra",
            "digest",
            "status",
            "symlink",
            "directory",
        ):
            with tempfile.TemporaryDirectory(dir=scratch) as temporary:
                base = Path(temporary) / "stage"
                run_set, ids = self._staged(base)
                if mutation == "missing":
                    (base / run_set["results"][0]["path"]).unlink()
                elif mutation == "extra":
                    (base / "stale.json").write_text("{}")
                elif mutation == "digest":
                    (base / run_set["results"][0]["path"]).write_bytes(b"{}")
                elif mutation == "status":
                    run_set["results"][0]["status"] = "unsupported"
                    run_set["status_counts"]["pass"] -= 1
                    run_set["status_counts"]["unsupported"] += 1
                    run_set["run_set_digest"] = run_set_digest(run_set)
                elif mutation == "symlink":
                    (base / "link.json").symlink_to(
                        base / run_set["results"][0]["path"]
                    )
                else:
                    (base / "stale-directory").mkdir()
                with (
                    self.subTest(mutation=mutation),
                    self.assertRaises(ConformanceError),
                ):
                    validate_staged_run_set(base, run_set, ids)


if __name__ == "__main__":
    unittest.main()
