# SPDX-License-Identifier: Apache-2.0
"""Contract tests for the generated conformance suite."""

from __future__ import annotations

import copy
import json
import tempfile
import sys
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from conformance_common import (  # noqa: E402
    ConformanceError,
    SUITE_ROOT,
    case_digest,
    resolve_regular_file,
    resolve_directory,
    suite_digest,
    validate_relative_path,
)
from generate_conformance_suite import (  # noqa: E402
    REQUIRED_VECTOR_CLASSES,
    generated_files,
    main as generate_main,
)
from validate_conformance_suite import (  # noqa: E402
    SCHEMAS,
    validate_repository,
)


class ConformanceSuiteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.manifest = json.loads(
            (ROOT / SUITE_ROOT / "suite-manifest.v0.1.json").read_text()
        )

    def test_repository_suite_is_valid(self) -> None:
        self.assertEqual([], validate_repository(ROOT, execute=False))

    def test_every_required_vector_class_has_one_stable_case(self) -> None:
        classes = {
            item["id"]: item["case_ids"] for item in self.manifest["vector_classes"]
        }
        self.assertEqual(set(REQUIRED_VECTOR_CLASSES), set(classes))
        self.assertTrue(all(len(case_ids) == 1 for case_ids in classes.values()))
        self.assertEqual(68, len(self.manifest["cases"]))

    def test_all_schemas_self_validate(self) -> None:
        for path in SCHEMAS.values():
            Draft202012Validator.check_schema(json.loads((ROOT / path).read_text()))

    def test_generator_is_byte_deterministic(self) -> None:
        first = generated_files(ROOT)
        second = generated_files(ROOT)
        self.assertEqual(first, second)
        for relative, content in first.items():
            self.assertEqual(content, (ROOT / relative).read_bytes(), relative)

    def test_check_mode_does_not_rewrite_generated_artifacts(self) -> None:
        path = ROOT / SUITE_ROOT / "suite-manifest.v0.1.json"
        before = (path.read_bytes(), path.stat().st_mtime_ns)
        self.assertEqual(0, generate_main(["--root", str(ROOT), "--check"]))
        self.assertEqual(before, (path.read_bytes(), path.stat().st_mtime_ns))

    def test_suite_and_case_digests_are_recomputable(self) -> None:
        self.assertEqual(self.manifest["suite_digest"], suite_digest(self.manifest))
        for entry in self.manifest["cases"]:
            case = json.loads((ROOT / SUITE_ROOT / entry["path"]).read_text())
            self.assertEqual(entry["case_digest"], case_digest(case))

    def test_expected_results_bind_every_case_once(self) -> None:
        expected = json.loads(
            (ROOT / SUITE_ROOT / "expected-results.v0.1.json").read_text()
        )
        case_ids = [item["case_id"] for item in self.manifest["cases"]]
        result_ids = [item["case_id"] for item in expected["results"]]
        self.assertEqual(sorted(case_ids), sorted(result_ids))
        self.assertEqual(len(result_ids), len(set(result_ids)))

    def test_digest_mutations_are_detectable(self) -> None:
        changed = copy.deepcopy(self.manifest)
        changed["protocol_pins"]["message_registry_digest"] = "sha256:" + "f" * 64
        self.assertNotEqual(changed["suite_digest"], suite_digest(changed))
        entry = self.manifest["cases"][0]
        case = json.loads((ROOT / SUITE_ROOT / entry["path"]).read_text())
        case["expected"]["protocol_outcome"] = "rejected"
        self.assertNotEqual(case["case_digest"], case_digest(case))

    def test_paths_fail_closed(self) -> None:
        for value in ("/absolute", "C:\\windows", "../escape", "a/../b", "a\\b", ""):
            with self.subTest(value=value), self.assertRaises(ConformanceError):
                validate_relative_path(value)
        with self.assertRaises(ConformanceError):
            resolve_regular_file(ROOT, "conformance/suites/missing.json")

    def test_intermediate_and_final_symlinks_are_rejected(self) -> None:
        scratch = ROOT / "artifacts"
        scratch.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as temporary:
            base = Path(temporary)
            (base / "real").mkdir()
            (base / "real" / "case.json").write_text("{}")
            (base / "link").symlink_to(base / "real", target_is_directory=True)
            relative = (base / "link" / "case.json").relative_to(ROOT).as_posix()
            with self.assertRaises(ConformanceError):
                resolve_regular_file(ROOT, relative)
            file_link = base / "file-link.json"
            file_link.symlink_to(base / "real" / "case.json")
            with self.assertRaises(ConformanceError):
                resolve_regular_file(ROOT, file_link.relative_to(ROOT).as_posix())

    def test_output_directory_is_repository_local_and_non_symlink(self) -> None:
        with self.assertRaises(ConformanceError):
            resolve_directory(ROOT, "../outside", create=True)
        scratch = ROOT / "artifacts"
        scratch.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as temporary:
            base = Path(temporary)
            (base / "real").mkdir()
            (base / "output").symlink_to(base / "real", target_is_directory=True)
            with self.assertRaises(ConformanceError):
                resolve_directory(ROOT, (base / "output").relative_to(ROOT).as_posix())

    def test_unknown_fields_fail_case_schema(self) -> None:
        entry = self.manifest["cases"][0]
        case = json.loads((ROOT / SUITE_ROOT / entry["path"]).read_text())
        case["unknown"] = True
        schema = json.loads((ROOT / SCHEMAS["case"]).read_text())
        self.assertTrue(list(Draft202012Validator(schema).iter_errors(case)))

    def test_duplicate_case_and_class_are_not_silent(self) -> None:
        case_ids = [entry["case_id"] for entry in self.manifest["cases"]]
        class_ids = [entry["id"] for entry in self.manifest["vector_classes"]]
        self.assertEqual(len(case_ids), len(set(case_ids)))
        self.assertEqual(len(class_ids), len(set(class_ids)))


if __name__ == "__main__":
    unittest.main()
