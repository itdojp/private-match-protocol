# SPDX-License-Identifier: Apache-2.0
"""Source, oracle, generated-suite, and closed-pin contract tests."""

from __future__ import annotations

import ast
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
from conformance_common import (  # noqa: E402
    ConformanceError,
    MESSAGE_INPUT_MANIFEST,
    SUITE_ROOT,
    case_digest,
    legacy_length_prefixed_tree_digest,
    message_conformance_paths,
    resolve_directory,
    resolve_regular_file,
    suite_digest,
    validate_message_input_manifest,
)
from generate_conformance_suite import (  # noqa: E402
    NORMATIVE_ORACLE,
    REQUIRED_VECTOR_CLASSES,
    generated_files,
    main as generate_main,
)
from validate_conformance_suite import SCHEMAS, validate_repository  # noqa: E402


class ConformanceSuiteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.manifest = json.loads(
            (ROOT / SUITE_ROOT / "suite-manifest.v0.1.json").read_text()
        )
        cls.source_manifest = json.loads((ROOT / MESSAGE_INPUT_MANIFEST).read_text())

    def test_repository_suite_is_valid(self) -> None:
        self.assertEqual([], validate_repository(ROOT, execute=False))

    def test_required_coverage_and_scopes_are_closed(self) -> None:
        self.assertEqual(
            REQUIRED_VECTOR_CLASSES,
            [item["vector_class"] for item in self.manifest["cases"]],
        )
        self.assertEqual(68, len(self.manifest["cases"]))
        self.assertEqual(
            {"protocol-executable": 58, "policy-projection": 6, "runner-self-test": 4},
            self.manifest["generation"]["case_scope_counts"],
        )

    def test_all_schemas_self_validate(self) -> None:
        for path in SCHEMAS.values():
            Draft202012Validator.check_schema(json.loads((ROOT / path).read_text()))

    def test_generator_is_byte_deterministic_and_check_only(self) -> None:
        first = generated_files(ROOT)
        second = generated_files(ROOT)
        self.assertEqual(first, second)
        for relative, content in first.items():
            self.assertEqual(content, (ROOT / relative).read_bytes(), relative)
        oracle = ROOT / NORMATIVE_ORACLE
        before = (oracle.read_bytes(), oracle.stat().st_mtime_ns)
        self.assertEqual(0, generate_main(["--root", str(ROOT), "--check"]))
        self.assertEqual(before, (oracle.read_bytes(), oracle.stat().st_mtime_ns))

    def test_generator_does_not_import_or_execute_reference_engine(self) -> None:
        tree = ast.parse((ROOT / "scripts/generate_conformance_suite.py").read_text())
        imports = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.module == "conformance_engine"
        ]
        names = {
            node.func.id
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        }
        self.assertEqual([], imports)
        self.assertNotIn("execute_case", names)

    def test_suite_case_and_expected_digests_are_recomputable(self) -> None:
        self.assertEqual(self.manifest["suite_digest"], suite_digest(self.manifest))
        expected = json.loads(
            (ROOT / SUITE_ROOT / "expected-results.v0.1.json").read_text()
        )
        self.assertEqual(
            {e["case_id"] for e in self.manifest["cases"]},
            {e["case_id"] for e in expected["results"]},
        )
        for entry in self.manifest["cases"]:
            case = json.loads((ROOT / SUITE_ROOT / entry["path"]).read_text())
            self.assertEqual(case["case_digest"], case_digest(case))

    def test_reviewed_tree_digest_recomputes_all_74_files(self) -> None:
        paths = message_conformance_paths(ROOT)
        self.assertEqual(74, len(paths))
        self.assertEqual(
            self.source_manifest["tree_digest"],
            legacy_length_prefixed_tree_digest(ROOT, paths),
        )
        self.assertEqual(
            self.manifest["protocol_pins"]["message_conformance_tree_digest"],
            self.source_manifest["tree_digest"],
        )
        validate_message_input_manifest(ROOT, self.source_manifest)

    def _source_tree(self):
        scratch = ROOT / "artifacts"
        scratch.mkdir(exist_ok=True)
        temporary = tempfile.TemporaryDirectory(dir=scratch)
        base = Path(temporary.name)
        shutil.copytree(ROOT / "conformance/messages", base / "conformance/messages")
        return temporary, base

    def test_every_message_input_role_mutation_fails_closed(self) -> None:
        representatives = [
            "conformance/messages/context.v0.1.yaml",
            "conformance/messages/verification-materials.v0.1.yaml",
            "conformance/messages/authenticated-requesters.v0.1.yaml",
            "conformance/messages/valid/session-proposal.json",
            "conformance/messages/invalid/unknown-field.json",
            "conformance/messages/invalid/manifest.v0.1.yaml",
            "conformance/messages/expected-digests/vectors.v0.1.json",
        ]
        for relative in representatives:
            with self.subTest(relative=relative):
                temporary, base = self._source_tree()
                try:
                    path = base / relative
                    path.write_bytes(path.read_bytes() + b"\n")
                    with self.assertRaises(ConformanceError):
                        validate_message_input_manifest(
                            base, copy.deepcopy(self.source_manifest)
                        )
                finally:
                    temporary.cleanup()

    def test_source_path_add_remove_duplicate_and_stale_tree_fail(self) -> None:
        temporary, base = self._source_tree()
        try:
            for mutation in ("remove", "duplicate", "stale"):
                manifest = copy.deepcopy(self.source_manifest)
                if mutation == "remove":
                    manifest["entries"].pop()
                elif mutation == "duplicate":
                    manifest["entries"].append(copy.deepcopy(manifest["entries"][0]))
                else:
                    manifest["tree_digest"] = "sha256:" + "f" * 64
                with (
                    self.subTest(mutation=mutation),
                    self.assertRaises(ConformanceError),
                ):
                    validate_message_input_manifest(base, manifest)
            extra = base / "conformance/messages/extra.json"
            extra.write_text("{}")
            with self.assertRaises(ConformanceError):
                validate_message_input_manifest(
                    base, copy.deepcopy(self.source_manifest)
                )
            extra.unlink()
            (base / "conformance/messages/extra-link.json").symlink_to(
                base / "conformance/messages/context.v0.1.yaml"
            )
            with self.assertRaises(ConformanceError):
                validate_message_input_manifest(
                    base, copy.deepcopy(self.source_manifest)
                )
        finally:
            temporary.cleanup()

    def test_cases_contain_no_tautological_probe_or_status_directive(self) -> None:
        for entry in self.manifest["cases"]:
            case = json.loads((ROOT / SUITE_ROOT / entry["path"]).read_text())
            self.assertFalse(
                {item["kind"] for item in case["ordered_inputs"]}
                & {"semantic-probe", "runner-directive"}
            )

    def test_unknown_case_fields_and_old_result_variant_fail_schema(self) -> None:
        entry = self.manifest["cases"][0]
        case = json.loads((ROOT / SUITE_ROOT / entry["path"]).read_text())
        schema = json.loads((ROOT / SCHEMAS["case"]).read_text())
        case["ordered_inputs"][0]["result_variant"] = "MATCH"
        self.assertTrue(list(Draft202012Validator(schema).iter_errors(case)))

    def test_paths_and_symlinks_fail_closed(self) -> None:
        for value in ("/absolute", "C:\\windows", "../escape", "a/../b", "a\\b", ""):
            with self.subTest(value=value), self.assertRaises(ConformanceError):
                resolve_regular_file(ROOT, value)
        scratch = ROOT / "artifacts"
        scratch.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as temporary:
            base = Path(temporary)
            (base / "real").mkdir()
            (base / "real/case.json").write_text("{}")
            (base / "link").symlink_to(base / "real", target_is_directory=True)
            with self.assertRaises(ConformanceError):
                resolve_regular_file(
                    ROOT, (base / "link/case.json").relative_to(ROOT).as_posix()
                )
            (base / "out").symlink_to(base / "real", target_is_directory=True)
            with self.assertRaises(ConformanceError):
                resolve_directory(ROOT, (base / "out").relative_to(ROOT).as_posix())


if __name__ == "__main__":
    unittest.main()
