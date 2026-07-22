#!/usr/bin/env python3
"""Validate generated suite, reviewed oracle, source pins, and execution parity."""

from __future__ import annotations

import argparse
import ast
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft202012Validator, FormatChecker

from canonicalize_message import canonicalize
from conformance_common import (
    ConformanceError,
    MESSAGE_INPUT_MANIFEST,
    REFERENCE_IMPLEMENTATION_MANIFEST,
    STATE_PROJECTION_PROFILE,
    SUITE_ROOT,
    SUITE_TREE_MANIFEST,
    case_digest,
    expected_result_digest,
    input_digest,
    resolve_regular_file,
    sha256_bytes,
    state_projection_profile_digest,
    strict_json_bytes,
    suite_digest,
    suite_tree_digest,
    validate_generated_suite_tree,
    validate_message_input_manifest,
    validate_reference_implementation_manifest,
)
from conformance_engine import compare_actual_to_expected, execute_case
from generate_conformance_suite import (
    CASE_DEFINITIONS,
    NORMATIVE_ORACLE,
    PROTOCOL_PINS,
    REQUIRED_VECTOR_CLASSES,
    generated_files,
)
from strict_yaml import strict_yaml_load

SCHEMAS = {
    "manifest": Path("schema/conformance-suite-manifest.v0.1.schema.json"),
    "case": Path("schema/conformance-case.v0.1.schema.json"),
    "expected": Path("schema/conformance-expected-result.v0.1.schema.json"),
    "run": Path("schema/conformance-run-result.v0.1.schema.json"),
    "run_set": Path("schema/conformance-run-set-manifest.v0.1.schema.json"),
    "adapter": Path("schema/conformance-adapter-result.v0.1.schema.json"),
    "case_definitions": Path("schema/conformance-case-definitions.v0.1.schema.json"),
    "oracle": Path("schema/conformance-normative-expected-results.v0.1.schema.json"),
    "message_inputs": Path(
        "schema/conformance-message-input-manifest.v0.1.schema.json"
    ),
    "state_projection": Path("schema/conformance-state-projection.v0.1.schema.json"),
    "state_projection_profile": Path(
        "schema/conformance-state-projection-profile.v0.1.schema.json"
    ),
    "implementation": Path(
        "schema/conformance-verifier-implementation.v0.1.schema.json"
    ),
    "suite_tree": Path("schema/conformance-suite-tree-manifest.v0.1.schema.json"),
}
CONFORMANCE_ERROR_CODES = {
    "CONFORMANCE-ADAPTER-UNSUPPORTED",
    "CONFORMANCE-CANONICALIZATION",
    "CONFORMANCE-CASE-SCHEMA",
    "CONFORMANCE-EXPECTED-MISMATCH",
    "CONFORMANCE-INPUT-JSON",
    "CONFORMANCE-MESSAGE-SCHEMA",
    "CONFORMANCE-NONCANONICAL-JSON",
    "CONFORMANCE-PROTOCOL-REJECTION",
    "CONFORMANCE-REVIEWED-SKIP",
    "CONFORMANCE-TIMEOUT",
    "CONFORMANCE-TOOL-ERROR",
}


@dataclass(frozen=True, order=True)
class Finding:
    code: str
    path: str
    detail: str

    def __str__(self) -> str:
        return f"{self.code}: {self.path}: {self.detail[:240]}"


def _load(root: Path, relative: Path, findings: list[Finding]) -> Any | None:
    try:
        path = resolve_regular_file(root, relative.as_posix())
        return strict_json_bytes(
            path.read_bytes(), path=relative.as_posix(), require_canonical=True
        )
    except (OSError, ConformanceError, ValueError) as error:
        findings.append(
            Finding(
                error.code
                if isinstance(error, ConformanceError)
                else "CONFORMANCE-JSON-PARSE",
                relative.as_posix(),
                "artifact could not be loaded",
            )
        )
        return None


def _schema_findings(value: Any, schema: dict[str, Any], path: str) -> list[Finding]:
    result = []
    for error in Draft202012Validator(
        schema, format_checker=FormatChecker()
    ).iter_errors(value):
        suffix = ".".join(map(str, error.absolute_path))
        result.append(
            Finding(
                "CONFORMANCE-SCHEMA",
                f"{path}{'.' + suffix if suffix else ''}",
                "closed Schema constraint failed",
            )
        )
    return result


def _closed_adapter_registry(root: Path, findings: list[Finding]) -> None:
    try:
        registry = strict_yaml_load(
            resolve_regular_file(
                root, "conformance/interop/adapters.v0.1.yaml"
            ).read_text(encoding="utf-8")
        )
        if set(registry) != {
            "schema_version",
            "artifact_status",
            "registry_id",
            "adapters",
        }:
            raise ValueError
        identifiers = []
        required = {
            "id",
            "version",
            "language",
            "runtime",
            "source_repository_policy",
            "target_suite",
            "implementation_status",
            "owner_role",
            "license_expectation",
            "canonicalization_dependency_review",
            "expected_independence_boundary",
            "required_vectors",
            "evidence_requirement",
            "limitations",
        }
        for item in registry["adapters"]:
            if (
                set(item) != required
                or item["implementation_status"] != "planned"
                or item["source_repository_policy"] != "public-only"
            ):
                raise ValueError
            identifiers.append(item["id"])
        if not identifiers or len(identifiers) != len(set(identifiers)):
            raise ValueError
    except (OSError, ValueError, TypeError, KeyError, yaml.YAMLError, ConformanceError):
        findings.append(
            Finding(
                "CONFORMANCE-ADAPTER-REGISTRY",
                "conformance/interop/adapters.v0.1.yaml",
                "closed planned adapter contract failed",
            )
        )


def validate_repository(root: Path, *, execute: bool = True) -> list[Finding]:
    findings: list[Finding] = []
    schemas = {}
    for key, relative in SCHEMAS.items():
        value = _load(root, relative, findings)
        if isinstance(value, dict):
            schemas[key] = value
            try:
                Draft202012Validator.check_schema(value)
            except Exception:
                findings.append(
                    Finding(
                        "CONFORMANCE-SCHEMA-SELF",
                        relative.as_posix(),
                        "invalid JSON Schema",
                    )
                )
    if findings:
        return sorted(set(findings))
    _closed_adapter_registry(root, findings)

    source_values = {
        "case_definitions": _load(root, CASE_DEFINITIONS, findings),
        "oracle": _load(root, NORMATIVE_ORACLE, findings),
        "message_inputs": _load(root, MESSAGE_INPUT_MANIFEST, findings),
        "state_projection_profile": _load(root, STATE_PROJECTION_PROFILE, findings),
        "implementation": _load(root, REFERENCE_IMPLEMENTATION_MANIFEST, findings),
    }
    for key, value in source_values.items():
        if isinstance(value, dict):
            findings.extend(
                _schema_findings(
                    value,
                    schemas[key],
                    {
                        "case_definitions": str(CASE_DEFINITIONS),
                        "oracle": str(NORMATIVE_ORACLE),
                        "message_inputs": str(MESSAGE_INPUT_MANIFEST),
                        "state_projection_profile": str(STATE_PROJECTION_PROFILE),
                        "implementation": str(REFERENCE_IMPLEMENTATION_MANIFEST),
                    }[key],
                )
            )
    profile = source_values.get("state_projection_profile")
    if isinstance(profile, dict) and profile.get(
        "profile_digest"
    ) != state_projection_profile_digest(profile):
        findings.append(
            Finding(
                "CONFORMANCE-STATE-PROJECTION-PROFILE-DIGEST",
                STATE_PROJECTION_PROFILE.as_posix(),
                "profile digest mismatch",
            )
        )
    implementation = source_values.get("implementation")
    if isinstance(implementation, dict):
        try:
            validate_reference_implementation_manifest(
                root, implementation, protocol_pins=PROTOCOL_PINS
            )
        except ConformanceError as error:
            findings.append(
                Finding(error.code, error.path, "implementation closure failed")
            )
    try:
        if not isinstance(source_values["message_inputs"], dict):
            raise ConformanceError("CONFORMANCE-SOURCE-MANIFEST-SHAPE", "source")
        validate_message_input_manifest(root, source_values["message_inputs"])
        if (
            source_values["message_inputs"]["tree_digest"]
            != PROTOCOL_PINS["message_conformance_tree_digest"]
        ):
            raise ConformanceError(
                "CONFORMANCE-PROTOCOL-PIN", "message-conformance-tree"
            )
    except ConformanceError as error:
        findings.append(
            Finding(error.code, error.path, "reviewed source-tree verification failed")
        )

    manifest_relative = SUITE_ROOT / "suite-manifest.v0.1.json"
    manifest = _load(root, manifest_relative, findings)
    if not isinstance(manifest, dict):
        return sorted(set(findings))
    findings.extend(
        _schema_findings(manifest, schemas["manifest"], manifest_relative.as_posix())
    )
    if manifest.get("suite_digest") != suite_digest(manifest):
        findings.append(
            Finding(
                "CONFORMANCE-SUITE-DIGEST",
                manifest_relative.as_posix(),
                "digest mismatch",
            )
        )
    if manifest.get("protocol_pins") != PROTOCOL_PINS:
        findings.append(
            Finding(
                "CONFORMANCE-PROTOCOL-PIN",
                manifest_relative.as_posix(),
                "reviewed pin mismatch",
            )
        )
    source_artifacts = manifest.get("source_artifacts", {})
    for field, relative in (
        ("message_input_manifest_digest", MESSAGE_INPUT_MANIFEST),
        ("case_definitions_digest", CASE_DEFINITIONS),
        ("normative_oracle_digest", NORMATIVE_ORACLE),
        ("state_projection_profile_digest", STATE_PROJECTION_PROFILE),
    ):
        try:
            if source_artifacts.get(field) != sha256_bytes(
                resolve_regular_file(root, relative.as_posix()).read_bytes()
            ):
                findings.append(
                    Finding(
                        "CONFORMANCE-SOURCE-DIGEST", field, "source digest mismatch"
                    )
                )
        except ConformanceError:
            findings.append(
                Finding("CONFORMANCE-SOURCE-DIGEST", field, "source unavailable")
            )

    try:
        machine = strict_yaml_load(
            resolve_regular_file(
                root, "specs/state-machines/private-match-core-session-v0.1.yaml"
            ).read_text(encoding="utf-8")
        )
        protocol_codes = {
            item.get("code")
            for item in machine.get("failure_taxonomy", [])
            if isinstance(item, dict)
        }
        if sha256_bytes(canonicalize(machine)) != PROTOCOL_PINS["state_machine_digest"]:
            raise ValueError
        if (
            sha256_bytes(
                resolve_regular_file(
                    root, "registry/message-types.v0.1.yaml"
                ).read_bytes()
            )
            != PROTOCOL_PINS["message_registry_digest"]
        ):
            raise ValueError
    except (OSError, ValueError, TypeError, KeyError, yaml.YAMLError, ConformanceError):
        protocol_codes = set()
        findings.append(
            Finding(
                "CONFORMANCE-PROTOCOL-PIN",
                "protocol-artifacts",
                "artifact digest mismatch",
            )
        )

    entries = manifest.get("cases", [])
    ids = [item.get("case_id") for item in entries if isinstance(item, dict)]
    classes = [item.get("vector_class") for item in entries if isinstance(item, dict)]
    if len(ids) != len(set(ids)):
        findings.append(
            Finding(
                "CONFORMANCE-DUPLICATE-CASE",
                "manifest.cases",
                "case IDs must be unique",
            )
        )
    if classes != REQUIRED_VECTOR_CLASSES:
        findings.append(
            Finding(
                "CONFORMANCE-VECTOR-COVERAGE",
                "manifest.cases",
                "required class set/order differs",
            )
        )
    if {
        item.get("id")
        for item in manifest.get("vector_classes", [])
        if isinstance(item, dict)
    } != set(REQUIRED_VECTOR_CLASSES):
        findings.append(
            Finding(
                "CONFORMANCE-VECTOR-COVERAGE",
                "manifest.vector_classes",
                "class catalog differs",
            )
        )

    expected_relative = SUITE_ROOT / str(manifest.get("expected_results_path", ""))
    expected = _load(root, expected_relative, findings)
    expected_by_id = {}
    if isinstance(expected, dict):
        findings.extend(
            _schema_findings(
                expected, schemas["expected"], expected_relative.as_posix()
            )
        )
        if expected.get("suite_digest") != manifest.get("suite_digest"):
            findings.append(
                Finding(
                    "CONFORMANCE-SUITE-DIGEST",
                    expected_relative.as_posix(),
                    "suite binding mismatch",
                )
            )
        for record in expected.get("results", []):
            identifier = record.get("case_id")
            if identifier in expected_by_id:
                findings.append(
                    Finding(
                        "CONFORMANCE-DUPLICATE-RESULT",
                        str(identifier),
                        "duplicate expected result",
                    )
                )
            expected_by_id[identifier] = record
            if record.get("expected_result_digest") != expected_result_digest(record):
                findings.append(
                    Finding(
                        "CONFORMANCE-EXPECTED-DIGEST",
                        str(identifier),
                        "expected result digest mismatch",
                    )
                )

    expected_reference = {
        "implementation_manifest_path": REFERENCE_IMPLEMENTATION_MANIFEST.as_posix(),
        "implementation_manifest_digest": sha256_bytes(
            resolve_regular_file(
                root, REFERENCE_IMPLEMENTATION_MANIFEST.as_posix()
            ).read_bytes()
        ),
        "implementation_digest": (
            implementation.get("implementation_digest")
            if isinstance(implementation, dict)
            else None
        ),
    }
    if manifest.get("reference_verifier") != expected_reference:
        findings.append(
            Finding(
                "CONFORMANCE-IMPLEMENTATION-BINDING",
                manifest_relative.as_posix(),
                "suite manifest implementation binding mismatch",
            )
        )
    oracle_by_id = (
        {
            item["case_id"]: item
            for item in source_values.get("oracle", {}).get("results", [])
            if isinstance(item, dict)
        }
        if isinstance(source_values.get("oracle"), dict)
        else {}
    )
    actual_by_class = {}
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        relative = SUITE_ROOT / str(entry.get("path", ""))
        case = _load(root, relative, findings)
        if not isinstance(case, dict):
            continue
        identifier = str(case.get("case_id"))
        findings.extend(_schema_findings(case, schemas["case"], relative.as_posix()))
        if case.get("case_digest") != case_digest(case) or entry.get(
            "case_digest"
        ) != case.get("case_digest"):
            findings.append(
                Finding("CONFORMANCE-CASE-DIGEST", identifier, "case digest mismatch")
            )
        if case.get("conformance_input_digest") != input_digest(case):
            findings.append(
                Finding("CONFORMANCE-INPUT-DIGEST", identifier, "input digest mismatch")
            )
        if case.get("protocol_pins") != PROTOCOL_PINS:
            findings.append(
                Finding("CONFORMANCE-PROTOCOL-PIN", identifier, "case pin mismatch")
            )
        if case.get("case_definition_source_digest") != source_artifacts.get(
            "case_definitions_digest"
        ) or case.get("normative_oracle_source_digest") != source_artifacts.get(
            "normative_oracle_digest"
        ):
            findings.append(
                Finding(
                    "CONFORMANCE-SOURCE-DIGEST",
                    identifier,
                    "case source binding mismatch",
                )
            )
        oracle = oracle_by_id.get(identifier)
        expected_record = expected_by_id.get(identifier)
        if not oracle:
            findings.append(
                Finding(
                    "CONFORMANCE-ORACLE-MISSING", identifier, "normative oracle missing"
                )
            )
        else:
            oracle_projection = {key: oracle[key] for key in case["expected"]}
            if (
                case["expected"] != oracle_projection
                or case["result_status_expectation"]
                != oracle["result_status_expectation"]
            ):
                findings.append(
                    Finding(
                        "CONFORMANCE-ORACLE-BINDING",
                        identifier,
                        "generated case differs from reviewed oracle",
                    )
                )
        if not expected_record:
            findings.append(
                Finding(
                    "CONFORMANCE-EXPECTED-MISSING",
                    identifier,
                    "expected result missing",
                )
            )
        else:
            projection = {key: expected_record[key] for key in case["expected"]}
            if projection != case["expected"] or expected_record.get(
                "case_digest"
            ) != case.get("case_digest"):
                findings.append(
                    Finding(
                        "CONFORMANCE-EXPECTED-BINDING",
                        identifier,
                        "expected artifact differs from case/oracle",
                    )
                )
        codes = case.get("expected", {}).get("error_codes", [])
        if codes != sorted(set(codes)):
            findings.append(
                Finding(
                    "CONFORMANCE-ERROR-ORDER",
                    identifier,
                    "errors must be sorted and unique",
                )
            )
        if any(code not in protocol_codes | CONFORMANCE_ERROR_CODES for code in codes):
            findings.append(
                Finding("CONFORMANCE-ERROR-UNKNOWN", identifier, "unknown error code")
            )
        if any(
            item.get("kind") in {"semantic-probe", "runner-directive"}
            for item in case.get("ordered_inputs", [])
            if isinstance(item, dict)
        ):
            findings.append(
                Finding(
                    "CONFORMANCE-TAUTOLOGICAL-PROBE",
                    identifier,
                    "directive/probe forbidden",
                )
            )
        if execute:
            try:
                actual = execute_case(root, root / SUITE_ROOT, case)
                actual_by_class[case["vector_class"]] = actual
                findings.extend(
                    _schema_findings(
                        actual.initial_state_projection,
                        schemas["state_projection"],
                        f"{identifier}.initial_state_projection",
                    )
                )
                findings.extend(
                    _schema_findings(
                        actual.final_state_projection,
                        schemas["state_projection"],
                        f"{identifier}.final_state_projection",
                    )
                )
                status, _, matched = compare_actual_to_expected(
                    actual, case["expected"]
                )
                intended_mismatch = (
                    case["vector_class"] == "CV-RUNNER-EXPECTED-MISMATCH"
                )
                if (
                    matched == intended_mismatch
                    or status != case["result_status_expectation"]
                ):
                    findings.append(
                        Finding(
                            "CONFORMANCE-EXPECTED-MISMATCH",
                            identifier,
                            "actual/oracle comparison contract failed",
                        )
                    )
            except (OSError, ValueError, KeyError, TypeError, ConformanceError):
                findings.append(
                    Finding(
                        "CONFORMANCE-TOOL-ERROR",
                        identifier,
                        "bounded execution failure",
                    )
                )

    # Generated artifacts are canonical projections of sources; execution cannot update them.
    try:
        generated = generated_files(root)
        validate_generated_suite_tree(root, generated)
        tree_manifest = _load(root, SUITE_TREE_MANIFEST, findings)
        if isinstance(tree_manifest, dict):
            findings.extend(
                _schema_findings(
                    tree_manifest,
                    schemas["suite_tree"],
                    SUITE_TREE_MANIFEST.as_posix(),
                )
            )
            entries_value = tree_manifest.get("entries", [])
            if (
                tree_manifest.get("file_count") != len(entries_value)
                or tree_manifest.get("tree_digest") != suite_tree_digest(entries_value)
                or manifest.get("suite_tree_manifest_path") != SUITE_TREE_MANIFEST.name
            ):
                findings.append(
                    Finding(
                        "CONFORMANCE-SUITE-TREE-DIGEST",
                        SUITE_TREE_MANIFEST.as_posix(),
                        "tree manifest binding mismatch",
                    )
                )
    except (OSError, ValueError, KeyError, TypeError, ConformanceError):
        findings.append(
            Finding(
                "CONFORMANCE-GENERATOR",
                "generated-files",
                "deterministic projection failed",
            )
        )
    try:
        tree = ast.parse(
            resolve_regular_file(
                root, "scripts/generate_conformance_suite.py"
            ).read_text(encoding="utf-8")
        )
        forbidden = [
            node
            for node in ast.walk(tree)
            if isinstance(node, (ast.Import, ast.ImportFrom))
            and (
                (
                    isinstance(node, ast.ImportFrom)
                    and node.module == "conformance_engine"
                )
                or (
                    isinstance(node, ast.Import)
                    and any(alias.name == "conformance_engine" for alias in node.names)
                )
            )
        ]
        if forbidden:
            findings.append(
                Finding(
                    "CONFORMANCE-ORACLE-INDEPENDENCE",
                    "scripts/generate_conformance_suite.py",
                    "generator imports implementation under test",
                )
            )
    except (OSError, SyntaxError, ConformanceError):
        findings.append(
            Finding(
                "CONFORMANCE-GENERATOR",
                "scripts/generate_conformance_suite.py",
                "source inspection failed",
            )
        )
    if execute and all(
        key in actual_by_class
        for key in (
            "CV-VALID-END-TO-END",
            "CV-VALID-NO-MATCH",
            "CV-VALID-INDETERMINATE",
        )
    ):
        results = [
            actual_by_class[key]
            for key in (
                "CV-VALID-END-TO-END",
                "CV-VALID-NO-MATCH",
                "CV-VALID-INDETERMINATE",
            )
        ]
        if (
            len({tuple(item.local_result_state.values()) for item in results}) != 3
            or len({item.final_state_digest for item in results}) != 3
        ):
            findings.append(
                Finding(
                    "CONFORMANCE-RESULT-VARIANTS",
                    "valid-results",
                    "three Party-local result executions must differ",
                )
            )
    return sorted(set(findings))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--no-execute", action="store_true")
    parser.add_argument("--print-digest", action="store_true")
    args = parser.parse_args(argv)
    root = args.root.resolve()
    findings = validate_repository(root, execute=not args.no_execute)
    for finding in findings:
        print(f"conformance-suite: error: {finding}", file=sys.stderr)
    if findings:
        return 1
    manifest = json.loads((root / SUITE_ROOT / "suite-manifest.v0.1.json").read_text())
    print(
        f"conformance-suite: valid cases={len(manifest['cases'])} classes={len(manifest['vector_classes'])} sha256={manifest['suite_digest'].removeprefix('sha256:')}"
    )
    if args.print_digest:
        print(manifest["suite_digest"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
