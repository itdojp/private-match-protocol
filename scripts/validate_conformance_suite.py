#!/usr/bin/env python3
"""Validate and execute the draft private-match-core/v0.1 conformance suite."""

from __future__ import annotations

import argparse
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
    SUITE_ROOT,
    case_digest,
    domain_digest,
    input_digest,
    resolve_regular_file,
    sha256_bytes,
    strict_json_bytes,
    suite_digest,
)
from conformance_engine import execute_case
from generate_conformance_suite import PROTOCOL_PINS, REQUIRED_VECTOR_CLASSES
from strict_yaml import strict_yaml_load


SCHEMAS = {
    "manifest": Path("schema/conformance-suite-manifest.v0.1.schema.json"),
    "case": Path("schema/conformance-case.v0.1.schema.json"),
    "expected": Path("schema/conformance-expected-result.v0.1.schema.json"),
    "run": Path("schema/conformance-run-result.v0.1.schema.json"),
    "adapter": Path("schema/conformance-adapter-result.v0.1.schema.json"),
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
            path.read_bytes(), path=relative.as_posix(), require_canonical=False
        )
    except (OSError, ConformanceError, ValueError) as error:
        code = (
            error.code
            if isinstance(error, ConformanceError)
            else "CONFORMANCE-JSON-PARSE"
        )
        findings.append(
            Finding(code, relative.as_posix(), "artifact could not be loaded")
        )
        return None


def _schema_findings(value: Any, schema: dict[str, Any], path: str) -> list[Finding]:
    findings = []
    for error in Draft202012Validator(
        schema, format_checker=FormatChecker()
    ).iter_errors(value):
        suffix = ".".join(map(str, error.absolute_path))
        findings.append(
            Finding(
                "CONFORMANCE-SCHEMA",
                f"{path}{'.' + suffix if suffix else ''}",
                "closed Schema constraint failed",
            )
        )
    return findings


def validate_repository(root: Path, *, execute: bool = True) -> list[Finding]:
    findings: list[Finding] = []
    schemas: dict[str, dict[str, Any]] = {}
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

    try:
        adapter_registry = strict_yaml_load(
            resolve_regular_file(
                root, "conformance/interop/adapters.v0.1.yaml"
            ).read_text(encoding="utf-8")
        )
        if set(adapter_registry) != {
            "schema_version",
            "artifact_status",
            "registry_id",
            "adapters",
        }:
            raise ValueError("closed adapter registry")
        adapter_ids: list[str] = []
        for adapter in adapter_registry.get("adapters", []):
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
            if set(adapter) != required:
                raise ValueError("closed adapter entry")
            adapter_ids.append(adapter["id"])
            if (
                adapter["implementation_status"] != "planned"
                or adapter["source_repository_policy"] != "public-only"
                or adapter["target_suite"]
                != {"id": "private-match-core", "version": "0.1"}
                or adapter["required_vectors"] != "all-suite-manifest-vector-classes"
            ):
                raise ValueError("planned adapter boundary")
        if len(adapter_ids) != len(set(adapter_ids)) or not adapter_ids:
            raise ValueError("adapter identity")
    except (OSError, ValueError, TypeError, KeyError, yaml.YAMLError, ConformanceError):
        findings.append(
            Finding(
                "CONFORMANCE-ADAPTER-REGISTRY",
                "conformance/interop/adapters.v0.1.yaml",
                "closed planned-adapter contract failed",
            )
        )

    suite_root = root / SUITE_ROOT
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
    try:
        planned_path = str(manifest.get("planned_adapters_path", ""))
        planned_bytes = resolve_regular_file(root, planned_path).read_bytes()
        if sha256_bytes(planned_bytes) != manifest.get("planned_adapters_digest"):
            findings.append(
                Finding(
                    "CONFORMANCE-ADAPTER-DIGEST",
                    planned_path,
                    "planned adapter registry digest mismatch",
                )
            )
    except (OSError, ConformanceError):
        findings.append(
            Finding(
                "CONFORMANCE-ADAPTER-REGISTRY",
                "manifest.planned_adapters_path",
                "planned adapter registry unavailable",
            )
        )

    # Recompute current public Protocol pins.  The conformance/messages tree is
    # the reviewed pre-Issue-6 input pin, not the newly generated suite tree.
    try:
        machine = strict_yaml_load(
            resolve_regular_file(
                root, "specs/state-machines/private-match-core-session-v0.1.yaml"
            ).read_text(encoding="utf-8")
        )
        machine_digest = sha256_bytes(canonicalize(machine))
        protocol_error_codes = {
            item.get("code")
            for item in machine.get("failure_taxonomy", [])
            if isinstance(item, dict)
        }
        registry_raw = resolve_regular_file(
            root, "registry/message-types.v0.1.yaml"
        ).read_bytes()
        if machine_digest != PROTOCOL_PINS["state_machine_digest"]:
            findings.append(
                Finding("CONFORMANCE-PROTOCOL-PIN", "state-machine", "digest mismatch")
            )
        if sha256_bytes(registry_raw) != PROTOCOL_PINS["message_registry_digest"]:
            findings.append(
                Finding(
                    "CONFORMANCE-PROTOCOL-PIN", "message-registry", "digest mismatch"
                )
            )
    except (OSError, ValueError, yaml.YAMLError, ConformanceError):
        protocol_error_codes = set()
        findings.append(
            Finding(
                "CONFORMANCE-PROTOCOL-PIN", "protocol-artifacts", "artifact unavailable"
            )
        )

    case_entries = manifest.get("cases", [])
    ids = [entry.get("case_id") for entry in case_entries if isinstance(entry, dict)]
    classes = [
        entry.get("vector_class") for entry in case_entries if isinstance(entry, dict)
    ]
    if len(ids) != len(set(ids)):
        findings.append(
            Finding(
                "CONFORMANCE-DUPLICATE-CASE",
                "manifest.cases",
                "case IDs must be unique",
            )
        )
    if set(classes) != set(REQUIRED_VECTOR_CLASSES):
        findings.append(
            Finding(
                "CONFORMANCE-VECTOR-COVERAGE",
                "manifest.cases",
                "required classes differ",
            )
        )
    declared_classes = {
        item.get("id")
        for item in manifest.get("vector_classes", [])
        if isinstance(item, dict)
    }
    if declared_classes != set(REQUIRED_VECTOR_CLASSES):
        findings.append(
            Finding(
                "CONFORMANCE-VECTOR-COVERAGE",
                "manifest.vector_classes",
                "class catalog differs",
            )
        )

    expected_relative = SUITE_ROOT / str(manifest.get("expected_results_path", ""))
    expected = _load(root, expected_relative, findings)
    expected_by_id: dict[str, dict[str, Any]] = {}
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
            if isinstance(record, dict):
                identifier = record.get("case_id")
                if identifier in expected_by_id:
                    findings.append(
                        Finding(
                            "CONFORMANCE-DUPLICATE-RESULT",
                            expected_relative.as_posix(),
                            "duplicate case result",
                        )
                    )
                expected_by_id[str(identifier)] = record
                material = dict(record)
                observed = material.pop("expected_result_digest", None)
                recomputed = domain_digest(
                    b"private-match-conformance-expected-result/v0.1\x00", material
                )
                if observed != recomputed:
                    findings.append(
                        Finding(
                            "CONFORMANCE-EXPECTED-DIGEST",
                            str(identifier),
                            "result digest mismatch",
                        )
                    )

    for entry in case_entries:
        if not isinstance(entry, dict):
            continue
        relative = SUITE_ROOT / str(entry.get("path", ""))
        case = _load(root, relative, findings)
        if not isinstance(case, dict):
            continue
        findings.extend(_schema_findings(case, schemas["case"], relative.as_posix()))
        identifier = str(case.get("case_id"))
        if case.get("case_digest") != case_digest(case) or entry.get(
            "case_digest"
        ) != case.get("case_digest"):
            findings.append(
                Finding(
                    "CONFORMANCE-CASE-DIGEST",
                    relative.as_posix(),
                    "case digest mismatch",
                )
            )
        if case.get("conformance_input_digest") != input_digest(case):
            findings.append(
                Finding(
                    "CONFORMANCE-INPUT-DIGEST",
                    relative.as_posix(),
                    "input digest mismatch",
                )
            )
        if case.get("protocol_pins") != manifest.get("protocol_pins"):
            findings.append(
                Finding(
                    "CONFORMANCE-PROTOCOL-PIN", relative.as_posix(), "case pin mismatch"
                )
            )
        error_codes = case.get("expected", {}).get("error_codes", [])
        if error_codes != sorted(set(error_codes)):
            findings.append(
                Finding(
                    "CONFORMANCE-ERROR-ORDER",
                    identifier,
                    "errors must be sorted and unique",
                )
            )
        if any(
            code not in protocol_error_codes | CONFORMANCE_ERROR_CODES
            for code in error_codes
        ):
            findings.append(
                Finding("CONFORMANCE-ERROR-UNKNOWN", identifier, "unknown error code")
            )
        expected_record = expected_by_id.get(identifier)
        if expected_record is None:
            findings.append(
                Finding(
                    "CONFORMANCE-EXPECTED-MISSING", identifier, "no expected result"
                )
            )
        elif (
            expected_record.get("case_digest") != case.get("case_digest")
            or expected_record.get("expected_status")
            != case.get("expected", {}).get("runner_status")
            or expected_record.get("protocol_outcome")
            != case.get("expected", {}).get("protocol_outcome")
            or expected_record.get("error_codes")
            != case.get("expected", {}).get("error_codes")
        ):
            findings.append(
                Finding(
                    "CONFORMANCE-EXPECTED-BINDING", identifier, "case/expected mismatch"
                )
            )
        if execute:
            try:
                actual = execute_case(root, suite_root, case)
            except (OSError, ValueError, KeyError, TypeError, ConformanceError):
                findings.append(
                    Finding(
                        "CONFORMANCE-TOOL-ERROR",
                        identifier,
                        "bounded execution failure",
                    )
                )
                continue
            expected_case = case.get("expected", {})
            actual_values = {
                "runner_status": actual.status,
                "protocol_outcome": actual.protocol_outcome,
                "terminal_phase": actual.terminal_phase,
                "error_codes": actual.error_codes,
                "transcript_head": actual.final_transcript_head,
                "state_digest": actual.final_state_digest,
                "mutation_assertions": {
                    key: "changed" if changed else "unchanged"
                    for key, changed in actual.mutation_summary.items()
                },
            }
            if expected_case != actual_values:
                findings.append(
                    Finding(
                        "CONFORMANCE-EXPECTED-MISMATCH",
                        identifier,
                        "actual outcome differs",
                    )
                )

    material_relative = SUITE_ROOT / str(manifest.get("verification_material_path", ""))
    try:
        material_bytes = resolve_regular_file(
            root, material_relative.as_posix()
        ).read_bytes()
        if sha256_bytes(material_bytes) != manifest.get("fixture_adapter", {}).get(
            "digest"
        ):
            findings.append(
                Finding(
                    "CONFORMANCE-ADAPTER-DIGEST",
                    material_relative.as_posix(),
                    "fixture digest mismatch",
                )
            )
    except (OSError, ConformanceError):
        findings.append(
            Finding(
                "CONFORMANCE-ADAPTER-MISSING",
                material_relative.as_posix(),
                "fixture unavailable",
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
        f"conformance-suite: valid cases={len(manifest['cases'])} "
        f"classes={len(manifest['vector_classes'])} sha256={manifest['suite_digest'].removeprefix('sha256:')}"
    )
    if args.print_digest:
        print(manifest["suite_digest"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
