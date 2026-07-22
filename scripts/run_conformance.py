#!/usr/bin/env python3
"""Run fixed suite cases through the deterministic reference verifier."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

from canonicalize_message import canonicalize
from conformance_common import (
    ConformanceError,
    SUITE_ROOT,
    atomic_write,
    reference_implementation_digest,
    resolve_directory,
    result_digest,
    strict_json_bytes,
)
from conformance_engine import execute_case
from validate_conformance_suite import validate_repository


def _load(path: Path) -> dict[str, Any]:
    value = strict_json_bytes(path.read_bytes(), path=path.name, require_canonical=True)
    if not isinstance(value, dict):
        raise ConformanceError("CONFORMANCE-ARTIFACT-TYPE", path.name)
    return value


def build_result(
    root: Path,
    manifest: dict[str, Any],
    case: dict[str, Any],
) -> dict[str, Any]:
    actual = execute_case(root, root / SUITE_ROOT, case)
    expected = case["expected"]
    actual_expected = {
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
    expected_match = actual_expected == expected
    status = actual.status
    error_codes = list(actual.error_codes)
    if not expected_match and status == "pass":
        status = "fail"
        error_codes.append("CONFORMANCE-EXPECTED-MISMATCH")
    result = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "schema_version": "0.1",
        "suite": {
            "id": manifest["suite_id"],
            "version": manifest["suite_version"],
            "digest": manifest["suite_digest"],
        },
        "case": {
            "id": case["case_id"],
            "digest": case["case_digest"],
            "input_digest": case["conformance_input_digest"],
        },
        "protocol_pins": case["protocol_pins"],
        "verifier": {
            "id": "private-match-reference-verifier",
            "version": "0.1",
            "implementation_digest": reference_implementation_digest(root),
        },
        "adapter": {
            "id": manifest["fixture_adapter"]["id"],
            "version": manifest["fixture_adapter"]["version"],
            "digest": manifest["fixture_adapter"]["digest"],
            "cryptographic_validity": "not-evaluated",
        },
        "status": status,
        "protocol_outcome": actual.protocol_outcome,
        "expected_match": expected_match,
        "error_codes": sorted(set(error_codes)),
        "initial_state_digest": actual.initial_state_digest,
        "final_state_digest": actual.final_state_digest,
        "initial_transcript_head": actual.initial_transcript_head,
        "final_transcript_head": actual.final_transcript_head,
        "accepted_event_count": actual.accepted_event_count,
        "mutation_summary": actual.mutation_summary,
        "limitations": sorted(set(case["limitations"] + actual.limitations)),
        "artifact_status": "draft",
        "result_digest": "sha256:" + "0" * 64,
    }
    result["result_digest"] = result_digest(result)
    schema = json.loads(
        (root / "schema/conformance-run-result.v0.1.schema.json").read_text()
    )
    errors = list(Draft202012Validator(schema).iter_errors(result))
    if errors:
        raise ConformanceError("CONFORMANCE-RUN-RESULT-SCHEMA", case["case_id"])
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path("."))
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--case-id")
    group.add_argument("--all", action="store_true")
    parser.add_argument("--output-dir", required=True)
    args = parser.parse_args(argv)
    root = args.root.resolve()
    try:
        findings = validate_repository(root, execute=False)
        if findings:
            raise ConformanceError("CONFORMANCE-SUITE-INVALID", "suite")
        manifest = _load(root / SUITE_ROOT / "suite-manifest.v0.1.json")
        entries = manifest["cases"]
        if args.case_id:
            entries = [item for item in entries if item["case_id"] == args.case_id]
            if len(entries) != 1:
                raise ConformanceError("CONFORMANCE-CASE-UNKNOWN", "case-id")
        output_root = resolve_directory(root, args.output_dir, create=True)
        for entry in entries:
            case = _load(root / SUITE_ROOT / entry["path"])
            result = build_result(root, manifest, case)
            relative = f"{case['case_id'].lower()}.result.v0.1.json"
            atomic_write(output_root, relative, canonicalize(result))
    except (OSError, ValueError, KeyError, TypeError, ConformanceError):
        print("reference-verifier: error [bounded]", file=sys.stderr)
        return 1
    print(f"reference-verifier: complete cases={len(entries)} output={args.output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
