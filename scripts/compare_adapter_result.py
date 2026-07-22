#!/usr/bin/env python3
"""Validate an offline independent-adapter result against one fixed case."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

from conformance_common import (
    ConformanceError,
    SUITE_ROOT,
    resolve_regular_file,
    result_digest,
    strict_json_bytes,
    validate_relative_path,
)
from validate_conformance_suite import validate_repository

TEST_FIXTURE_LIMITATIONS = [
    "Synthetic offline comparison fixture; not an independent implementation or interoperability certification."
]


def _load(root: Path, relative: str, *, canonical: bool = True) -> dict[str, Any]:
    logical = validate_relative_path(relative)
    path = resolve_regular_file(root, logical.as_posix())
    value = strict_json_bytes(
        path.read_bytes(), path=logical.as_posix(), require_canonical=canonical
    )
    if not isinstance(value, dict):
        raise ConformanceError("CONFORMANCE-ARTIFACT-TYPE", logical.as_posix())
    return value


def compare(
    root: Path,
    adapter: dict[str, Any],
    case: dict[str, Any],
    manifest: dict[str, Any],
    *,
    mode: str,
) -> list[str]:
    """Compare every interoperable evidence field declared by the contract."""

    del root  # Comparison is intentionally pure after safe artifact loading.
    errors: list[str] = []
    expected = case["expected"]
    expected_mutation = {
        key: value == "changed"
        for key, value in expected["mutation_assertions"].items()
    }
    exact = (
        (
            "suite",
            {
                "id": manifest["suite_id"],
                "version": manifest["suite_version"],
                "digest": manifest["suite_digest"],
            },
            "CONFORMANCE-SUITE-DIGEST",
        ),
        (
            "case",
            {
                "id": case["case_id"],
                "digest": case["case_digest"],
                "input_digest": case["conformance_input_digest"],
            },
            "CONFORMANCE-CASE-DIGEST",
        ),
        ("status", expected["runner_status"], "CONFORMANCE-STATUS-MISMATCH"),
        (
            "protocol_outcome",
            expected["protocol_outcome"],
            "CONFORMANCE-EXPECTED-MISMATCH",
        ),
        ("error_codes", expected["error_codes"], "CONFORMANCE-ERROR-CODE-MISMATCH"),
        (
            "initial_state_digest",
            expected["initial_state_digest"],
            "CONFORMANCE-INITIAL-STATE-DIGEST-MISMATCH",
        ),
        (
            "final_state_digest",
            expected["state_digest"],
            "CONFORMANCE-STATE-DIGEST-MISMATCH",
        ),
        (
            "initial_transcript_head",
            expected["initial_transcript_head"],
            "CONFORMANCE-INITIAL-TRANSCRIPT-DIGEST-MISMATCH",
        ),
        (
            "final_transcript_head",
            expected["transcript_head"],
            "CONFORMANCE-TRANSCRIPT-DIGEST-MISMATCH",
        ),
        (
            "accepted_event_count",
            expected["accepted_event_count"],
            "CONFORMANCE-ACCEPTED-COUNT-MISMATCH",
        ),
        ("mutation_summary", expected_mutation, "CONFORMANCE-MUTATION-MISMATCH"),
        (
            "cached_response_authorized",
            expected["cached_response_authorized"],
            "CONFORMANCE-CACHED-RESPONSE-MISMATCH",
        ),
    )
    for field, value, code in exact:
        if adapter.get(field) != value:
            errors.append(code)
    if adapter.get("result_digest") != result_digest(adapter):
        errors.append("CONFORMANCE-ADAPTER-RESULT-DIGEST")

    limitations = adapter.get("limitations")
    if not isinstance(limitations, list) or limitations != sorted(set(limitations)):
        errors.append("CONFORMANCE-LIMITATIONS-BOUNDARY")
    if mode == "test-fixture":
        if (
            adapter.get("adapter_mode") != "test-fixture"
            or adapter.get("artifact_status") != "test-only"
            or adapter.get("adapter", {}).get("id")
            != "synthetic-offline-adapter-fixture"
            or limitations != TEST_FIXTURE_LIMITATIONS
        ):
            errors.append("CONFORMANCE-ADAPTER-MODE")
    elif mode == "normal":
        if (
            adapter.get("adapter_mode") != "independent-result"
            or adapter.get("artifact_status") != "draft"
            or adapter.get("adapter", {}).get("id")
            == "synthetic-offline-adapter-fixture"
            or not limitations
        ):
            errors.append("CONFORMANCE-ADAPTER-MODE")
    else:
        errors.append("CONFORMANCE-ADAPTER-MODE")
    return sorted(set(errors))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--adapter-result", required=True)
    parser.add_argument("--case-id", required=True)
    parser.add_argument("--mode", choices=("normal", "test-fixture"), required=True)
    args = parser.parse_args(argv)
    root = args.root.resolve()
    try:
        if validate_repository(root, execute=False):
            raise ConformanceError("CONFORMANCE-SUITE-INVALID", "suite")
        adapter = _load(root, args.adapter_result)
        schema = _load(root, "schema/conformance-adapter-result.v0.1.schema.json")
        if list(Draft202012Validator(schema).iter_errors(adapter)):
            raise ConformanceError("CONFORMANCE-ADAPTER-SCHEMA", "adapter-result")
        manifest = _load(root, (SUITE_ROOT / "suite-manifest.v0.1.json").as_posix())
        entries = [
            item for item in manifest["cases"] if item["case_id"] == args.case_id
        ]
        if len(entries) != 1:
            raise ConformanceError("CONFORMANCE-CASE-UNKNOWN", "case-id")
        case = _load(root, (SUITE_ROOT / entries[0]["path"]).as_posix())
        errors = compare(root, adapter, case, manifest, mode=args.mode)
        if errors:
            print("adapter-compare: mismatch " + ",".join(errors), file=sys.stderr)
            return 1
    except (OSError, ValueError, KeyError, TypeError, ConformanceError):
        print("adapter-compare: error [bounded]", file=sys.stderr)
        return 1
    print(f"adapter-compare: match case={args.case_id} status={adapter['status']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
