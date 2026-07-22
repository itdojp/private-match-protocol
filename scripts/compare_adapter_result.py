#!/usr/bin/env python3
"""Validate an offline independent-adapter result against one fixed case."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

from conformance_common import (
    ConformanceError,
    SUITE_ROOT,
    result_digest,
    strict_json_bytes,
)
from validate_conformance_suite import validate_repository


def _load(path: Path, *, canonical: bool = True) -> dict[str, Any]:
    value = strict_json_bytes(
        path.read_bytes(), path=path.name, require_canonical=canonical
    )
    if not isinstance(value, dict):
        raise ConformanceError("CONFORMANCE-ARTIFACT-TYPE", path.name)
    return value


def compare(
    root: Path, adapter: dict[str, Any], case: dict[str, Any], manifest: dict[str, Any]
) -> list[str]:
    errors: list[str] = []
    if adapter.get("result_digest") != result_digest(adapter):
        errors.append("CONFORMANCE-ADAPTER-RESULT-DIGEST")
    if adapter.get("suite") != {
        "id": manifest["suite_id"],
        "version": manifest["suite_version"],
        "digest": manifest["suite_digest"],
    }:
        errors.append("CONFORMANCE-SUITE-DIGEST")
    if adapter.get("case") != {
        "id": case["case_id"],
        "digest": case["case_digest"],
    }:
        errors.append("CONFORMANCE-CASE-DIGEST")
    expected = case["expected"]
    if adapter.get("status") != expected["runner_status"]:
        errors.append("CONFORMANCE-STATUS-MISMATCH")
    if adapter.get("protocol_outcome") != expected["protocol_outcome"]:
        errors.append("CONFORMANCE-EXPECTED-MISMATCH")
    if adapter.get("error_codes") != expected["error_codes"]:
        errors.append("CONFORMANCE-ERROR-CODE-MISMATCH")
    if adapter.get("final_state_digest") != expected["state_digest"]:
        errors.append("CONFORMANCE-STATE-DIGEST-MISMATCH")
    if adapter.get("final_transcript_head") != expected["transcript_head"]:
        errors.append("CONFORMANCE-TRANSCRIPT-DIGEST-MISMATCH")
    return sorted(set(errors))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--adapter-result", required=True)
    parser.add_argument("--case-id", required=True)
    args = parser.parse_args(argv)
    root = args.root.resolve()
    try:
        if validate_repository(root, execute=False):
            raise ConformanceError("CONFORMANCE-SUITE-INVALID", "suite")
        candidate = Path(args.adapter_result)
        if candidate.is_absolute() or ".." in candidate.parts:
            raise ConformanceError("CONFORMANCE-PATH", "adapter-result")
        adapter = _load(root / candidate)
        schema = json.loads(
            (root / "schema/conformance-adapter-result.v0.1.schema.json").read_text()
        )
        if list(Draft202012Validator(schema).iter_errors(adapter)):
            raise ConformanceError("CONFORMANCE-ADAPTER-SCHEMA", "adapter-result")
        manifest = _load(root / SUITE_ROOT / "suite-manifest.v0.1.json")
        entries = [
            item for item in manifest["cases"] if item["case_id"] == args.case_id
        ]
        if len(entries) != 1:
            raise ConformanceError("CONFORMANCE-CASE-UNKNOWN", "case-id")
        case = _load(root / SUITE_ROOT / entries[0]["path"])
        errors = compare(root, adapter, case, manifest)
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
