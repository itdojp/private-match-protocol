#!/usr/bin/env python3
"""Run fixed cases and write deterministic, transactional reference results."""

from __future__ import annotations

import argparse
import os
import shutil
import sys
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

from canonicalize_message import canonicalize
from conformance_common import (
    ConformanceError,
    SUITE_ROOT,
    atomic_write,
    domain_digest,
    reference_implementation_manifest,
    reference_implementation_digest,
    resolve_directory,
    result_digest,
    run_set_digest,
    sha256_bytes,
    strict_json_bytes,
    validate_relative_path,
)
from conformance_engine import compare_actual_to_expected, execute_case
from validate_conformance_suite import validate_repository


def _load(path: Path) -> dict[str, Any]:
    value = strict_json_bytes(path.read_bytes(), path=path.name, require_canonical=True)
    if not isinstance(value, dict):
        raise ConformanceError("CONFORMANCE-ARTIFACT-TYPE", path.name)
    return value


def build_result(
    root: Path, manifest: dict[str, Any], case: dict[str, Any]
) -> dict[str, Any]:
    actual = execute_case(root, root / SUITE_ROOT, case)
    status, error_codes, expected_match = compare_actual_to_expected(
        actual, case["expected"]
    )
    implementation_manifest = reference_implementation_manifest(root)
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
            "implementation_digest": implementation_manifest["implementation_digest"],
            "implementation_manifest_digest": sha256_bytes(
                (
                    root
                    / "conformance/source/reference-verifier-implementation.v0.1.json"
                ).read_bytes()
            ),
        },
        "adapter": {
            "id": manifest["fixture_adapter"]["id"],
            "version": manifest["fixture_adapter"]["version"],
            "digest": manifest["fixture_adapter"]["digest"],
            "cryptographic_validity": "not-evaluated",
        },
        "status": status,
        "protocol_outcome": actual.protocol_outcome,
        "terminal_phase": actual.terminal_phase,
        "expected_match": expected_match,
        "error_codes": error_codes,
        "initial_state_digest": actual.initial_state_digest,
        "final_state_digest": actual.final_state_digest,
        "initial_transcript_head": actual.initial_transcript_head,
        "final_transcript_head": actual.final_transcript_head,
        "accepted_event_count": actual.accepted_event_count,
        "mutation_summary": actual.mutation_summary,
        "cached_response_authorized": actual.cached_response_authorized,
        "deterministic_work_units": actual.work_units,
        "limitations": sorted(set(case["limitations"] + actual.limitations)),
        "artifact_status": "draft",
        "result_digest": "sha256:" + "0" * 64,
    }
    result["result_digest"] = result_digest(result)
    schema = _load(root / "schema/conformance-run-result.v0.1.schema.json")
    if list(Draft202012Validator(schema).iter_errors(result)):
        raise ConformanceError("CONFORMANCE-RUN-RESULT-SCHEMA", case["case_id"])
    return result


def _result_name(case_id: str) -> str:
    return f"{case_id.lower()}.result.v0.1.json"


def _run_set_manifest(
    manifest: dict[str, Any],
    results: list[tuple[str, bytes, dict[str, Any]]],
    implementation_digest: str,
) -> dict[str, Any]:
    entries = [
        {
            "case_id": result["case"]["id"],
            "path": path,
            "result_digest": result["result_digest"],
            "file_digest": sha256_bytes(raw),
            "status": result["status"],
        }
        for path, raw, result in results
    ]
    counts = {
        status: sum(item["status"] == status for item in entries)
        for status in ("pass", "fail", "skip", "unsupported", "timeout", "tool-error")
    }
    value = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "schema_version": "0.1",
        "artifact_status": "draft",
        "suite_digest": manifest["suite_digest"],
        "verifier_implementation_digest": implementation_digest,
        "case_ids": [item["case_id"] for item in entries],
        "results": entries,
        "complete_result_tree_digest": domain_digest(
            b"private-match-conformance-result-tree/v0.1\x00",
            [
                {"path": item["path"], "file_digest": item["file_digest"]}
                for item in entries
            ],
        ),
        "status_counts": counts,
        "run_set_digest": "sha256:" + "0" * 64,
    }
    value["run_set_digest"] = run_set_digest(value)
    return value


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def validate_staged_run_set(
    staging: Path, run_set: dict[str, Any], expected_case_ids: list[str]
) -> None:
    """Re-read the complete staged tree before the directory-level commit."""

    if run_set.get("run_set_digest") != run_set_digest(run_set):
        raise ConformanceError("CONFORMANCE-RUN-SET-DIGEST", "run-set")
    entries = run_set.get("results", [])
    if (
        not isinstance(entries, list)
        or [item.get("case_id") for item in entries] != expected_case_ids
    ):
        raise ConformanceError("CONFORMANCE-RUN-SET-COUNT", "run-set")
    paths = [str(item.get("path", "")) for item in entries]
    if len(paths) != len(set(paths)):
        raise ConformanceError("CONFORMANCE-RUN-SET-FILES", "run-set")
    expected_files = set(paths) | {"run-set-manifest.v0.1.json"}
    observed = list(staging.iterdir())
    if any(path.is_symlink() or not path.is_file() for path in observed):
        raise ConformanceError("CONFORMANCE-RUN-SET-FILES", "run-set")
    observed_files = {path.name for path in observed}
    if observed_files != expected_files:
        raise ConformanceError("CONFORMANCE-RUN-SET-FILES", "run-set")
    tree_entries = []
    statuses = {
        status: 0
        for status in ("pass", "fail", "skip", "unsupported", "timeout", "tool-error")
    }
    for item in entries:
        raw = (staging / item["path"]).read_bytes()
        result = strict_json_bytes(raw, path=item["path"], require_canonical=True)
        if (
            not isinstance(result, dict)
            or result.get("case", {}).get("id") != item["case_id"]
            or result.get("status") != item["status"]
        ):
            raise ConformanceError("CONFORMANCE-RUN-SET-BINDING", item["path"])
        if (
            sha256_bytes(raw) != item["file_digest"]
            or result.get("result_digest") != item["result_digest"]
            or result_digest(result) != item["result_digest"]
        ):
            raise ConformanceError("CONFORMANCE-RUN-SET-RESULT-DIGEST", item["path"])
        tree_entries.append({"path": item["path"], "file_digest": item["file_digest"]})
        statuses[item["status"]] += 1
    tree = domain_digest(
        b"private-match-conformance-result-tree/v0.1\x00", tree_entries
    )
    if tree != run_set.get("complete_result_tree_digest") or statuses != run_set.get(
        "status_counts"
    ):
        raise ConformanceError("CONFORMANCE-RUN-SET-TREE", "run-set")


def _write_all_transactionally(
    root: Path, relative: str, manifest: dict[str, Any], entries: list[dict[str, Any]]
) -> None:
    logical = validate_relative_path(relative)
    final = root.joinpath(*logical.parts)
    parent_relative = logical.parent.as_posix()
    parent = (
        root
        if parent_relative == "."
        else resolve_directory(root, parent_relative, create=True)
    )
    if final.exists() or final.is_symlink():
        raise ConformanceError("CONFORMANCE-OUTPUT-EXISTS", relative)
    staging = final.with_name(f".{final.name}.partial")
    if staging.exists() or staging.is_symlink():
        raise ConformanceError("CONFORMANCE-OUTPUT-STAGING", relative)
    staging.mkdir(mode=0o700)
    committed = False
    try:
        results: list[tuple[str, bytes, dict[str, Any]]] = []
        for entry in entries:
            case = _load(root / SUITE_ROOT / entry["path"])
            result = build_result(root, manifest, case)
            name = _result_name(case["case_id"])
            raw = canonicalize(result)
            atomic_write(staging, name, raw)
            results.append((name, raw, result))
        implementation = reference_implementation_digest(root)
        run_set = _run_set_manifest(manifest, results, implementation)
        run_set_schema = _load(
            root / "schema/conformance-run-set-manifest.v0.1.schema.json"
        )
        if list(Draft202012Validator(run_set_schema).iter_errors(run_set)):
            raise ConformanceError("CONFORMANCE-RUN-SET-SCHEMA", relative)
        run_set_raw = canonicalize(run_set)
        atomic_write(staging, "run-set-manifest.v0.1.json", run_set_raw)
        validate_staged_run_set(
            staging, run_set, [entry["case_id"] for entry in entries]
        )
        _fsync_directory(staging)
        os.replace(staging, final)
        committed = True
        _fsync_directory(parent)
    except Exception:
        if staging.exists() and not staging.is_symlink():
            shutil.rmtree(staging)
        if committed and final.exists() and not final.is_symlink():
            shutil.rmtree(final)
            _fsync_directory(parent)
        raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path("."))
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--case-id")
    group.add_argument("--all", action="store_true")
    parser.add_argument("--output-dir", required=True)
    args = parser.parse_args(argv)
    root = args.root.resolve()
    entries: list[dict[str, Any]] = []
    try:
        if validate_repository(root, execute=False):
            raise ConformanceError("CONFORMANCE-SUITE-INVALID", "suite")
        manifest = _load(root / SUITE_ROOT / "suite-manifest.v0.1.json")
        entries = manifest["cases"]
        if args.case_id:
            entries = [item for item in entries if item["case_id"] == args.case_id]
            if len(entries) != 1:
                raise ConformanceError("CONFORMANCE-CASE-UNKNOWN", "case-id")
            output_root = resolve_directory(root, args.output_dir, create=True)
            case = _load(root / SUITE_ROOT / entries[0]["path"])
            atomic_write(
                output_root,
                _result_name(case["case_id"]),
                canonicalize(build_result(root, manifest, case)),
            )
        else:
            _write_all_transactionally(root, args.output_dir, manifest, entries)
    except (OSError, ValueError, KeyError, TypeError, ConformanceError):
        print("reference-verifier: error [bounded]", file=sys.stderr)
        return 1
    print(f"reference-verifier: complete cases={len(entries)} output={args.output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
