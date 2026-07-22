#!/usr/bin/env python3
"""Shared, deterministic primitives for the draft conformance suite.

The module deliberately contains no transport, network, subprocess, or
cryptographic implementation.  It composes the already reviewed message and
state-machine helpers and supplies only conformance artifact plumbing.
"""

from __future__ import annotations

import copy
import hashlib
import os
import stat
from dataclasses import asdict, is_dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from canonicalize_message import canonicalize, strict_loads


SUITE_ID = "private-match-core"
SUITE_VERSION = "0.1"
ARTIFACT_STATUS = "draft"
SUITE_ROOT = Path("conformance/suites/private-match-core-v0.1")
CASE_DOMAIN = b"private-match-conformance-case/v0.1\x00"
SUITE_DOMAIN = b"private-match-conformance-suite/v0.1\x00"
INPUT_DOMAIN = b"private-match-conformance-input/v0.1\x00"
STATE_DOMAIN = b"private-match-conformance-state/v0.1\x00"
RESULT_DOMAIN = b"private-match-conformance-result/v0.1\x00"
IMPLEMENTATION_DOMAIN = b"private-match-reference-verifier-implementation/v0.1\x00"
FILE_SIZE_LIMIT = 2 * 1024 * 1024
REFERENCE_IMPLEMENTATION_FILES = [
    "scripts/canonicalize_message.py",
    "scripts/validate_messages.py",
    "scripts/conformance_common.py",
    "scripts/conformance_engine.py",
    "scripts/generate_conformance_suite.py",
    "scripts/run_conformance.py",
    "scripts/strict_yaml.py",
    "scripts/validate_conformance_suite.py",
    "schema/conformance-adapter-result.v0.1.schema.json",
    "schema/conformance-case.v0.1.schema.json",
    "schema/conformance-expected-result.v0.1.schema.json",
    "schema/conformance-run-result.v0.1.schema.json",
    "schema/conformance-suite-manifest.v0.1.schema.json",
    "schemas/messages/envelope.v0.1.schema.json",
    "schemas/messages/timer-event.v0.1.schema.json",
    "requirements-dev.txt",
]

RUNNER_STATUSES = {
    "pass",
    "fail",
    "skip",
    "unsupported",
    "timeout",
    "tool-error",
}
PROTOCOL_OUTCOMES = {
    "accepted",
    "rejected",
    "no-op",
    "terminal",
    "not-evaluated",
}


class ConformanceError(ValueError):
    """A bounded, value-free conformance artifact error."""

    def __init__(self, code: str, path: str = "artifact") -> None:
        super().__init__(f"{code}: {path}")
        self.code = code
        self.path = path


def sha256_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def domain_digest(domain: bytes, value: Any) -> str:
    return sha256_bytes(domain + canonicalize(value))


def case_digest(case: dict[str, Any]) -> str:
    material = copy.deepcopy(case)
    material.pop("case_digest", None)
    return domain_digest(CASE_DOMAIN, material)


def input_digest(case: dict[str, Any]) -> str:
    return domain_digest(
        INPUT_DOMAIN,
        {
            "initial_state_fixture": case["initial_state_fixture"],
            "ordered_inputs": case["ordered_inputs"],
            "authentication_precondition": case["authentication_precondition"],
        },
    )


def suite_digest(manifest: dict[str, Any]) -> str:
    material = copy.deepcopy(manifest)
    material.pop("suite_digest", None)
    return domain_digest(SUITE_DOMAIN, material)


def result_digest(result: dict[str, Any]) -> str:
    material = copy.deepcopy(result)
    material.pop("result_digest", None)
    return domain_digest(RESULT_DOMAIN, material)


def state_digest(runner: Any, transcript: Any) -> str:
    runner_state = copy.deepcopy(runner.__dict__)
    material = {
        "runner": _jsonable(runner_state),
        "transcript": {
            "accepted_event_index": transcript.accepted_event_index,
            "head": transcript.head,
        },
    }
    return domain_digest(STATE_DOMAIN, material)


def _jsonable(value: Any) -> Any:
    if is_dataclass(value):
        return _jsonable(asdict(value))
    if isinstance(value, dict):
        return {
            str(key): _jsonable(item)
            for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
        }
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    if isinstance(value, set):
        return sorted(_jsonable(item) for item in value)
    return value


def strict_json_bytes(raw: bytes, *, path: str, require_canonical: bool = True) -> Any:
    if len(raw) > FILE_SIZE_LIMIT:
        raise ConformanceError("CONFORMANCE-FILE-SIZE", path)
    try:
        value = strict_loads(raw)
    except (UnicodeDecodeError, ValueError) as error:
        raise ConformanceError("CONFORMANCE-JSON-PARSE", path) from error
    if require_canonical:
        try:
            expected = canonicalize(value)
        except (TypeError, ValueError) as error:
            raise ConformanceError("CONFORMANCE-CANONICALIZATION", path) from error
        if raw != expected:
            raise ConformanceError("CONFORMANCE-NONCANONICAL-JSON", path)
    return value


def strict_json_file(path: Path, *, root: Path, require_canonical: bool = True) -> Any:
    safe = resolve_regular_file(root, path.relative_to(root).as_posix())
    return strict_json_bytes(
        safe.read_bytes(),
        path=safe.relative_to(root).as_posix(),
        require_canonical=require_canonical,
    )


def validate_relative_path(value: str) -> PurePosixPath:
    if not value or "\\" in value or value.startswith("/"):
        raise ConformanceError("CONFORMANCE-PATH", "path")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ConformanceError("CONFORMANCE-PATH", "path")
    if len(path.parts) > 32:
        raise ConformanceError("CONFORMANCE-PATH", "path")
    return path


def resolve_regular_file(root: Path, relative: str) -> Path:
    logical = validate_relative_path(relative)
    root = root.resolve()
    current = root
    for part in logical.parts:
        current = current / part
        try:
            info = current.lstat()
        except OSError as error:
            raise ConformanceError("CONFORMANCE-FILE-MISSING", relative) from error
        if stat.S_ISLNK(info.st_mode):
            raise ConformanceError("CONFORMANCE-SYMLINK", relative)
    try:
        current.relative_to(root)
    except ValueError as error:
        raise ConformanceError("CONFORMANCE-PATH-ESCAPE", relative) from error
    if not stat.S_ISREG(current.stat().st_mode):
        raise ConformanceError("CONFORMANCE-NONREGULAR", relative)
    return current


def resolve_directory(root: Path, relative: str, *, create: bool = False) -> Path:
    logical = validate_relative_path(relative)
    root = root.resolve()
    current = root
    for part in logical.parts:
        current = current / part
        if not current.exists():
            if not create:
                raise ConformanceError("CONFORMANCE-DIRECTORY-MISSING", relative)
            current.mkdir(mode=0o700)
        info = current.lstat()
        if stat.S_ISLNK(info.st_mode):
            raise ConformanceError("CONFORMANCE-SYMLINK", relative)
        if not stat.S_ISDIR(info.st_mode):
            raise ConformanceError("CONFORMANCE-NONDIRECTORY", relative)
    try:
        current.resolve().relative_to(root)
    except ValueError as error:
        raise ConformanceError("CONFORMANCE-PATH-ESCAPE", relative) from error
    return current.resolve()


def atomic_write(root: Path, relative: str, data: bytes) -> Path:
    logical = validate_relative_path(relative)
    root = root.resolve()
    target = root.joinpath(*logical.parts)
    target.parent.mkdir(parents=True, exist_ok=True)
    try:
        target.parent.resolve().relative_to(root)
    except ValueError as error:
        raise ConformanceError("CONFORMANCE-OUTPUT-PATH", relative) from error
    if target.exists() and target.is_symlink():
        raise ConformanceError("CONFORMANCE-OUTPUT-SYMLINK", relative)
    temporary = target.with_name(f".{target.name}.partial")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    try:
        descriptor = os.open(temporary, flags, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, target)
    except Exception:
        if temporary.exists() and not temporary.is_symlink():
            temporary.unlink()
        raise
    return target


def canonical_file_tree_digest(root: Path, paths: list[str]) -> str:
    entries = []
    for relative in sorted(paths):
        path = resolve_regular_file(root, relative)
        entries.append({"path": relative, "digest": sha256_bytes(path.read_bytes())})
    return domain_digest(IMPLEMENTATION_DOMAIN, entries)


def reference_implementation_digest(root: Path) -> str:
    return canonical_file_tree_digest(root, REFERENCE_IMPLEMENTATION_FILES)


def bounded_error(error: BaseException) -> str:
    if isinstance(error, ConformanceError):
        return f"{error.code} [{error.path[:160]}]"
    return "CONFORMANCE-TOOL-ERROR [bounded]"
