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
from collections.abc import Iterable, Mapping
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
STATE_PROJECTION_DOMAIN = b"private-match-conformance-state-projection/v0.1\x00"
STATE_PROJECTION_PROFILE_DOMAIN = (
    b"private-match-conformance-state-projection-profile/v0.1\x00"
)
RESULT_DOMAIN = b"private-match-conformance-result/v0.1\x00"
IMPLEMENTATION_DOMAIN = b"private-match-reference-verifier-implementation/v0.1\x00"
RUN_SET_DOMAIN = b"private-match-conformance-run-set/v0.1\x00"
EXPECTED_RESULT_DOMAIN = b"private-match-conformance-expected-result/v0.1\x00"
SUITE_TREE_DOMAIN = b"private-match-conformance-suite-tree/v0.1\x00"
MESSAGE_INPUT_MANIFEST = Path("conformance/source/message-conformance-inputs.v0.1.json")
STATE_PROJECTION_PROFILE = Path("conformance/source/state-projection-profile.v0.1.json")
REFERENCE_IMPLEMENTATION_MANIFEST = Path(
    "conformance/source/reference-verifier-implementation.v0.1.json"
)
SUITE_TREE_MANIFEST = SUITE_ROOT / "suite-tree-manifest.v0.1.json"
FILE_SIZE_LIMIT = 2 * 1024 * 1024
REFERENCE_IMPLEMENTATION_FILES = {
    "scripts/canonicalize_message.py": "python-source",
    "scripts/compare_adapter_result.py": "python-source",
    "scripts/conformance_common.py": "python-source",
    "scripts/conformance_engine.py": "python-source",
    "scripts/generate_conformance_suite.py": "python-source",
    "scripts/generate_message_vectors.py": "python-source",
    "scripts/generate_verifier_manifest.py": "python-source",
    "scripts/run_conformance.py": "python-source",
    "scripts/strict_yaml.py": "python-source",
    "scripts/validate_conformance_suite.py": "python-source",
    "scripts/validate_messages.py": "python-source",
    "scripts/validate_session_state_machine.py": "python-source",
    "schema/conformance-adapter-result.v0.1.schema.json": "runtime-schema",
    "schema/conformance-case.v0.1.schema.json": "runtime-schema",
    "schema/conformance-case-definitions.v0.1.schema.json": "runtime-schema",
    "schema/conformance-expected-result.v0.1.schema.json": "runtime-schema",
    "schema/conformance-message-input-manifest.v0.1.schema.json": "runtime-schema",
    "schema/conformance-normative-expected-results.v0.1.schema.json": "runtime-schema",
    "schema/conformance-run-result.v0.1.schema.json": "runtime-schema",
    "schema/conformance-run-set-manifest.v0.1.schema.json": "runtime-schema",
    "schema/conformance-state-projection-profile.v0.1.schema.json": "runtime-schema",
    "schema/conformance-state-projection.v0.1.schema.json": "runtime-schema",
    "schema/conformance-suite-manifest.v0.1.schema.json": "runtime-schema",
    "schema/conformance-suite-tree-manifest.v0.1.schema.json": "runtime-schema",
    "schema/conformance-verifier-implementation.v0.1.schema.json": "runtime-schema",
    "schema/session-state-machine.schema.json": "runtime-schema",
    "schemas/messages/envelope.v0.1.schema.json": "runtime-schema",
    "schemas/messages/timer-event.v0.1.schema.json": "runtime-schema",
    "schemas/registry/authenticated-requesters.v0.1.schema.json": "runtime-schema",
    "schemas/registry/message-types.v0.1.schema.json": "runtime-schema",
    "schemas/registry/verification-materials.v0.1.schema.json": "runtime-schema",
    "conformance/interop/adapters.v0.1.yaml": "runtime-policy",
    STATE_PROJECTION_PROFILE.as_posix(): "runtime-profile",
    "requirements-build.txt": "dependency-lock",
    "requirements-dev.txt": "dependency-lock",
}
REFERENCE_PROTOCOL_ARTIFACTS = {
    "state-machine": "specs/state-machines/private-match-core-session-v0.1.yaml",
    "message-registry": "registry/message-types.v0.1.yaml",
    "message-conformance-input-tree": MESSAGE_INPUT_MANIFEST.as_posix(),
}
REFERENCE_PROTOCOL_DIGESTS = {
    "state-machine": "sha256:42e63b8a1f413e932e46370aae5fa0d972f3ab71d93efe08557472b4c7066fe8",
    "message-registry": "sha256:2ff1685ca4325a0ff3bd49c7a411cd7f0857add6215c2f285097bdf40dcbc2b6",
    "message-conformance-input-tree": "sha256:19d2218c11c6ac7ba1d2f0884ba9e3c79cbd1264bd3ef682e543bcb9a63ccf0f",
}

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


def run_set_digest(manifest: dict[str, Any]) -> str:
    material = copy.deepcopy(manifest)
    material.pop("run_set_digest", None)
    return domain_digest(RUN_SET_DOMAIN, material)


def expected_result_digest(record: dict[str, Any]) -> str:
    material = copy.deepcopy(record)
    material.pop("expected_result_digest", None)
    return domain_digest(EXPECTED_RESULT_DOMAIN, material)


def state_projection_profile_digest(profile: dict[str, Any]) -> str:
    material = copy.deepcopy(profile)
    material.pop("profile_digest", None)
    return domain_digest(STATE_PROJECTION_PROFILE_DOMAIN, material)


def implementation_manifest_digest(manifest: dict[str, Any]) -> str:
    material = copy.deepcopy(manifest)
    material.pop("implementation_digest", None)
    return domain_digest(IMPLEMENTATION_DOMAIN, material)


def suite_tree_digest(entries: list[dict[str, Any]]) -> str:
    return domain_digest(SUITE_TREE_DOMAIN, entries)


def _logical_get(value: Any, name: str, default: Any = None) -> Any:
    if isinstance(value, Mapping):
        return value.get(name, default)
    return getattr(value, name, default)


def _slot(value: Any, *names: str) -> Any:
    for name in names:
        candidate = _logical_get(value, name)
        if candidate is not None:
            return candidate
    return None


def _closed_record(value: Any, fields: tuple[str, ...]) -> dict[str, Any] | None:
    if value is None:
        return None
    return {field: copy.deepcopy(_logical_get(value, field)) for field in fields}


def _party_slots(value: Any, fields: tuple[str, ...] | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for public, alternatives in (
        ("party_a", ("a", "party_a")),
        ("party_b", ("b", "party_b")),
    ):
        item = _slot(value, *alternatives)
        result[public] = (
            _closed_record(item, fields) if fields is not None else copy.deepcopy(item)
        )
    return result


def _canonical_sorted(values: Iterable[Any]) -> list[Any]:
    unique: dict[bytes, Any] = {}
    for value in values:
        copied = copy.deepcopy(value)
        unique[canonicalize(copied)] = copied
    return [unique[key] for key in sorted(unique)]


def _subject_projection(value: Any) -> dict[str, Any] | None:
    return _closed_record(
        value,
        (
            "actor",
            "participant_id",
            "key_id",
            "subject_binding_id",
            "verification_material_id",
            "profile_id",
            "profile_version",
            "profile_instance_id",
        ),
    )


def _replay_records(index: Any, fields: tuple[str, ...]) -> list[dict[str, Any]]:
    if isinstance(index, Mapping):
        candidates = index.values()
    elif isinstance(index, list):
        candidates = index
    else:
        candidates = []
    projected = []
    for record in candidates:
        item = {field: copy.deepcopy(_logical_get(record, field)) for field in fields}
        item["original_authenticated_subject"] = _subject_projection(
            _logical_get(record, "original_authenticated_subject")
        )
        item["response_recipient_binding"] = _subject_projection(
            _logical_get(record, "response_recipient_binding")
        )
        projected.append(item)
    return _canonical_sorted(projected)


def conformance_state_projection(
    runner: Any, replay_state: Any = None
) -> dict[str, Any]:
    """Project only reviewed logical state into a versioned interoperable value.

    Python object layout, arbitrary attributes, audit helper state, normalized
    response references, transcript head/index, and raw authentication values
    are intentionally not observed.  A mapping or an alternate object with the
    same logical fields therefore produces the same RFC 8785 bytes.
    """

    base = _logical_get(runner, "base_context", {}) or {}
    session = _logical_get(base, "session_context", {}) or {}
    policy = _logical_get(session, "policy", {}) or {}
    replay = replay_state or {}
    party_common = (
        "session_id",
        "sender_participant_id",
        "message_id",
        "nonce",
        "sequence",
        "issued_at",
        "canonical_message_digest",
        "canonical_wire_digest",
        "verification_material_id",
    )
    operation_common = (
        "actor_id",
        "operation_id",
        "idempotency_key",
        "canonical_message_digest",
        "canonical_wire_digest",
        "verification_material_id",
    )
    callback_common = (
        "profile_id",
        "profile_version",
        "profile_instance_id",
        "session_id",
        "evaluation_attempt_id",
        "callback_id",
        "idempotency_key",
        "canonical_message_digest",
        "canonical_wire_digest",
        "verification_material_id",
    )
    acceptance_fields = (
        "proposal_digest",
        "acceptance_digest",
        "participant_id",
        "key_id",
        "subject_binding_id",
        "verification_material_id",
    )
    policy_acceptance_fields = ("policy_id", "policy_version", "acceptance_digest")
    participant_fields = ("participant_id", "key_id")
    receipt_fields = (
        "opaque_receipt_ref",
        "acknowledgment_status",
        "profile_evidence_ref",
    )
    consent_fields = (
        "opaque_receipt_ref",
        "disclosure_profile_id",
        "disclosure_profile_version",
        "scope",
        "audience",
        "issued_at",
        "expires_at",
        "consent_nonce",
        "consent_artifact_digest",
        "status",
    )
    approved_profiles = _logical_get(base, "approved_disclosure_profiles", []) or []
    intended_audience = _logical_get(session, "intended_audience", []) or []
    return {
        "schema_version": "0.1",
        "protocol": {"profile": SUITE_ID, "version": SUITE_VERSION},
        "lifecycle_phase": _logical_get(runner, "phase"),
        "session": {
            "session_id": _logical_get(session, "session_id"),
            "proposal_digest": _logical_get(runner, "proposal_digest"),
            "expires_at": _logical_get(runner, "session_expires_at"),
            "intended_audience": sorted(set(intended_audience)),
            "acceptance": _party_slots(
                _logical_get(runner, "session_acceptance", {}), acceptance_fields
            ),
        },
        "participants": _party_slots(
            _logical_get(runner, "participants", {}), participant_fields
        ),
        "policy": {
            "policy_id": _logical_get(policy, "policy_id"),
            "policy_version": _logical_get(policy, "policy_version"),
            "acceptance": _party_slots(
                _logical_get(runner, "policy_acceptance", {}),
                policy_acceptance_fields,
            ),
        },
        "commitments": {
            **_party_slots(_logical_get(runner, "commitments", {})),
            "commitment_pair_id": _logical_get(runner, "commitment_pair_id"),
        },
        "evaluation": {
            "started": bool(_logical_get(runner, "evaluation_started", False)),
            "attempt_id": _logical_get(runner, "evaluation_attempt_id"),
            "deadline": _logical_get(runner, "evaluation_deadline"),
            "integration_profile": _closed_record(
                _logical_get(runner, "selected_integration_profile"),
                ("profile_id", "profile_version", "profile_instance_id"),
            ),
            "contributions": _party_slots(_logical_get(runner, "contributions", {})),
            "local_results": {
                "pending": _party_slots(
                    _logical_get(runner, "proposed_result_state", {})
                ),
                "accepted": _party_slots(
                    _logical_get(runner, "accepted_result_state", {})
                ),
            },
            "receipt_acknowledgments": _party_slots(
                _logical_get(runner, "receipt_acks", {}), receipt_fields
            ),
            "accepted_receipt": _closed_record(
                _logical_get(runner, "accepted_receipt"), receipt_fields
            ),
        },
        "query_budget": {
            "reserved": bool(_logical_get(runner, "budget_reserved", False)),
            "state": _logical_get(runner, "query_budget_state"),
        },
        "consent": _party_slots(_logical_get(runner, "consents", {}), consent_fields),
        "disclosure": {
            "authorization_state": _logical_get(runner, "disclosure_state"),
            "reviewed_profiles": _canonical_sorted(approved_profiles),
        },
        "clock": {
            "authoritative_time": _logical_get(runner, "authoritative_time"),
            "maximum_time_jump_seconds": _logical_get(
                runner, "maximum_time_jump_seconds"
            ),
            "allowed_clock_skew_seconds": _logical_get(
                base, "allowed_clock_skew_seconds"
            ),
            "message_stale_threshold_seconds": _logical_get(
                base, "message_stale_threshold_seconds"
            ),
        },
        "terminal": {
            "internal_failure_code": _logical_get(runner, "terminal_failure_code"),
            "party_category": _logical_get(runner, "party_terminal_category"),
        },
        "next_sequence": {
            key: value
            for key, value in _party_slots(
                _logical_get(runner, "next_sequence", {})
            ).items()
        },
        "replay": {
            "party_messages": _replay_records(
                _logical_get(replay, "party_by_id", []), party_common
            ),
            "coordinator_operations": _replay_records(
                _logical_get(replay, "operation_by_id", []), operation_common
            ),
            "profile_callbacks": _replay_records(
                _logical_get(replay, "callback_by_id", []), callback_common
            ),
        },
    }


def state_digest(runner: Any, transcript: Any) -> str:
    """Digest the interoperable state projection, excluding transcript state."""

    return domain_digest(
        STATE_PROJECTION_DOMAIN,
        conformance_state_projection(runner, _logical_get(transcript, "dedup", {})),
    )


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
    if (
        not value
        or "\\" in value
        or value.startswith("/")
        or (len(value) >= 2 and value[0].isalpha() and value[1] == ":")
    ):
        raise ConformanceError("CONFORMANCE-PATH", "path")
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or path.as_posix() != value
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
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


def _local_import_paths(root: Path, paths: set[str]) -> set[str]:
    """Return repository-local Python imports used by the reviewed sources."""

    import ast

    module_paths = {
        path.stem: path.relative_to(root).as_posix()
        for path in (root / "scripts").glob("*.py")
    }
    imports: set[str] = set()
    for relative in sorted(path for path in paths if path.endswith(".py")):
        tree = ast.parse(
            resolve_regular_file(root, relative).read_text(encoding="utf-8")
        )
        for node in ast.walk(tree):
            names: list[str] = []
            if isinstance(node, ast.Import):
                names = [alias.name.split(".")[0] for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                names = [node.module.split(".")[0]]
            for name in names:
                if name in module_paths:
                    imports.add(module_paths[name])
    return imports


def validate_reference_implementation_manifest(
    root: Path,
    manifest: dict[str, Any],
    *,
    protocol_pins: dict[str, str] | None = None,
) -> None:
    """Validate the closed source/runtime dependency and Protocol pin boundary."""

    required = {
        "$schema",
        "schema_version",
        "artifact_status",
        "verifier",
        "canonicalization_runtime",
        "tested_runtime_target",
        "files",
        "protocol_artifacts",
        "implementation_digest",
        "limitations",
        "license",
    }
    if set(manifest) != required:
        raise ConformanceError("CONFORMANCE-IMPLEMENTATION-SHAPE", "manifest")
    files = manifest.get("files")
    if not isinstance(files, list):
        raise ConformanceError("CONFORMANCE-IMPLEMENTATION-SHAPE", "files")
    paths: list[str] = []
    for entry in files:
        if not isinstance(entry, dict) or set(entry) != {"path", "digest", "role"}:
            raise ConformanceError("CONFORMANCE-IMPLEMENTATION-SHAPE", "files")
        relative = str(entry.get("path", ""))
        validate_relative_path(relative)
        paths.append(relative)
        if REFERENCE_IMPLEMENTATION_FILES.get(relative) != entry.get("role"):
            raise ConformanceError("CONFORMANCE-IMPLEMENTATION-PATH-SET", relative)
        raw = resolve_regular_file(root, relative).read_bytes()
        if entry.get("digest") != sha256_bytes(raw):
            raise ConformanceError("CONFORMANCE-IMPLEMENTATION-FILE-DIGEST", relative)
    if len(paths) != len(set(paths)):
        raise ConformanceError("CONFORMANCE-IMPLEMENTATION-DUPLICATE-PATH", "files")
    if set(paths) != set(REFERENCE_IMPLEMENTATION_FILES):
        raise ConformanceError("CONFORMANCE-IMPLEMENTATION-PATH-SET", "files")
    if not _local_import_paths(root, set(paths)).issubset(set(paths)):
        raise ConformanceError("CONFORMANCE-IMPLEMENTATION-IMPORT-CLOSURE", "files")
    artifacts = manifest.get("protocol_artifacts")
    if not isinstance(artifacts, list):
        raise ConformanceError("CONFORMANCE-IMPLEMENTATION-SHAPE", "protocol")
    artifact_ids = []
    for item in artifacts:
        if not isinstance(item, dict) or set(item) != {"id", "path", "digest"}:
            raise ConformanceError("CONFORMANCE-IMPLEMENTATION-SHAPE", "protocol")
        identifier = str(item.get("id", ""))
        path = str(item.get("path", ""))
        artifact_ids.append(identifier)
        if REFERENCE_PROTOCOL_ARTIFACTS.get(identifier) != path:
            raise ConformanceError("CONFORMANCE-IMPLEMENTATION-PROTOCOL", identifier)
        resolve_regular_file(root, path)
    if len(artifact_ids) != len(set(artifact_ids)) or set(artifact_ids) != set(
        REFERENCE_PROTOCOL_ARTIFACTS
    ):
        raise ConformanceError("CONFORMANCE-IMPLEMENTATION-PROTOCOL", "artifacts")
    if {item["id"]: item["digest"] for item in artifacts} != REFERENCE_PROTOCOL_DIGESTS:
        raise ConformanceError("CONFORMANCE-IMPLEMENTATION-PROTOCOL", "digests")
    if protocol_pins is not None:
        expected = {
            "state-machine": protocol_pins["state_machine_digest"],
            "message-registry": protocol_pins["message_registry_digest"],
            "message-conformance-input-tree": protocol_pins[
                "message_conformance_tree_digest"
            ],
        }
        if expected != REFERENCE_PROTOCOL_DIGESTS:
            raise ConformanceError("CONFORMANCE-IMPLEMENTATION-PROTOCOL", "digests")
    if manifest.get("implementation_digest") != implementation_manifest_digest(
        manifest
    ):
        raise ConformanceError("CONFORMANCE-IMPLEMENTATION-DIGEST", "manifest")


def reference_implementation_manifest(root: Path) -> dict[str, Any]:
    path = resolve_regular_file(root, REFERENCE_IMPLEMENTATION_MANIFEST.as_posix())
    value = strict_json_bytes(
        path.read_bytes(),
        path=REFERENCE_IMPLEMENTATION_MANIFEST.as_posix(),
        require_canonical=True,
    )
    if not isinstance(value, dict):
        raise ConformanceError("CONFORMANCE-IMPLEMENTATION-SHAPE", "manifest")
    return value


def reference_implementation_digest(root: Path) -> str:
    manifest = reference_implementation_manifest(root)
    validate_reference_implementation_manifest(root, manifest)
    return str(manifest["implementation_digest"])


def validate_generated_suite_tree(
    root: Path,
    generated: Mapping[Path, bytes],
    *,
    compare_bytes: bool = True,
) -> None:
    """Require the generated suite directory to equal the reviewed path set.

    This check deliberately covers directories as well as regular files so an
    unlisted nested directory, a symlink at any level, an old case, or a stale
    fixture cannot survive a successful generator ``--check`` or repository
    validation.
    """

    suite = root / SUITE_ROOT
    if not suite.exists() or suite.is_symlink() or not suite.is_dir():
        raise ConformanceError("CONFORMANCE-SUITE-TREE", SUITE_ROOT.as_posix())
    expected_files = {
        path.relative_to(SUITE_ROOT).as_posix(): content
        for path, content in generated.items()
        if path.is_relative_to(SUITE_ROOT)
    }
    if len(expected_files) != len(generated):
        raise ConformanceError("CONFORMANCE-SUITE-TREE", "generated-path-set")
    expected_directories = {"."}
    for relative in expected_files:
        logical = validate_relative_path(relative)
        parent = logical.parent
        while parent.as_posix() != ".":
            expected_directories.add(parent.as_posix())
            parent = parent.parent

    actual_files: set[str] = set()
    actual_directories = {"."}
    for path in suite.rglob("*"):
        relative = path.relative_to(suite).as_posix()
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode):
            raise ConformanceError("CONFORMANCE-SUITE-TREE-SYMLINK", relative)
        if stat.S_ISDIR(info.st_mode):
            actual_directories.add(relative)
        elif stat.S_ISREG(info.st_mode):
            actual_files.add(relative)
        else:
            raise ConformanceError("CONFORMANCE-SUITE-TREE-NONREGULAR", relative)
    if (
        actual_files != set(expected_files)
        or actual_directories != expected_directories
    ):
        raise ConformanceError("CONFORMANCE-SUITE-TREE-PATH-SET", "suite")
    if compare_bytes:
        for relative, expected in expected_files.items():
            if resolve_regular_file(suite, relative).read_bytes() != expected:
                raise ConformanceError("CONFORMANCE-GENERATED-STALE", relative)


def legacy_length_prefixed_tree_digest(root: Path, paths: list[str]) -> str:
    """Recompute the reviewed pre-Issue-6 message-conformance tree.

    Issue #5 used a length-prefixed relative-path/byte stream.  Keeping that
    exact calculation preserves the reviewed pin while making every input and
    byte recomputable rather than trusting a constant.
    """

    hasher = hashlib.sha256()
    for relative in sorted(paths):
        data = resolve_regular_file(root, relative).read_bytes()
        encoded = relative.encode("utf-8", errors="strict")
        hasher.update(len(encoded).to_bytes(8, "big"))
        hasher.update(encoded)
        hasher.update(len(data).to_bytes(8, "big"))
        hasher.update(data)
    return "sha256:" + hasher.hexdigest()


def message_conformance_paths(root: Path) -> list[str]:
    base = root / "conformance/messages"
    paths: list[str] = []
    for path in base.rglob("*"):
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            raise ConformanceError("CONFORMANCE-SOURCE-SYMLINK", relative)
        if path.is_file():
            paths.append(relative)
    return sorted(paths)


def validate_message_input_manifest(root: Path, manifest: dict[str, Any]) -> None:
    """Fail closed unless the closed manifest matches the complete input tree."""

    required = {
        "$schema",
        "schema_version",
        "artifact_status",
        "tree_digest",
        "calculation",
        "entries",
        "review_source",
        "limitations",
        "license",
    }
    if set(manifest) != required:
        raise ConformanceError(
            "CONFORMANCE-SOURCE-MANIFEST-SHAPE", str(MESSAGE_INPUT_MANIFEST)
        )
    entries = manifest.get("entries")
    if not isinstance(entries, list):
        raise ConformanceError("CONFORMANCE-SOURCE-MANIFEST-SHAPE", "entries")
    paths: list[str] = []
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {
            "path",
            "digest",
            "role",
            "artifact_status",
        }:
            raise ConformanceError("CONFORMANCE-SOURCE-MANIFEST-SHAPE", "entries")
        relative = str(entry.get("path", ""))
        validate_relative_path(relative)
        paths.append(relative)
        data = resolve_regular_file(root, relative).read_bytes()
        if entry.get("digest") != sha256_bytes(data):
            raise ConformanceError("CONFORMANCE-SOURCE-FILE-DIGEST", relative)
    if len(paths) != len(set(paths)):
        raise ConformanceError("CONFORMANCE-SOURCE-DUPLICATE-PATH", "entries")
    actual_paths = message_conformance_paths(root)
    if sorted(paths) != actual_paths:
        raise ConformanceError("CONFORMANCE-SOURCE-PATH-SET", "entries")
    digest = legacy_length_prefixed_tree_digest(root, paths)
    if manifest.get("tree_digest") != digest:
        raise ConformanceError("CONFORMANCE-SOURCE-TREE-DIGEST", "tree_digest")


def bounded_error(error: BaseException) -> str:
    if isinstance(error, ConformanceError):
        return f"{error.code} [{error.path[:160]}]"
    return "CONFORMANCE-TOOL-ERROR [bounded]"
