#!/usr/bin/env python3
"""Reference execution engine composed from existing Protocol validators."""

from __future__ import annotations

import copy
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from conformance_common import (
    ConformanceError,
    resolve_regular_file,
    sha256_bytes,
    state_digest,
    strict_json_bytes,
)
from strict_yaml import strict_yaml_load
from validate_messages import (
    AbstractStateRunner,
    TranscriptState,
    apply_profile_local_result_fixture,
    apply_trace_message_atomically,
    apply_trace_timer_atomically,
    validate_message_bytes,
)


MESSAGE_SCHEMA = Path("schemas/messages/envelope.v0.1.schema.json")
TIMER_SCHEMA = Path("schemas/messages/timer-event.v0.1.schema.json")
REGISTRY = Path("registry/message-types.v0.1.yaml")

FINDING_TO_ERROR = {
    "json-parse": "CONFORMANCE-INPUT-JSON",
    "noncanonical-json": "CONFORMANCE-NONCANONICAL-JSON",
    "schema": "CONFORMANCE-MESSAGE-SCHEMA",
    "message-schema": "CONFORMANCE-MESSAGE-SCHEMA",
    "unknown-message-type": "PROTOCOL_VERSION_MISMATCH",
    "protocol-version": "PROTOCOL_VERSION_MISMATCH",
    "message-version": "PROTOCOL_VERSION_MISMATCH",
    "context-binding": "PARTICIPANT_MISMATCH",
    "audience-binding": "AUDIENCE_MISMATCH",
    "key-binding": "PARTICIPANT_MISMATCH",
    "authentication-subject": "VERIFICATION_MATERIAL_MISSING",
    "verification-material": "VERIFICATION_MATERIAL_MISSING",
    "message-expired": "STALE_MESSAGE",
    "stale-message": "STALE_MESSAGE",
    "future-message": "STALE_MESSAGE",
    "payload-digest": "COMMITMENT_MUTATION",
    "message-digest": "COMMITMENT_MUTATION",
    "prior-transcript": "REPLAY_CONFLICT",
    "callback-binding": "RESULT_CONFLICT",
    "prohibited-data": "DISCLOSURE_PROFILE_REQUIRED",
    "plaintext-outcome": "DISCLOSURE_PROFILE_REQUIRED",
    "failure-projection": "DISCLOSURE_PROFILE_REQUIRED",
    "canonicalization": "CONFORMANCE-CANONICALIZATION",
    "state-trace": "UNKNOWN_STATE",
    "timer-state": "CLOCK_DOMAIN_INVALID",
    "timer-schema": "CONFORMANCE-CASE-SCHEMA",
    "local-result-symmetry": "RESULT_CONFLICT",
    "profile-local-result-binding": "RESULT_CONFLICT",
    "profile-local-result-fixture": "RESULT_CONFLICT",
    "profile-local-result-state": "UNKNOWN_STATE",
    "low-entropy-receipt": "DISCLOSURE_PROFILE_REQUIRED",
}


@dataclass
class ExecutionActual:
    """Deterministic in-memory result before normative-oracle comparison."""

    status: str
    protocol_outcome: str
    error_codes: list[str]
    initial_state_digest: str
    final_state_digest: str
    initial_transcript_head: str
    final_transcript_head: str
    accepted_event_count: int
    mutation_summary: dict[str, bool]
    terminal_phase: str | None
    limitations: list[str]
    cached_response_authorized: bool | None
    local_result_state: dict[str, str | None]
    work_units: int


def _load_json(root: Path, relative: Path) -> dict[str, Any]:
    raw = resolve_regular_file(root, relative.as_posix()).read_bytes()
    value = strict_json_bytes(raw, path=relative.as_posix(), require_canonical=False)
    if not isinstance(value, dict):
        raise ConformanceError("CONFORMANCE-ARTIFACT-TYPE", relative.as_posix())
    return value


def _load_yaml(root: Path, relative: Path) -> dict[str, Any]:
    raw = resolve_regular_file(root, relative.as_posix()).read_text(encoding="utf-8")
    try:
        value = strict_yaml_load(raw)
    except yaml.YAMLError as error:
        raise ConformanceError("CONFORMANCE-YAML-PARSE", relative.as_posix()) from error
    if not isinstance(value, dict):
        raise ConformanceError("CONFORMANCE-ARTIFACT-TYPE", relative.as_posix())
    return value


def _finding_codes(findings: list[Any]) -> list[str]:
    values: set[str] = set()
    for finding in findings:
        finding_code = str(finding.code)
        detail = (str(finding.path) + " " + str(finding.message)).lower()
        code = FINDING_TO_ERROR.get(finding_code, "CONFORMANCE-PROTOCOL-REJECTION")
        if finding_code == "verification-material" and "expired" in detail:
            code = "VERIFICATION_MATERIAL_EXPIRED"
        elif finding_code == "context-binding":
            if "session_id" in detail:
                code = "SESSION_MISMATCH"
            elif "policy" in detail:
                code = "POLICY_VERSION_MISMATCH"
            elif "commitment_pair_id" in detail:
                code = "COMMITMENT_MUTATION"
            elif "evaluation_attempt_id" in detail:
                code = "UNKNOWN_STATE"
        elif finding_code == "state-trace":
            if "sequence does not equal" in detail:
                code = "OUT_OF_ORDER"
            elif "commitment" in detail:
                code = "COMMITMENT_MUTATION"
            elif "receipt" in detail or "symmetric party-local" in detail:
                code = "RESULT_CONFLICT"
            elif "scope" in detail:
                code = "DISCLOSURE_SCOPE_MISMATCH"
            elif "audience" in detail:
                code = "AUDIENCE_MISMATCH"
            elif "disclosure" in detail or "extension" in detail:
                code = "DISCLOSURE_PROFILE_REQUIRED"
            elif "consent" in detail:
                code = "CONSENT_MISSING"
        values.add(code)
    return sorted(values)


def expected_projection(actual: ExecutionActual) -> dict[str, Any]:
    """Return the complete normative comparison surface."""

    return {
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
        "cached_response_authorized": actual.cached_response_authorized,
    }


def compare_actual_to_expected(
    actual: ExecutionActual, expected: dict[str, Any]
) -> tuple[str, list[str], bool]:
    """Derive run status while preserving every non-pass runner status."""

    expected_match = expected_projection(actual) == expected
    status = actual.status
    errors = set(actual.error_codes)
    if not expected_match:
        errors.add("CONFORMANCE-EXPECTED-MISMATCH")
        if status == "pass":
            status = "fail"
    return status, sorted(errors), expected_match


def _actual(
    runner: AbstractStateRunner,
    transcript: TranscriptState,
    *,
    status: str,
    protocol_outcome: str,
    error_codes: set[str],
    initial_state: str,
    initial_head: str,
    initial_budget: str,
    initial_audit: list[str],
    limitations: list[str],
    cached_response_authorized: bool | None,
    work_units: int,
) -> ExecutionActual:
    final_state = state_digest(runner, transcript)
    return ExecutionActual(
        status=status,
        protocol_outcome=protocol_outcome,
        error_codes=sorted(error_codes),
        initial_state_digest=initial_state,
        final_state_digest=final_state,
        initial_transcript_head=initial_head,
        final_transcript_head=transcript.head,
        accepted_event_count=transcript.accepted_event_index,
        mutation_summary={
            "state": initial_state != final_state,
            "transcript": initial_head != transcript.head,
            "budget": initial_budget != runner.query_budget_state,
            "audit": initial_audit != runner.audit_lifecycle,
        },
        terminal_phase=(
            runner.phase if runner.phase in {"CLOSED", "ABORTED", "EXPIRED"} else None
        ),
        limitations=limitations,
        cached_response_authorized=cached_response_authorized,
        local_result_state=copy.deepcopy(runner.accepted_result_state),
        work_units=work_units,
    )


def _work_units(suite_root: Path, ordered_inputs: list[dict[str, Any]]) -> int:
    units = 0
    for item in ordered_inputs:
        if item.get("kind") == "trace-fixture":
            trace = _load_json(suite_root, Path(str(item.get("path"))))
            entries = trace.get("entries")
            if not isinstance(entries, list):
                raise ConformanceError("CONFORMANCE-TRACE-SHAPE", str(item.get("path")))
            units += len(entries)
        else:
            units += 1
    return units


def _reviewed_skip_applies(root: Path, precondition: dict[str, Any]) -> bool:
    if precondition == {"kind": "always-run"}:
        return False
    reviewed = {
        "kind": "reviewed-skip",
        "condition": "second-adapter-planned-not-implemented",
        "reason_code": "SECOND_ADAPTER_NOT_IMPLEMENTED",
        "scope": "runner-self-test",
    }
    if precondition != reviewed:
        raise ConformanceError(
            "CONFORMANCE-SKIP-PRECONDITION", "execution_precondition"
        )
    registry = _load_yaml(root, Path("conformance/interop/adapters.v0.1.yaml"))
    adapters = registry.get("adapters", [])
    return bool(adapters) and all(
        isinstance(item, dict) and item.get("implementation_status") == "planned"
        for item in adapters
    )


def _verified_fixture(
    suite_root: Path, item: dict[str, Any], path_key: str = "path"
) -> Path:
    relative = str(item[path_key])
    path = resolve_regular_file(suite_root, relative)
    digest_key = (
        "fixture_digest"
        if path_key == "path"
        else path_key.removesuffix("_path") + "_digest"
    )
    if sha256_bytes(path.read_bytes()) != item[digest_key]:
        raise ConformanceError("CONFORMANCE-INPUT-DIGEST", relative)
    return path


def execute_case(root: Path, suite_root: Path, case: dict[str, Any]) -> ExecutionActual:
    """Execute one case without consulting the normative expected result."""

    message_schema = _load_json(root, MESSAGE_SCHEMA)
    timer_schema = _load_json(root, TIMER_SCHEMA)
    registry = _load_yaml(root, REGISTRY)
    context_path = case["initial_state_fixture"]["context_path"]
    context_file = resolve_regular_file(suite_root, context_path)
    if (
        sha256_bytes(context_file.read_bytes())
        != case["initial_state_fixture"]["context_digest"]
    ):
        raise ConformanceError("CONFORMANCE-INPUT-DIGEST", context_path)
    context = _load_json(suite_root, Path(context_path))
    runner = AbstractStateRunner(copy.deepcopy(context))
    transcript = TranscriptState()
    initial_state = state_digest(runner, transcript)
    initial_head = transcript.head
    initial_budget = runner.query_budget_state
    initial_audit = copy.deepcopy(runner.audit_lifecycle)
    limitations = [
        "fixture-preverified authentication does not evaluate cryptographic validity"
    ]

    if _reviewed_skip_applies(root, case["execution_precondition"]):
        return _actual(
            runner,
            transcript,
            status="skip",
            protocol_outcome="not-evaluated",
            error_codes={"CONFORMANCE-REVIEWED-SKIP"},
            initial_state=initial_state,
            initial_head=initial_head,
            initial_budget=initial_budget,
            initial_audit=initial_audit,
            limitations=limitations,
            cached_response_authorized=None,
            work_units=0,
        )

    authentication = case["authentication_precondition"]
    if authentication["mode"] == "unsupported-real-algorithm/v0.1":
        return _actual(
            runner,
            transcript,
            status="unsupported",
            protocol_outcome="not-evaluated",
            error_codes={"CONFORMANCE-ADAPTER-UNSUPPORTED"},
            initial_state=initial_state,
            initial_head=initial_head,
            initial_budget=initial_budget,
            initial_audit=initial_audit,
            limitations=limitations,
            cached_response_authorized=None,
            work_units=0,
        )

    material_path = authentication["material_path"]
    if material_path is None:
        materials = {"materials": []}
    else:
        material_file = resolve_regular_file(suite_root, material_path)
        if (
            sha256_bytes(material_file.read_bytes())
            != authentication["material_digest"]
        ):
            raise ConformanceError("CONFORMANCE-INPUT-DIGEST", material_path)
        materials = _load_json(suite_root, Path(material_path))

    work_units = _work_units(suite_root, case["ordered_inputs"])
    if work_units > case["timeout_policy"]["max_operation_steps"]:
        return _actual(
            runner,
            transcript,
            status="timeout",
            protocol_outcome="not-evaluated",
            error_codes={"CONFORMANCE-TIMEOUT"},
            initial_state=initial_state,
            initial_head=initial_head,
            initial_budget=initial_budget,
            initial_audit=initial_audit,
            limitations=limitations,
            cached_response_authorized=None,
            work_units=work_units,
        )

    error_codes: set[str] = set()
    protocol_outcome = "not-evaluated"
    status = "pass"
    response_authorized: bool | None = None

    for item in case["ordered_inputs"]:
        kind = item["kind"]
        if "path" in item:
            _verified_fixture(suite_root, item)
        if "context_path" in item:
            _verified_fixture(suite_root, item, "context_path")
        if "authenticated_requester_path" in item:
            _verified_fixture(suite_root, item, "authenticated_requester_path")

        if kind == "trace-fixture":
            trace = _load_json(suite_root, Path(item["path"]))
            for entry in trace["entries"]:
                if entry["kind"] == "message":
                    outcome, findings = apply_trace_message_atomically(
                        runner,
                        transcript,
                        entry["message"],
                        message_schema,
                        registry,
                        materials,
                    )
                    if findings:
                        error_codes.update(_finding_codes(findings))
                        protocol_outcome = "rejected"
                        break
                    protocol_outcome = (
                        "no-op"
                        if outcome.classification.startswith("EXACT_DUPLICATE")
                        else "terminal"
                        if runner.phase in {"CLOSED", "ABORTED", "EXPIRED"}
                        else "accepted"
                    )
                elif entry["kind"] == "timer":
                    outcome, transition, findings = apply_trace_timer_atomically(
                        runner, transcript, entry["timer_event"], timer_schema
                    )
                    if findings or outcome not in {"ACCEPTED", "NO_OP"}:
                        error_codes.update(_finding_codes(findings))
                        if not findings:
                            error_codes.add("REPLAY_CONFLICT")
                        protocol_outcome = "rejected"
                        break
                    protocol_outcome = (
                        "terminal"
                        if transition
                        in {
                            "TR-ADVANCE-TIME-EXPIRE",
                            "TR-EVALUATION-TIMEOUT",
                            "TR-CONSENT-EXPIRED",
                        }
                        else "no-op"
                        if outcome == "NO_OP"
                        else "accepted"
                    )
                else:
                    raise ConformanceError("CONFORMANCE-TRACE-KIND", item["path"])
        elif kind in {"message-fixture", "raw-message-fixture"}:
            raw = resolve_regular_file(suite_root, item["path"]).read_bytes()
            if kind == "message-fixture":
                try:
                    message = strict_json_bytes(
                        raw, path=item["path"], require_canonical=True
                    )
                except ConformanceError as error:
                    error_codes.add(error.code)
                    protocol_outcome = "rejected"
                    continue
                requester = (
                    _load_json(suite_root, Path(item["authenticated_requester_path"]))
                    if "authenticated_requester_path" in item
                    else None
                )
                outcome, findings = apply_trace_message_atomically(
                    runner,
                    transcript,
                    message,
                    message_schema,
                    registry,
                    materials,
                    authenticated_requester=requester,
                )
                if findings:
                    error_codes.update(_finding_codes(findings))
                    protocol_outcome = "rejected"
                elif outcome.classification.startswith("EXACT_DUPLICATE"):
                    protocol_outcome = "no-op"
                    response_authorized = outcome.response_authorized
                elif outcome == "ACCEPTED":
                    protocol_outcome = (
                        "terminal"
                        if runner.phase in {"CLOSED", "ABORTED", "EXPIRED"}
                        else "accepted"
                    )
                else:
                    error_codes.add(
                        "REPLAY_CONFLICT"
                        if outcome == "REPLAY_CONFLICT"
                        else "CONFORMANCE-PROTOCOL-REJECTION"
                    )
                    protocol_outcome = "rejected"
            else:
                context_for_message = copy.deepcopy(context)
                context_reference = _load_json(suite_root, Path(item["context_path"]))
                if isinstance(context_reference.get("session_context"), dict):
                    context_for_message["session_context"] = copy.deepcopy(
                        context_reference["session_context"]
                    )
                    context_for_message["prior_transcript_digest"] = (
                        context_reference.get("prior_transcript_digest")
                    )
                _, findings = validate_message_bytes(
                    raw,
                    message_schema,
                    registry,
                    materials,
                    context_for_message,
                    path=item["path"],
                )
                if findings:
                    error_codes.update(_finding_codes(findings))
                    protocol_outcome = "rejected"
                else:
                    protocol_outcome = "accepted"
        elif kind == "timer-fixture":
            timer = _load_json(suite_root, Path(item["path"]))
            outcome, transition, findings = apply_trace_timer_atomically(
                runner, transcript, timer, timer_schema
            )
            if findings or outcome not in {"ACCEPTED", "NO_OP"}:
                error_codes.update(_finding_codes(findings))
                if not findings:
                    error_codes.add("REPLAY_CONFLICT")
                protocol_outcome = "rejected"
            elif outcome == "NO_OP":
                protocol_outcome = "no-op"
            else:
                protocol_outcome = (
                    "terminal"
                    if transition
                    in {
                        "TR-ADVANCE-TIME-EXPIRE",
                        "TR-EVALUATION-TIMEOUT",
                        "TR-CONSENT-EXPIRED",
                    }
                    else "accepted"
                )
        elif kind == "profile-local-result-fixture":
            fixture = _load_json(suite_root, Path(item["path"]))
            findings = apply_profile_local_result_fixture(runner, fixture)
            if findings:
                error_codes.update(_finding_codes(findings))
                protocol_outcome = "rejected"
            else:
                protocol_outcome = "accepted"
        elif kind == "controlled-fault-fixture":
            fixture = _load_json(suite_root, Path(item["path"]))
            if fixture != {
                "schema_version": "0.1",
                "kind": "controlled-fault-fixture",
                "fault_id": "STRICT-FIXTURE-PROCESSING-FAULT",
                "component": "reference-fixture-parser",
                "artifact_status": "test-only",
            }:
                raise ConformanceError("CONFORMANCE-FAULT-FIXTURE", item["path"])
            status = "tool-error"
            protocol_outcome = "not-evaluated"
            error_codes.add("CONFORMANCE-TOOL-ERROR")
            limitations.append(
                "controlled runner self-test fault; no Protocol event ran"
            )
            break
        else:
            raise ConformanceError("CONFORMANCE-INPUT-KIND", str(kind))

    return _actual(
        runner,
        transcript,
        status=status,
        protocol_outcome=protocol_outcome,
        error_codes=error_codes,
        initial_state=initial_state,
        initial_head=initial_head,
        initial_budget=initial_budget,
        initial_audit=initial_audit,
        limitations=limitations,
        cached_response_authorized=response_authorized,
        work_units=work_units,
    )


if __name__ == "__main__":
    print("conformance-engine: library-only", file=sys.stderr)
    raise SystemExit(2)
