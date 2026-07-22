#!/usr/bin/env python3
"""Reference execution engine that composes existing Protocol validators."""

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
    apply_trace_message_atomically,
    apply_trace_timer_atomically,
    validate_message_bytes,
)


MESSAGE_SCHEMA = Path("schemas/messages/envelope.v0.1.schema.json")
TIMER_SCHEMA = Path("schemas/messages/timer-event.v0.1.schema.json")
REGISTRY = Path("registry/message-types.v0.1.yaml")
MATERIALS = Path("conformance/messages/verification-materials.v0.1.yaml")
CONTEXT = Path("conformance/messages/context.v0.1.yaml")

FINDING_TO_ERROR = {
    "json-parse": "CONFORMANCE-INPUT-JSON",
    "noncanonical-json": "CONFORMANCE-NONCANONICAL-JSON",
    "schema": "CONFORMANCE-MESSAGE-SCHEMA",
    "unknown-message-type": "PROTOCOL_VERSION_MISMATCH",
    "protocol-version": "PROTOCOL_VERSION_MISMATCH",
    "message-version": "PROTOCOL_VERSION_MISMATCH",
    "context-binding": "PARTICIPANT_MISMATCH",
    "audience-binding": "PARTICIPANT_MISMATCH",
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
}


@dataclass
class ExecutionActual:
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
    values = set()
    for finding in findings:
        code = FINDING_TO_ERROR.get(str(finding.code), "CONFORMANCE-PROTOCOL-REJECTION")
        if (
            str(finding.code) == "verification-material"
            and "expired" in (str(finding.path) + " " + str(finding.message)).lower()
        ):
            code = "VERIFICATION_MATERIAL_EXPIRED"
        values.add(code)
    return sorted(values)


def _evaluate_probe(rule_id: str, observed: dict[str, Any]) -> tuple[str, list[str]]:
    """Evaluate closed, public Protocol assertions not represented as wire input.

    The probes are intentionally narrow: they validate projections or bindings
    already declared by the Leakage Contract, message contract, and State
    Machine.  They are not a second state-machine implementation.
    """

    subject = observed.get("subject")
    value = observed.get("value")
    if rule_id == "binding-equality":
        if not isinstance(value, dict) or value.get("actual") != value.get("required"):
            return "rejected", [str(value.get("error_code", "PARTICIPANT_MISMATCH"))]
        return "accepted", []
    if rule_id == "prohibited-observation":
        prohibited = {
            "EXACT-COUNT",
            "MATCHING-ELEMENT",
            "PARTICIPANT-IDENTITY",
            "PLAINTEXT-RESULT",
            "RAW-PRIVATE-INPUT",
            "ACTUAL-DISCLOSURE-PAYLOAD",
        }
        if isinstance(value, dict) and value.get("data_class") in prohibited:
            return "rejected", ["DISCLOSURE_PROFILE_REQUIRED"]
        return "accepted", []
    if rule_id == "clock-transition":
        if not isinstance(value, dict):
            return "rejected", ["CLOCK_DOMAIN_INVALID"]
        current = int(value.get("current", 0))
        proposed = int(value.get("proposed", 0))
        maximum = int(value.get("maximum_jump", 0))
        if proposed < current:
            return "rejected", ["CLOCK_ROLLBACK"]
        if proposed - current > maximum:
            return "rejected", ["CLOCK_JUMP_EXCEEDED"]
        return "accepted", []
    if rule_id == "state-precondition":
        if not isinstance(value, dict) or not value.get("satisfied", False):
            return "rejected", [
                str(value.get("error_code", "INVALID_STATE_TRANSITION"))
            ]
        return "accepted", []
    if rule_id == "low-entropy-receipt":
        if (
            isinstance(value, dict)
            and value.get("construction") == "bare-result-digest"
        ):
            return "rejected", ["DISCLOSURE_PROFILE_REQUIRED"]
        return "accepted", []
    if rule_id == "transcript-operation":
        operation = value.get("operation") if isinstance(value, dict) else None
        if operation in {"reorder", "omit", "append-exact-duplicate"}:
            return (
                "no-op" if operation == "append-exact-duplicate" else "rejected",
                [] if operation == "append-exact-duplicate" else ["REPLAY_CONFLICT"],
            )
        return "accepted", []
    if rule_id == "local-result-symmetry":
        if isinstance(value, dict) and value.get("party_a") != value.get("party_b"):
            return "rejected", ["RESULT_CONFLICT"]
        return "accepted", []
    if rule_id == "cached-response-recipient":
        if not isinstance(value, dict) or value.get("requester") != value.get(
            "recipient"
        ):
            return "rejected", ["PARTICIPANT_MISMATCH"]
        return "no-op", []
    if rule_id == "authentication-algorithm":
        return "not-evaluated", ["CONFORMANCE-ADAPTER-UNSUPPORTED"]
    raise ConformanceError("CONFORMANCE-PROBE-RULE", str(subject)[:120])


def execute_case(root: Path, suite_root: Path, case: dict[str, Any]) -> ExecutionActual:
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
    material_path = case["authentication_precondition"]["material_path"]
    if material_path is None:
        materials = {"materials": []}
    else:
        material_file = resolve_regular_file(suite_root, material_path)
        if (
            sha256_bytes(material_file.read_bytes())
            != case["authentication_precondition"]["material_digest"]
        ):
            raise ConformanceError("CONFORMANCE-INPUT-DIGEST", material_path)
        materials = _load_json(suite_root, Path(material_path))
    runner = AbstractStateRunner(copy.deepcopy(context))
    transcript = TranscriptState()
    initial_state = state_digest(runner, transcript)
    initial_head = transcript.head
    initial_budget = runner.query_budget_state
    initial_audit = copy.deepcopy(runner.audit_lifecycle)
    error_codes: set[str] = set()
    protocol_outcome = "not-evaluated"
    status = "pass"
    limitations = [
        "fixture-preverified authentication does not evaluate cryptographic validity"
    ]

    for item in case["ordered_inputs"]:
        kind = item["kind"]
        if "path" in item:
            fixture_file = resolve_regular_file(suite_root, item["path"])
            if sha256_bytes(fixture_file.read_bytes()) != item["fixture_digest"]:
                raise ConformanceError("CONFORMANCE-INPUT-DIGEST", item["path"])
        if "context_path" in item:
            fixture_context = resolve_regular_file(suite_root, item["context_path"])
            if sha256_bytes(fixture_context.read_bytes()) != item["context_digest"]:
                raise ConformanceError("CONFORMANCE-INPUT-DIGEST", item["context_path"])
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
                else:
                    outcome, _, findings = apply_trace_timer_atomically(
                        runner, transcript, entry["timer_event"], timer_schema
                    )
                if findings:
                    error_codes.update(_finding_codes(findings))
                    protocol_outcome = "rejected"
                    break
                protocol_outcome = (
                    "no-op"
                    if outcome.classification.startswith("EXACT_DUPLICATE")
                    else "accepted"
                )
        elif kind in {"message-fixture", "raw-message-fixture"}:
            raw_path = resolve_regular_file(suite_root, item["path"])
            raw = raw_path.read_bytes()
            if kind == "message-fixture":
                try:
                    message = strict_json_bytes(
                        raw, path=item["path"], require_canonical=True
                    )
                except ConformanceError as error:
                    error_codes.add(error.code)
                    protocol_outcome = "rejected"
                    continue
                outcome, findings = apply_trace_message_atomically(
                    runner, transcript, message, message_schema, registry, materials
                )
                if findings:
                    error_codes.update(_finding_codes(findings))
                    protocol_outcome = "rejected"
                elif (
                    outcome.classification.startswith("EXACT_DUPLICATE")
                    or outcome == "EXCLUDED"
                ):
                    protocol_outcome = "no-op"
                elif outcome == "ACCEPTED":
                    protocol_outcome = "accepted"
                else:
                    error_codes.add(
                        "REPLAY_CONFLICT"
                        if outcome == "REPLAY_CONFLICT"
                        else "CONFORMANCE-PROTOCOL-REJECTION"
                    )
                    protocol_outcome = "rejected"
            else:
                # Stateless fixture validation is bound to the reviewed base
                # context.  It must not accept substituted session/context
                # values by promoting the untrusted message to authority.
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
            if findings:
                error_codes.update(_finding_codes(findings))
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
                        "TR-CONSENT-EXPIRE",
                    }
                    else "accepted"
                )
        elif kind == "semantic-probe":
            protocol_outcome, probe_errors = _evaluate_probe(
                item["rule_id"], item["observed"]
            )
            error_codes.update(probe_errors)
        elif kind == "runner-directive":
            directive = item["directive"]
            status = {
                "reviewed-skip": "skip",
                "force-timeout": "timeout",
                "simulate-tool-error": "tool-error",
                "unknown-algorithm": "unsupported",
                "expected-mismatch": "fail",
            }[directive]
            protocol_outcome = "not-evaluated"
            error_codes.add(
                {
                    "reviewed-skip": "CONFORMANCE-REVIEWED-SKIP",
                    "force-timeout": "CONFORMANCE-TIMEOUT",
                    "simulate-tool-error": "CONFORMANCE-TOOL-ERROR",
                    "unknown-algorithm": "CONFORMANCE-ADAPTER-UNSUPPORTED",
                    "expected-mismatch": "CONFORMANCE-EXPECTED-MISMATCH",
                }[directive]
            )

    final_state = state_digest(runner, transcript)
    terminal_phase = (
        runner.phase if runner.phase in {"CLOSED", "ABORTED", "EXPIRED"} else None
    )
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
        terminal_phase=terminal_phase,
        limitations=limitations,
    )


if __name__ == "__main__":
    print("conformance-engine: library-only", file=sys.stderr)
    raise SystemExit(2)
