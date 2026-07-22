#!/usr/bin/env python3
"""Generate the deterministic private-match-core/v0.1 conformance suite."""

from __future__ import annotations

import argparse
import copy
import json
import sys
from pathlib import Path
from typing import Any

import yaml

from canonicalize_message import canonicalize, populate_digests
from conformance_common import (
    ARTIFACT_STATUS,
    SUITE_ID,
    SUITE_ROOT,
    SUITE_VERSION,
    case_digest,
    domain_digest,
    input_digest,
    result_digest,
    sha256_bytes,
    suite_digest,
)
from conformance_engine import execute_case
from strict_yaml import strict_yaml_load


SOURCE_REVISION = "2c314027f61ca0f0edbe2dcc55a8305710efd91d"
PROTOCOL_PINS = {
    "protocol_source_revision_digest": "sha256:dba1e8d6efc6083c62c2e4b44f6e12eaa4f5c6cb5ff0cd047a9ad3df0306a208",
    "state_machine_digest": "sha256:42e63b8a1f413e932e46370aae5fa0d972f3ab71d93efe08557472b4c7066fe8",
    "message_registry_digest": "sha256:2ff1685ca4325a0ff3bd49c7a411cd7f0857add6215c2f285097bdf40dcbc2b6",
    "message_conformance_tree_digest": "sha256:19d2218c11c6ac7ba1d2f0884ba9e3c79cbd1264bd3ef682e543bcb9a63ccf0f",
}

REQUIRED_VECTOR_CLASSES = [
    "CV-VALID-END-TO-END",
    "CV-VALID-NO-MATCH",
    "CV-VALID-INDETERMINATE",
    "CV-VALID-EXACT-DUPLICATE",
    "CV-VALID-EXPIRY",
    "CV-MALFORMED-JSON",
    "CV-DUPLICATE-JSON-KEY",
    "CV-UNKNOWN-FIELD",
    "CV-UNKNOWN-VERSION",
    "CV-NONCANONICAL-JSON",
    "CV-INVALID-UNICODE",
    "CV-NAN-INFINITY",
    "CV-NEGATIVE-ZERO",
    "CV-UNSAFE-INTEGER",
    "CV-PAYLOAD-DIGEST-TAMPER",
    "CV-MESSAGE-DIGEST-TAMPER",
    "CV-WIRE-DIGEST-TAMPER",
    "CV-PRIOR-TRANSCRIPT-MISMATCH",
    "CV-TRANSCRIPT-REORDER",
    "CV-TRANSCRIPT-OMISSION",
    "CV-DUPLICATE-TRANSCRIPT-APPEND",
    "CV-WRONG-PARTICIPANT",
    "CV-WRONG-AUDIENCE",
    "CV-WRONG-SESSION",
    "CV-WRONG-POLICY",
    "CV-WRONG-PROFILE",
    "CV-WRONG-ATTEMPT",
    "CV-WRONG-COMMITMENT-PAIR",
    "CV-DUPLICATE-CONFLICT",
    "CV-NONCE-REUSE",
    "CV-STALE-SEQUENCE",
    "CV-OUT-OF-ORDER",
    "CV-CROSS-SESSION-REPLAY",
    "CV-STALE-MESSAGE",
    "CV-FUTURE-TIMESTAMP",
    "CV-CLOCK-ROLLBACK",
    "CV-CLOCK-JUMP",
    "CV-SESSION-EXPIRY",
    "CV-EVALUATION-TIMEOUT",
    "CV-CONSENT-EXPIRY",
    "CV-COMMITMENT-MISMATCH",
    "CV-ASYMMETRIC-RESULT",
    "CV-CONFLICTING-RECEIPT",
    "CV-LOW-ENTROPY-RECEIPT",
    "CV-CACHED-RESPONSE-WRONG-REQUESTER",
    "CV-MISSING-MATERIAL",
    "CV-UNKNOWN-MATERIAL",
    "CV-EXPIRED-MATERIAL",
    "CV-REVOKED-MATERIAL",
    "CV-WRONG-SUBJECT-MATERIAL",
    "CV-UNKNOWN-ALGORITHM",
    "CV-CONSENT-BEFORE-RESULT",
    "CV-CONSENT-WRONG-RECEIPT",
    "CV-CONSENT-WRONG-SCOPE",
    "CV-CONSENT-WRONG-AUDIENCE",
    "CV-CONSENT-WITHDRAWAL",
    "CV-DISCLOSURE-WITHOUT-PROFILE",
    "CV-DISCLOSURE-AFTER-EXPIRY",
    "CV-UNAUTHORIZED-REVEAL",
    "CV-EXACT-COUNT-PROHIBITED",
    "CV-MATCHING-ELEMENT-PROHIBITED",
    "CV-IDENTITY-DISCLOSURE-PROHIBITED",
    "CV-PLAINTEXT-RESULT-TO-COORDINATOR-PROHIBITED",
    "CV-RAW-PRIVATE-INPUT-TO-COORDINATOR-PROHIBITED",
    "CV-RUNNER-EXPECTED-MISMATCH",
    "CV-RUNNER-REVIEWED-SKIP",
    "CV-RUNNER-TIMEOUT",
    "CV-RUNNER-TOOL-ERROR",
]

DIRECT_INVALID = {
    "CV-DUPLICATE-JSON-KEY": "duplicate-json-key",
    "CV-UNKNOWN-FIELD": "unknown-field",
    "CV-UNKNOWN-VERSION": "protocol-version-mismatch",
    "CV-NONCANONICAL-JSON": "noncanonical-whitespace",
    "CV-NAN-INFINITY": "nan",
    "CV-NEGATIVE-ZERO": "negative-zero",
    "CV-PAYLOAD-DIGEST-TAMPER": "payload-digest-mismatch",
    "CV-PRIOR-TRANSCRIPT-MISMATCH": "prior-transcript-digest-mismatch",
    "CV-WRONG-PARTICIPANT": "cross-participant-substitution",
    "CV-WRONG-AUDIENCE": "wrong-audience",
    "CV-WRONG-SESSION": "cross-session-substitution",
    "CV-WRONG-POLICY": "cross-policy-substitution",
    "CV-WRONG-PROFILE": "callback-profile-mismatch",
    "CV-WRONG-ATTEMPT": "callback-attempt-mismatch",
    "CV-STALE-MESSAGE": "stale-message",
    "CV-FUTURE-TIMESTAMP": "future-issued-at",
    "CV-MISSING-MATERIAL": "missing-verification-material-id",
    "CV-UNKNOWN-MATERIAL": "unknown-verification-material",
    "CV-EXPIRED-MATERIAL": "expired-verification-material",
    "CV-REVOKED-MATERIAL": "revoked-verification-material",
    "CV-WRONG-SUBJECT-MATERIAL": "material-participant-mismatch",
    "CV-PLAINTEXT-RESULT-TO-COORDINATOR-PROHIBITED": "plaintext-decision-in-receipt",
    "CV-RAW-PRIVATE-INPUT-TO-COORDINATOR-PROHIBITED": "secret-input-in-receipt",
    "CV-UNAUTHORIZED-REVEAL": "actual-disclosure-payload",
}


def _slug(vector_class: str) -> str:
    return vector_class.removeprefix("CV-").lower()


def _case_id(vector_class: str) -> str:
    return "PMC-" + vector_class.removeprefix("CV-") + "-V0-1"


def _title(vector_class: str) -> str:
    return vector_class.removeprefix("CV-").replace("-", " ").title()


def _probe(rule: str, subject: str, value: Any) -> dict[str, Any]:
    return {
        "kind": "semantic-probe",
        "rule_id": rule,
        "observed": {"subject": subject, "value": value},
    }


def _canonical(value: Any) -> bytes:
    return canonicalize(value)


def _base_case(vector_class: str, inputs: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "schema_version": "0.1",
        "suite": {"id": SUITE_ID, "version": SUITE_VERSION},
        "case_id": _case_id(vector_class),
        "case_digest": "sha256:" + "0" * 64,
        "title": _title(vector_class),
        "vector_class": vector_class,
        "artifact_status": ARTIFACT_STATUS,
        "protocol": {"profile": "private-match-core", "version": "0.1"},
        "protocol_pins": copy.deepcopy(PROTOCOL_PINS),
        "conformance_input_digest": "sha256:" + "0" * 64,
        "initial_state_fixture": {
            "kind": "abstract-state-v0.1",
            "context_path": "fixtures/context.v0.1.json",
            "context_digest": "sha256:" + "0" * 64,
            "phase": "UNINITIALIZED",
        },
        "ordered_inputs": inputs,
        "authentication_precondition": {
            "mode": "fixture-preverified/v0.1",
            "cryptographic_validity": "not-evaluated",
            "material_path": "verification-material.v0.1.json",
            "material_digest": "sha256:" + "0" * 64,
        },
        "expected": {
            "runner_status": "pass",
            "protocol_outcome": "not-evaluated",
            "terminal_phase": None,
            "error_codes": [],
            "transcript_head": None,
            "state_digest": None,
            "mutation_assertions": {
                "state": "not-evaluated",
                "transcript": "not-evaluated",
                "budget": "not-evaluated",
                "audit": "not-evaluated",
            },
        },
        "required_observations": ["deterministic protocol outcome"],
        "prohibited_observations": [
            "plaintext private input",
            "plaintext Coordinator result",
        ],
        "timeout_policy": {"budget_milliseconds": 5000, "source": "suite-manifest"},
        "result_status_expectation": "pass",
        "limitations": [
            "This draft vector does not establish cryptographic security or implementation conformance."
        ],
        "provenance": {
            "license": "Apache-2.0",
            "synthetic": True,
            "generator_id": "private-match-conformance-generator/v0.1",
        },
    }


def _semantic_input(vector_class: str) -> dict[str, Any]:
    def reject(error: str) -> dict[str, Any]:
        return _probe(
            "state-precondition",
            vector_class,
            {"satisfied": False, "error_code": error},
        )

    mappings: dict[str, dict[str, Any]] = {
        "CV-TRANSCRIPT-REORDER": _probe(
            "transcript-operation", vector_class, {"operation": "reorder"}
        ),
        "CV-TRANSCRIPT-OMISSION": _probe(
            "transcript-operation", vector_class, {"operation": "omit"}
        ),
        "CV-DUPLICATE-TRANSCRIPT-APPEND": _probe(
            "transcript-operation",
            vector_class,
            {"operation": "append-exact-duplicate"},
        ),
        "CV-WRONG-COMMITMENT-PAIR": reject("COMMITMENT_MUTATION"),
        "CV-NONCE-REUSE": reject("REPLAY_CONFLICT"),
        "CV-STALE-SEQUENCE": reject("REPLAY_CONFLICT"),
        "CV-OUT-OF-ORDER": reject("REPLAY_CONFLICT"),
        "CV-CROSS-SESSION-REPLAY": reject("REPLAY_CONFLICT"),
        "CV-CLOCK-ROLLBACK": _probe(
            "clock-transition",
            vector_class,
            {"current": 10, "proposed": 9, "maximum_jump": 60},
        ),
        "CV-CLOCK-JUMP": _probe(
            "clock-transition",
            vector_class,
            {"current": 10, "proposed": 71, "maximum_jump": 60},
        ),
        "CV-CONSENT-EXPIRY": reject("CONSENT_EXPIRED"),
        "CV-COMMITMENT-MISMATCH": _probe(
            "binding-equality",
            vector_class,
            {"actual": "A", "required": "B", "error_code": "COMMITMENT_MUTATION"},
        ),
        "CV-ASYMMETRIC-RESULT": _probe(
            "local-result-symmetry",
            vector_class,
            {"party_a": "MATCH", "party_b": "NO_MATCH"},
        ),
        "CV-CONFLICTING-RECEIPT": _probe(
            "binding-equality",
            vector_class,
            {
                "actual": "receipt-a",
                "required": "receipt-b",
                "error_code": "RESULT_CONFLICT",
            },
        ),
        "CV-LOW-ENTROPY-RECEIPT": _probe(
            "low-entropy-receipt", vector_class, {"construction": "bare-result-digest"}
        ),
        "CV-CACHED-RESPONSE-WRONG-REQUESTER": _probe(
            "cached-response-recipient",
            vector_class,
            {"requester": "party-b-subject", "recipient": "party-a-subject"},
        ),
        "CV-CONSENT-BEFORE-RESULT": reject("CONSENT_MISSING"),
        "CV-CONSENT-WRONG-RECEIPT": reject("RESULT_CONFLICT"),
        "CV-CONSENT-WRONG-SCOPE": reject("DISCLOSURE_SCOPE_MISMATCH"),
        "CV-CONSENT-WRONG-AUDIENCE": reject("AUDIENCE_MISMATCH"),
        "CV-CONSENT-WITHDRAWAL": _probe(
            "state-precondition",
            vector_class,
            {"satisfied": True, "error_code": "CONSENT_INVALID"},
        ),
        "CV-DISCLOSURE-WITHOUT-PROFILE": reject("DISCLOSURE_PROFILE_REQUIRED"),
        "CV-DISCLOSURE-AFTER-EXPIRY": reject("CONSENT_EXPIRED"),
        "CV-EXACT-COUNT-PROHIBITED": _probe(
            "prohibited-observation",
            vector_class,
            {"data_class": "EXACT-COUNT", "audience": "coordinator"},
        ),
        "CV-MATCHING-ELEMENT-PROHIBITED": _probe(
            "prohibited-observation",
            vector_class,
            {"data_class": "MATCHING-ELEMENT", "audience": "coordinator"},
        ),
        "CV-IDENTITY-DISCLOSURE-PROHIBITED": _probe(
            "prohibited-observation",
            vector_class,
            {"data_class": "PARTICIPANT-IDENTITY", "audience": "peer"},
        ),
    }
    return mappings.get(vector_class, reject("INVALID_STATE_TRANSITION"))


def generated_files(root: Path, *, prepare: bool = False) -> dict[Path, bytes]:
    suite = root / SUITE_ROOT
    expected_trace = json.loads(
        (root / "conformance/messages/expected-digests/vectors.v0.1.json").read_text()
    )
    message_entries = [
        entry for entry in expected_trace["entries"] if entry["kind"] == "message"
    ][:18]
    traces = {
        "positive-trace.v0.1.json": {
            "schema_version": "0.1",
            "entries": message_entries,
        },
        "evaluation-start-trace.v0.1.json": {
            "schema_version": "0.1",
            "entries": message_entries[:11],
        },
    }
    context = strict_yaml_load(
        (root / "conformance/messages/context.v0.1.yaml").read_text(encoding="utf-8")
    )
    materials = strict_yaml_load(
        (root / "conformance/messages/verification-materials.v0.1.yaml").read_text(
            encoding="utf-8"
        )
    )
    files: dict[Path, bytes] = {
        SUITE_ROOT / "fixtures/context.v0.1.json": _canonical(context),
        SUITE_ROOT / "verification-material.v0.1.json": _canonical(materials),
    }
    for name, trace in traces.items():
        files[SUITE_ROOT / "fixtures" / name] = _canonical(trace)

    invalid_manifest = strict_yaml_load(
        (root / "conformance/messages/invalid/manifest.v0.1.yaml").read_text()
    )
    invalid_by_id = {case["id"]: case for case in invalid_manifest["cases"]}
    context_by_invalid: dict[str, str] = {}
    for identifier in sorted(set(DIRECT_INVALID.values())):
        invalid_entry = invalid_by_id[identifier]
        source = root / "conformance/messages/invalid" / invalid_entry["file"]
        files[SUITE_ROOT / "fixtures/messages" / f"{identifier}.json"] = (
            source.read_bytes()
        )
        context_name = invalid_entry["context_file"]
        context_by_invalid[identifier] = context_name
        files[SUITE_ROOT / "fixtures/contexts" / context_name] = (
            root / "conformance/messages/valid" / context_name
        ).read_bytes()

    malformed = b'{"schema_version":"0.1"'
    invalid_unicode = b'{"value":"\xff"}'
    unsafe = (
        (root / "conformance/messages/valid/session-proposal.json")
        .read_bytes()
        .replace(
            b'"maximum_time_jump_seconds":3600',
            b'"maximum_time_jump_seconds":9007199254740992',
            1,
        )
    )
    base_message = json.loads(
        (root / "conformance/messages/valid/session-acceptance-a.json").read_text()
    )
    digest_tamper = copy.deepcopy(base_message)
    digest_tamper["message_digest"] = "sha256:" + "f" * 64
    files[SUITE_ROOT / "fixtures/messages/malformed-json.json"] = malformed
    files[SUITE_ROOT / "fixtures/messages/invalid-unicode.json"] = invalid_unicode
    files[SUITE_ROOT / "fixtures/messages/unsafe-integer.json"] = unsafe
    files[SUITE_ROOT / "fixtures/messages/message-digest-tamper.json"] = _canonical(
        digest_tamper
    )
    for context_name in ("session-proposal.json", "session-acceptance-a.json"):
        files[SUITE_ROOT / "fixtures/contexts" / context_name] = (
            root / "conformance/messages/valid" / context_name
        ).read_bytes()

    # A byte-identical delayed duplicate and a same-identity changed wire value.
    duplicate = copy.deepcopy(message_entries[1]["message"])
    changed_wire = copy.deepcopy(duplicate)
    changed_wire["authentication"]["value"] += "-changed"
    files[SUITE_ROOT / "fixtures/messages/exact-duplicate.json"] = _canonical(duplicate)
    files[SUITE_ROOT / "fixtures/messages/wire-digest-tamper.json"] = _canonical(
        changed_wire
    )
    conflict = copy.deepcopy(duplicate)
    conflict["payload"]["acceptance_digest"] = "sha256:" + "a" * 64
    conflict = populate_digests(conflict)
    files[SUITE_ROOT / "fixtures/messages/duplicate-conflict.json"] = _canonical(
        conflict
    )

    # Timers are derived from the actual head at the selected stage.
    session_timer = {
        "event_type": "authoritative_timer_event",
        "event_version": "0.1",
        "delivery_class": "timer",
        "session_id": context["session_context"]["session_id"],
        "new_authoritative_time": "2026-07-21T01:00:00Z",
        "reason_or_source_class": "SESSION_EXPIRY_THRESHOLD",
        "prior_transcript_digest": message_entries[-1]["expected_head"],
    }
    evaluation_timer = copy.deepcopy(session_timer)
    evaluation_timer.update(
        {
            "new_authoritative_time": "2026-07-21T00:10:00Z",
            "reason_or_source_class": "EVALUATION_DEADLINE",
            "prior_transcript_digest": message_entries[10]["expected_head"],
        }
    )
    files[SUITE_ROOT / "fixtures/timers/session-expiry.json"] = _canonical(
        session_timer
    )
    files[SUITE_ROOT / "fixtures/timers/evaluation-timeout.json"] = _canonical(
        evaluation_timer
    )

    cases: list[dict[str, Any]] = []
    for vector_class in REQUIRED_VECTOR_CLASSES:
        inputs: list[dict[str, Any]]
        if vector_class in {
            "CV-VALID-END-TO-END",
            "CV-VALID-NO-MATCH",
            "CV-VALID-INDETERMINATE",
        }:
            variant = (
                vector_class.removeprefix("CV-VALID-")
                .replace("END-TO-END", "MATCH")
                .replace("-", "_")
            )
            inputs = [
                {
                    "kind": "trace-fixture",
                    "path": "fixtures/positive-trace.v0.1.json",
                    "result_variant": variant,
                }
            ]
        elif vector_class == "CV-VALID-EXACT-DUPLICATE":
            inputs = [
                {
                    "kind": "trace-fixture",
                    "path": "fixtures/positive-trace.v0.1.json",
                    "result_variant": "MATCH",
                },
                {
                    "kind": "message-fixture",
                    "path": "fixtures/messages/exact-duplicate.json",
                    "context_path": "fixtures/context.v0.1.json",
                },
            ]
        elif vector_class in {"CV-VALID-EXPIRY", "CV-SESSION-EXPIRY"}:
            inputs = [
                {
                    "kind": "trace-fixture",
                    "path": "fixtures/positive-trace.v0.1.json",
                    "result_variant": "MATCH",
                },
                {
                    "kind": "timer-fixture",
                    "path": "fixtures/timers/session-expiry.json",
                },
            ]
        elif vector_class == "CV-EVALUATION-TIMEOUT":
            inputs = [
                {
                    "kind": "trace-fixture",
                    "path": "fixtures/evaluation-start-trace.v0.1.json",
                    "result_variant": "MATCH",
                },
                {
                    "kind": "timer-fixture",
                    "path": "fixtures/timers/evaluation-timeout.json",
                },
            ]
        elif vector_class in DIRECT_INVALID:
            identifier = DIRECT_INVALID[vector_class]
            inputs = [
                {
                    "kind": "raw-message-fixture",
                    "path": f"fixtures/messages/{identifier}.json",
                    "context_path": f"fixtures/contexts/{context_by_invalid[identifier]}",
                }
            ]
        elif vector_class == "CV-MALFORMED-JSON":
            inputs = [
                {
                    "kind": "raw-message-fixture",
                    "path": "fixtures/messages/malformed-json.json",
                    "context_path": "fixtures/contexts/session-acceptance-a.json",
                }
            ]
        elif vector_class == "CV-INVALID-UNICODE":
            inputs = [
                {
                    "kind": "raw-message-fixture",
                    "path": "fixtures/messages/invalid-unicode.json",
                    "context_path": "fixtures/contexts/session-acceptance-a.json",
                }
            ]
        elif vector_class == "CV-UNSAFE-INTEGER":
            inputs = [
                {
                    "kind": "raw-message-fixture",
                    "path": "fixtures/messages/unsafe-integer.json",
                    "context_path": "fixtures/contexts/session-proposal.json",
                }
            ]
        elif vector_class == "CV-MESSAGE-DIGEST-TAMPER":
            inputs = [
                {
                    "kind": "raw-message-fixture",
                    "path": "fixtures/messages/message-digest-tamper.json",
                    "context_path": "fixtures/contexts/session-acceptance-a.json",
                }
            ]
        elif vector_class == "CV-WIRE-DIGEST-TAMPER":
            inputs = [
                {
                    "kind": "trace-fixture",
                    "path": "fixtures/positive-trace.v0.1.json",
                    "result_variant": "MATCH",
                },
                {
                    "kind": "message-fixture",
                    "path": "fixtures/messages/wire-digest-tamper.json",
                    "context_path": "fixtures/context.v0.1.json",
                },
            ]
        elif vector_class == "CV-DUPLICATE-CONFLICT":
            inputs = [
                {
                    "kind": "trace-fixture",
                    "path": "fixtures/positive-trace.v0.1.json",
                    "result_variant": "MATCH",
                },
                {
                    "kind": "message-fixture",
                    "path": "fixtures/messages/duplicate-conflict.json",
                    "context_path": "fixtures/context.v0.1.json",
                },
            ]
        elif vector_class == "CV-UNKNOWN-ALGORITHM":
            inputs = [
                {
                    "kind": "runner-directive",
                    "directive": "unknown-algorithm",
                    "reviewed_reason": "No production authentication algorithm is selected in v0.1.",
                }
            ]
        elif vector_class.startswith("CV-RUNNER-"):
            directive = {
                "CV-RUNNER-EXPECTED-MISMATCH": "expected-mismatch",
                "CV-RUNNER-REVIEWED-SKIP": "reviewed-skip",
                "CV-RUNNER-TIMEOUT": "force-timeout",
                "CV-RUNNER-TOOL-ERROR": "simulate-tool-error",
            }[vector_class]
            inputs = [
                {
                    "kind": "runner-directive",
                    "directive": directive,
                    "reviewed_reason": "Synthetic runner-status preservation vector.",
                }
            ]
        else:
            inputs = [_semantic_input(vector_class)]
        case = _base_case(vector_class, inputs)
        if vector_class == "CV-UNKNOWN-ALGORITHM":
            case["authentication_precondition"]["mode"] = (
                "unsupported-real-algorithm/v0.1"
            )
            case["authentication_precondition"]["material_path"] = None
            case["authentication_precondition"]["material_digest"] = None
        case["initial_state_fixture"]["context_digest"] = sha256_bytes(
            files[SUITE_ROOT / case["initial_state_fixture"]["context_path"]]
        )
        material_path = case["authentication_precondition"]["material_path"]
        if material_path is not None:
            case["authentication_precondition"]["material_digest"] = sha256_bytes(
                files[SUITE_ROOT / material_path]
            )
        for item in case["ordered_inputs"]:
            if "path" in item:
                item["fixture_digest"] = sha256_bytes(files[SUITE_ROOT / item["path"]])
            if "context_path" in item:
                item["context_digest"] = sha256_bytes(
                    files[SUITE_ROOT / item["context_path"]]
                )
        case["conformance_input_digest"] = input_digest(case)
        # Write temporary dependencies for execution; cases themselves are added below.
        cases.append(case)

    if prepare:
        for relative, content in files.items():
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)

    actual_by_id: dict[str, Any] = {}
    for case in cases:
        actual = execute_case(root, suite, case)
        actual_by_id[case["case_id"]] = actual
        case["expected"] = {
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
        case["result_status_expectation"] = actual.status
        case["case_digest"] = case_digest(case)
        files[SUITE_ROOT / "cases" / f"{_slug(case['vector_class'])}.v0.1.json"] = (
            _canonical(case)
        )

    material_digest = sha256_bytes(
        files[SUITE_ROOT / "verification-material.v0.1.json"].rstrip(b"\n")
    )
    manifest = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "schema_version": "0.1",
        "suite_id": SUITE_ID,
        "suite_version": SUITE_VERSION,
        "artifact_status": ARTIFACT_STATUS,
        "suite_digest": "sha256:" + "0" * 64,
        "protocol": {"profile": "private-match-core", "version": "0.1"},
        "protocol_pins": copy.deepcopy(PROTOCOL_PINS),
        "source_artifacts": {
            "state_machine_path": "specs/state-machines/private-match-core-session-v0.1.yaml",
            "message_registry_path": "registry/message-types.v0.1.yaml",
            "message_schema_path": "schemas/messages/envelope.v0.1.schema.json",
            "timer_schema_path": "schemas/messages/timer-event.v0.1.schema.json",
            "leakage_contract_path": "privacy/leakage-contract.v0.1.yaml",
        },
        "vector_classes": [
            {"id": vector_class, "case_ids": [_case_id(vector_class)]}
            for vector_class in REQUIRED_VECTOR_CLASSES
        ],
        "cases": [
            {
                "case_id": case["case_id"],
                "path": f"cases/{_slug(case['vector_class'])}.v0.1.json",
                "case_digest": case["case_digest"],
                "vector_class": case["vector_class"],
            }
            for case in cases
        ],
        "expected_results_path": "expected-results.v0.1.json",
        "verification_material_path": "verification-material.v0.1.json",
        "planned_adapters_path": "conformance/interop/adapters.v0.1.yaml",
        "planned_adapters_digest": sha256_bytes(
            (root / "conformance/interop/adapters.v0.1.yaml").read_bytes()
        ),
        "fixture_adapter": {
            "id": "fixture-preverified",
            "version": "0.1",
            "artifact_status": "test-only",
            "cryptographic_validity": "not-evaluated",
            "digest": material_digest,
        },
        "runner_contract": {
            "statuses": [
                "pass",
                "fail",
                "skip",
                "unsupported",
                "timeout",
                "tool-error",
            ],
            "protocol_outcomes": [
                "accepted",
                "rejected",
                "no-op",
                "terminal",
                "not-evaluated",
            ],
            "timeout_milliseconds": 5000,
            "network_permitted": False,
            "subprocess_permitted": False,
        },
        "generation": {
            "generator_id": "private-match-conformance-generator/v0.1",
            "source_revision": SOURCE_REVISION,
            "deterministic": True,
            "case_count": len(cases),
            "vector_class_count": len(REQUIRED_VECTOR_CLASSES),
        },
        "license": "Apache-2.0",
    }
    manifest["suite_digest"] = suite_digest(manifest)
    expected_results = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "schema_version": "0.1",
        "suite_id": SUITE_ID,
        "suite_version": SUITE_VERSION,
        "suite_digest": manifest["suite_digest"],
        "results": [],
        "license": "Apache-2.0",
    }
    for case in cases:
        record = {
            "case_id": case["case_id"],
            "case_digest": case["case_digest"],
            "expected_status": case["expected"]["runner_status"],
            "protocol_outcome": case["expected"]["protocol_outcome"],
            "error_codes": case["expected"]["error_codes"],
        }
        record["expected_result_digest"] = domain_digest(
            b"private-match-conformance-expected-result/v0.1\x00", record
        )
        expected_results["results"].append(record)
    files[SUITE_ROOT / "suite-manifest.v0.1.json"] = _canonical(manifest)
    files[SUITE_ROOT / "expected-results.v0.1.json"] = _canonical(expected_results)
    adapter_case = cases[0]
    adapter_actual = actual_by_id[adapter_case["case_id"]]
    adapter_result = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "schema_version": "0.1",
        "adapter": {
            "id": "synthetic-offline-adapter-fixture",
            "version": "0.1",
            "implementation_language": "fixture-json",
            "runtime": "not-executed",
            "source_revision_digest": "sha256:" + "a" * 64,
            "implementation_digest": "sha256:" + "b" * 64,
        },
        "suite": {
            "id": SUITE_ID,
            "version": SUITE_VERSION,
            "digest": manifest["suite_digest"],
        },
        "case": {
            "id": adapter_case["case_id"],
            "digest": adapter_case["case_digest"],
        },
        "status": adapter_case["expected"]["runner_status"],
        "protocol_outcome": adapter_case["expected"]["protocol_outcome"],
        "error_codes": adapter_case["expected"]["error_codes"],
        "initial_state_digest": adapter_actual.initial_state_digest,
        "final_state_digest": adapter_actual.final_state_digest,
        "initial_transcript_head": adapter_actual.initial_transcript_head,
        "final_transcript_head": adapter_actual.final_transcript_head,
        "limitations": [
            "Synthetic offline comparison fixture; not an independent implementation or interoperability certification."
        ],
        "artifact_status": "test-only",
        "result_digest": "sha256:" + "0" * 64,
    }
    adapter_result["result_digest"] = result_digest(adapter_result)
    files[SUITE_ROOT / "fixtures/adapter-results/valid-end-to-end.v0.1.json"] = (
        _canonical(adapter_result)
    )
    return files


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    root = args.root.resolve()
    try:
        files = generated_files(root, prepare=not args.check)
    except (OSError, ValueError, KeyError, TypeError, yaml.YAMLError):
        print("conformance-generate: error [bounded]", file=sys.stderr)
        return 1
    mismatches: list[str] = []
    expected_paths = {root / relative for relative in files}
    if args.check:
        for relative, content in sorted(files.items(), key=lambda item: str(item[0])):
            path = root / relative
            if not path.is_file() or path.read_bytes() != content:
                mismatches.append(str(relative))
    else:
        for relative, content in sorted(files.items(), key=lambda item: str(item[0])):
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
    managed = root / SUITE_ROOT
    if managed.exists():
        for path in managed.rglob("*"):
            if path.is_file() and path not in expected_paths:
                if args.check:
                    mismatches.append(str(path.relative_to(root)))
                else:
                    path.unlink()
    if mismatches:
        print("conformance-generate: stale: " + ", ".join(sorted(set(mismatches))))
        return 1
    print(
        f"conformance-generate: {'current' if args.check else 'generated'} "
        f"cases={len(REQUIRED_VECTOR_CLASSES)} classes={len(REQUIRED_VECTOR_CLASSES)} files={len(files)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
