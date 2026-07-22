#!/usr/bin/env python3
"""Generate fixed suite artifacts from reviewed definitions and normative oracle."""

from __future__ import annotations

import argparse
import copy
import json
import sys
from pathlib import Path
from typing import Any

from canonicalize_message import (
    append_transcript,
    canonicalize,
    populate_digests,
    timer_event_digest,
    transcript_genesis_digest,
)
from conformance_common import (
    ARTIFACT_STATUS,
    ConformanceError,
    MESSAGE_INPUT_MANIFEST,
    REFERENCE_IMPLEMENTATION_MANIFEST,
    STATE_PROJECTION_PROFILE,
    SUITE_ID,
    SUITE_ROOT,
    SUITE_VERSION,
    SUITE_TREE_MANIFEST,
    case_digest,
    expected_result_digest,
    input_digest,
    reference_implementation_manifest,
    result_digest,
    sha256_bytes,
    strict_json_bytes,
    suite_digest,
    suite_tree_digest,
    validate_generated_suite_tree,
    validate_message_input_manifest,
)
from strict_yaml import strict_yaml_load

SOURCE_REVISION = "2c314027f61ca0f0edbe2dcc55a8305710efd91d"
PROTOCOL_PINS = {
    "protocol_source_revision_digest": "sha256:dba1e8d6efc6083c62c2e4b44f6e12eaa4f5c6cb5ff0cd047a9ad3df0306a208",
    "state_machine_digest": "sha256:42e63b8a1f413e932e46370aae5fa0d972f3ab71d93efe08557472b4c7066fe8",
    "message_registry_digest": "sha256:2ff1685ca4325a0ff3bd49c7a411cd7f0857add6215c2f285097bdf40dcbc2b6",
    "message_conformance_tree_digest": "sha256:19d2218c11c6ac7ba1d2f0884ba9e3c79cbd1264bd3ef682e543bcb9a63ccf0f",
}
CASE_DEFINITIONS = Path("conformance/source/case-definitions.v0.1.json")
NORMATIVE_ORACLE = Path("conformance/source/normative-expected-results.v0.1.json")

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
POLICY_PROJECTIONS = {
    "CV-UNAUTHORIZED-REVEAL",
    "CV-EXACT-COUNT-PROHIBITED",
    "CV-MATCHING-ELEMENT-PROHIBITED",
    "CV-IDENTITY-DISCLOSURE-PROHIBITED",
    "CV-PLAINTEXT-RESULT-TO-COORDINATOR-PROHIBITED",
    "CV-RAW-PRIVATE-INPUT-TO-COORDINATOR-PROHIBITED",
}
RUNNER_SELF_TESTS = {
    item for item in REQUIRED_VECTOR_CLASSES if item.startswith("CV-RUNNER-")
}


def _canonical(value: Any) -> bytes:
    return canonicalize(value)


def _load_json(root: Path, relative: Path) -> dict[str, Any]:
    value = strict_json_bytes(
        (root / relative).read_bytes(), path=relative.as_posix(), require_canonical=True
    )
    if not isinstance(value, dict):
        raise ValueError(relative)
    return value


def _slug(vector_class: str) -> str:
    return vector_class.removeprefix("CV-").lower()


def _trace(messages: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "schema_version": "0.1",
        "entries": [{"kind": "message", "message": copy.deepcopy(m)} for m in messages],
    }


def _rechain(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    head = transcript_genesis_digest()
    result: list[dict[str, Any]] = []
    for index, source in enumerate(messages, 1):
        message = copy.deepcopy(source)
        message["prior_transcript_digest"] = head
        message = populate_digests(message)
        head = append_transcript(head, index, message["message_digest"])
        result.append(message)
    return result


def _mutated(
    source: dict[str, Any],
    *,
    prior: str,
    identity: dict[str, Any] | None = None,
    payload: dict[str, Any] | None = None,
    context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    value = copy.deepcopy(source)
    value["prior_transcript_digest"] = prior
    if identity:
        value["identity"].update(identity)
    if payload:
        value["payload"].update(payload)
    if context:
        value["session_context"].update(context)
    return populate_digests(value)


def _input(
    kind: str,
    path: str,
    files: dict[Path, bytes],
    *,
    context_path: str | None = None,
    requester_path: str | None = None,
) -> dict[str, Any]:
    item: dict[str, Any] = {
        "kind": kind,
        "path": path,
        "fixture_digest": sha256_bytes(files[SUITE_ROOT / path]),
    }
    if context_path is not None:
        item.update(
            {
                "context_path": context_path,
                "context_digest": sha256_bytes(files[SUITE_ROOT / context_path]),
            }
        )
    if requester_path is not None:
        item.update(
            {
                "authenticated_requester_path": requester_path,
                "authenticated_requester_digest": sha256_bytes(
                    files[SUITE_ROOT / requester_path]
                ),
            }
        )
    return item


def _base_case(
    definition: dict[str, Any],
    inputs: list[dict[str, Any]],
    expected: dict[str, Any],
    files: dict[Path, bytes],
) -> dict[str, Any]:
    auth_mode = (
        "unsupported-real-algorithm/v0.1"
        if definition["vector_class"] == "CV-UNKNOWN-ALGORITHM"
        else "fixture-preverified/v0.1"
    )
    context_path = "fixtures/context.v0.1.json"
    material_path = (
        None
        if auth_mode.startswith("unsupported")
        else "verification-material.v0.1.json"
    )
    timeout = 1 if definition["vector_class"] == "CV-RUNNER-TIMEOUT" else 128
    precondition = (
        {
            "kind": "reviewed-skip",
            "condition": "second-adapter-planned-not-implemented",
            "reason_code": "SECOND_ADAPTER_NOT_IMPLEMENTED",
            "scope": "runner-self-test",
        }
        if definition["vector_class"] == "CV-RUNNER-REVIEWED-SKIP"
        else {"kind": "always-run"}
    )
    case = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "schema_version": "0.1",
        "suite": {"id": SUITE_ID, "version": SUITE_VERSION},
        "case_id": definition["case_id"],
        "case_digest": "sha256:" + "0" * 64,
        "title": definition["title"],
        "vector_class": definition["vector_class"],
        "case_scope": definition["case_scope"],
        "artifact_status": ARTIFACT_STATUS,
        "case_definition_source_digest": sha256_bytes(_canonical(definition)),
        "normative_oracle_source_digest": "",
        "protocol": {"profile": "private-match-core", "version": "0.1"},
        "protocol_pins": copy.deepcopy(PROTOCOL_PINS),
        "conformance_input_digest": "sha256:" + "0" * 64,
        "initial_state_fixture": {
            "kind": "abstract-state-v0.1",
            "context_path": context_path,
            "context_digest": sha256_bytes(files[SUITE_ROOT / context_path]),
            "phase": "UNINITIALIZED",
        },
        "ordered_inputs": inputs,
        "authentication_precondition": {
            "mode": auth_mode,
            "cryptographic_validity": "not-evaluated",
            "material_path": material_path,
            "material_digest": sha256_bytes(files[SUITE_ROOT / material_path])
            if material_path
            else None,
        },
        "execution_precondition": precondition,
        "expected": {
            key: copy.deepcopy(expected[key])
            for key in (
                "runner_status",
                "protocol_outcome",
                "terminal_phase",
                "error_codes",
                "initial_state_digest",
                "initial_transcript_head",
                "transcript_head",
                "state_digest",
                "accepted_event_count",
                "mutation_assertions",
                "cached_response_authorized",
            )
        },
        "required_observations": [
            "deterministic outcome from shared Protocol validation"
        ],
        "prohibited_observations": [
            "plaintext private input",
            "plaintext Coordinator result",
        ],
        "timeout_policy": {
            "kind": "deterministic-operation-budget",
            "max_operation_steps": timeout,
        },
        "result_status_expectation": expected["result_status_expectation"],
        "limitations": [
            "Draft synthetic fixtures do not establish cryptographic security or implementation conformance."
        ],
        "provenance": {
            "license": "Apache-2.0",
            "synthetic": True,
            "generator_id": "private-match-conformance-generator/v0.1",
        },
    }
    case["conformance_input_digest"] = input_digest(case)
    return case


def generated_files(root: Path) -> dict[Path, bytes]:
    source_manifest = _load_json(root, MESSAGE_INPUT_MANIFEST)
    validate_message_input_manifest(root, source_manifest)
    if (
        source_manifest["tree_digest"]
        != PROTOCOL_PINS["message_conformance_tree_digest"]
    ):
        raise ValueError("reviewed message conformance tree pin mismatch")
    definitions_source = _load_json(root, CASE_DEFINITIONS)
    oracle_source = _load_json(root, NORMATIVE_ORACLE)
    _load_json(root, STATE_PROJECTION_PROFILE)
    implementation_manifest = reference_implementation_manifest(root)
    definitions = definitions_source["definitions"]
    if [item["vector_class"] for item in definitions] != REQUIRED_VECTOR_CLASSES:
        raise ValueError("closed case-definition vector set/order mismatch")
    oracle = {item["case_id"]: item for item in oracle_source["results"]}
    if set(oracle) != {item["case_id"] for item in definitions}:
        raise ValueError("normative oracle case set mismatch")

    expected_trace = json.loads(
        (root / "conformance/messages/expected-digests/vectors.v0.1.json").read_text()
    )
    base_messages = [
        entry["message"]
        for entry in expected_trace["entries"]
        if entry["kind"] == "message"
    ][:18]
    heads = [
        entry["expected_head"]
        for entry in expected_trace["entries"]
        if entry["kind"] == "message"
    ][:18]
    context = strict_yaml_load(
        (root / "conformance/messages/context.v0.1.yaml").read_text()
    )
    materials = strict_yaml_load(
        (root / "conformance/messages/verification-materials.v0.1.yaml").read_text()
    )
    requesters = strict_yaml_load(
        (root / "conformance/messages/authenticated-requesters.v0.1.yaml").read_text()
    )
    files: dict[Path, bytes] = {
        SUITE_ROOT / "fixtures/context.v0.1.json": _canonical(context),
        SUITE_ROOT / "verification-material.v0.1.json": _canonical(materials),
        SUITE_ROOT / "fixtures/requesters/party-a.json": _canonical(
            requesters["requesters"]["party_a"]
        ),
        SUITE_ROOT / "fixtures/requesters/party-b.json": _canonical(
            requesters["requesters"]["party_b"]
        ),
    }

    def add(path: str, value: Any, *, raw: bool = False) -> None:
        files[SUITE_ROOT / path] = value if raw else _canonical(value)

    add("fixtures/traces/prefix-through-contributions.json", _trace(base_messages[:13]))
    add("fixtures/traces/result-tail.json", _trace(base_messages[13:18]))
    add("fixtures/traces/receipt-a-tail.json", _trace(base_messages[13:14]))
    add("fixtures/traces/result-acceptance-tail.json", _trace(base_messages[13:16]))
    add("fixtures/traces/consent-a-tail.json", _trace(base_messages[16:17]))
    add("fixtures/traces/positive-without-local-result.json", _trace(base_messages))
    add("fixtures/traces/evaluation-start.json", _trace(base_messages[:11]))
    add("fixtures/traces/created-and-accepted-a.json", _trace(base_messages[:2]))
    add("fixtures/traces/created.json", _trace(base_messages[:1]))
    add("fixtures/traces/both-bound.json", _trace(base_messages[:5]))
    add("fixtures/traces/commitment-a.json", _trace(base_messages[:9]))
    add("fixtures/traces/committed.json", _trace(base_messages[:10]))
    add("fixtures/traces/receipt-prefix.json", _trace(base_messages[:14]))
    add("fixtures/traces/result-prefix.json", _trace(base_messages[:16]))
    add("fixtures/traces/consent-a-prefix.json", _trace(base_messages[:17]))
    for variant in ("MATCH", "NO_MATCH", "INDETERMINATE"):
        add(
            f"fixtures/local-results/{variant.lower()}.json",
            {
                "schema_version": "0.1",
                "kind": "profile-local-result-fixture",
                "artifact_status": "test-only",
                "cryptographic_validity": "not-evaluated",
                "profile_binding": base_messages[12]["session_context"][
                    "selected_integration_profile"
                ],
                "session_id": base_messages[12]["session_context"]["session_id"],
                "evaluation_attempt_id": base_messages[12]["session_context"][
                    "evaluation_attempt_id"
                ],
                "party_local_results": {"a": variant, "b": variant},
                "opaque_receipt_ref": base_messages[13]["payload"][
                    "opaque_receipt_ref"
                ],
            },
        )
    asym = json.loads(files[SUITE_ROOT / "fixtures/local-results/match.json"])
    asym["party_local_results"]["b"] = "NO_MATCH"
    add("fixtures/local-results/asymmetric.json", asym)

    invalid_manifest = strict_yaml_load(
        (root / "conformance/messages/invalid/manifest.v0.1.yaml").read_text()
    )
    invalid_by_id = {item["id"]: item for item in invalid_manifest["cases"]}
    context_by_invalid: dict[str, str] = {}
    for identifier in sorted(set(DIRECT_INVALID.values())):
        item = invalid_by_id[identifier]
        add(
            f"fixtures/messages/{identifier}.json",
            (root / "conformance/messages/invalid" / item["file"]).read_bytes(),
            raw=True,
        )
        context_by_invalid[identifier] = item["context_file"]
        add(
            f"fixtures/contexts/{item['context_file']}",
            (root / "conformance/messages/valid" / item["context_file"]).read_bytes(),
            raw=True,
        )
    add("fixtures/messages/malformed-json.json", b'{"schema_version":"0.1"', raw=True)
    add("fixtures/messages/invalid-unicode.json", b'{"value":"\xff"}', raw=True)
    unsafe = (
        (root / "conformance/messages/valid/session-proposal.json")
        .read_bytes()
        .replace(
            b'"maximum_time_jump_seconds":3600',
            b'"maximum_time_jump_seconds":9007199254740992',
            1,
        )
    )
    add("fixtures/messages/unsafe-integer.json", unsafe, raw=True)
    add(
        "fixtures/contexts/session-proposal.json",
        (root / "conformance/messages/valid/session-proposal.json").read_bytes(),
        raw=True,
    )
    add(
        "fixtures/contexts/session-acceptance-a.json",
        (root / "conformance/messages/valid/session-acceptance-a.json").read_bytes(),
        raw=True,
    )
    digest_tamper = copy.deepcopy(base_messages[1])
    digest_tamper["message_digest"] = "sha256:" + "f" * 64
    add("fixtures/messages/message-digest-tamper.json", digest_tamper)

    # Concrete replay, binding, receipt, consent, clock, and leakage fixtures.
    add("fixtures/messages/exact-duplicate.json", base_messages[1])
    changed_wire = copy.deepcopy(base_messages[1])
    changed_wire["authentication"]["value"] += "-changed"
    add("fixtures/messages/wire-digest-tamper.json", changed_wire)
    conflict = _mutated(
        base_messages[1],
        prior=base_messages[1]["prior_transcript_digest"],
        payload={"acceptance_digest": "sha256:" + "a" * 64},
    )
    add("fixtures/messages/duplicate-conflict.json", conflict)
    nonce = _mutated(
        base_messages[3],
        prior=heads[1],
        identity={"nonce": base_messages[1]["identity"]["nonce"]},
    )
    add("fixtures/messages/nonce-reuse.json", nonce)
    stale_seq = _mutated(base_messages[5], prior=heads[4], identity={"sequence": 1})
    gap_seq = _mutated(base_messages[5], prior=heads[4], identity={"sequence": 3})
    add("fixtures/messages/stale-sequence.json", stale_seq)
    add("fixtures/messages/out-of-order.json", gap_seq)
    cross = _mutated(
        base_messages[1],
        prior=heads[1],
        context={"session_id": "urn:private-match:test:session:other"},
        identity={
            "message_id": "urn:private-match:test:message:cross-session",
            "nonce": "urn:private-match:test:nonce:cross-session",
            "sequence": 1,
        },
    )
    add("fixtures/messages/cross-session-replay.json", cross)
    wrong_pair = _mutated(
        base_messages[10],
        prior=heads[9],
        context={"commitment_pair_id": "sha256:" + "f" * 64},
    )
    add("fixtures/messages/wrong-commitment-pair.json", wrong_pair)
    commitment_again = _mutated(
        base_messages[8],
        prior=heads[8],
        identity={
            "message_id": "urn:private-match:test:message:commitment-again",
            "nonce": "urn:private-match:test:nonce:commitment-again",
            "sequence": 4,
        },
        context=base_messages[9]["session_context"],
    )
    add("fixtures/messages/commitment-mismatch.json", commitment_again)
    receipt_conflict = _mutated(
        base_messages[14],
        prior=heads[13],
        payload={
            "opaque_receipt_ref": "urn:private-match:test:opaque-receipt:conflict"
        },
    )
    add("fixtures/messages/conflicting-receipt.json", receipt_conflict)
    consent_before = _mutated(
        base_messages[16], prior=heads[12], identity={"sequence": 5}
    )
    add("fixtures/messages/consent-before-result.json", consent_before)
    consent_wrong_receipt = _mutated(
        base_messages[16],
        prior=heads[15],
        payload={"opaque_receipt_ref": "urn:private-match:test:opaque-receipt:wrong"},
    )
    add("fixtures/messages/consent-wrong-receipt.json", consent_wrong_receipt)
    consent_wrong_scope = _mutated(
        base_messages[17],
        prior=heads[16],
        payload={"scope": ["urn:private-match:test:scope:other"]},
    )
    consent_wrong_audience = _mutated(
        base_messages[17], prior=heads[16], payload={"audience": ["party_b_client"]}
    )
    add("fixtures/messages/consent-wrong-scope.json", consent_wrong_scope)
    add("fixtures/messages/consent-wrong-audience.json", consent_wrong_audience)
    withdrawal_source = json.loads(
        (root / "conformance/messages/valid/consent-withdrawal-a.json").read_text()
    )
    withdrawal = _mutated(
        withdrawal_source,
        prior=heads[17],
        identity={
            "message_id": "urn:private-match:test:message:withdrawal-a",
            "nonce": "urn:private-match:test:nonce:withdrawal-a",
            "sequence": 7,
        },
        payload={
            "consent_artifact_digest": base_messages[16]["payload"][
                "consent_artifact_digest"
            ]
        },
        context=base_messages[17]["session_context"],
    )
    add("fixtures/messages/consent-withdrawal.json", withdrawal)
    disclosure_source = json.loads(
        (
            root / "conformance/messages/valid/disclosure-extension-authorization.json"
        ).read_text()
    )
    disclosure = _mutated(
        disclosure_source,
        prior=heads[17],
        identity={
            "operation_id": "urn:private-match:test:operation:disclosure",
            "idempotency_key": "urn:private-match:test:operation-key:disclosure",
        },
        context=base_messages[17]["session_context"],
    )
    add("fixtures/messages/disclosure-extension.json", disclosure)

    for name, field in (
        ("exact-count", "exact_count"),
        ("matching-element", "matching_element"),
        ("identity-disclosure", "normalized_identifier"),
    ):
        message = copy.deepcopy(base_messages[15])
        message["payload"][field] = (
            1 if field == "exact_count" else "urn:private-match:test:prohibited"
        )
        message = populate_digests(message)
        add(f"fixtures/messages/{name}.json", message)
    low = json.loads(files[SUITE_ROOT / "fixtures/local-results/match.json"])
    import hashlib

    low["opaque_receipt_ref"] = "sha256:" + hashlib.sha256(b"MATCH").hexdigest()
    add("fixtures/local-results/low-entropy.json", low)

    rollback = {
        "event_type": "authoritative_timer_event",
        "event_version": "0.1",
        "delivery_class": "timer",
        "session_id": context["session_context"]["session_id"],
        "new_authoritative_time": "2026-07-21T00:00:29Z",
        "reason_or_source_class": "COORDINATOR_CLOCK",
        "prior_transcript_digest": heads[0],
    }
    jump = copy.deepcopy(rollback)
    jump["new_authoritative_time"] = "2026-07-21T01:00:31Z"
    session_expiry = copy.deepcopy(rollback)
    session_expiry.update(
        {
            "new_authoritative_time": "2026-07-21T01:00:00Z",
            "reason_or_source_class": "SESSION_EXPIRY_THRESHOLD",
            "prior_transcript_digest": heads[17],
        }
    )
    evaluation_timeout = copy.deepcopy(rollback)
    evaluation_timeout.update(
        {
            "new_authoritative_time": "2026-07-21T00:10:00Z",
            "reason_or_source_class": "EVALUATION_DEADLINE",
            "prior_transcript_digest": heads[10],
        }
    )
    for name, value in (
        ("rollback", rollback),
        ("jump", jump),
        ("session-expiry", session_expiry),
        ("evaluation-timeout", evaluation_timeout),
    ):
        add(f"fixtures/timers/{name}.json", value)
    later = copy.deepcopy(base_messages)
    later[10]["payload"]["evaluation_deadline"] = "2026-07-21T00:30:00Z"
    later = _rechain(later)
    add("fixtures/traces/consent-expiry-prefix.json", _trace(later))
    add(
        "fixtures/traces/consent-expiry-contribution-prefix.json",
        _trace(later[:13]),
    )
    add("fixtures/traces/consent-expiry-result-tail.json", _trace(later[13:18]))
    consent_timer = copy.deepcopy(rollback)
    consent_timer.update(
        {
            "new_authoritative_time": "2026-07-21T00:10:00Z",
            "reason_or_source_class": "CONSENT_EXPIRY_THRESHOLD",
            "prior_transcript_digest": append_transcript(
                later[-1]["prior_transcript_digest"], 18, later[-1]["message_digest"]
            ),
        }
    )
    add("fixtures/timers/consent-expiry.json", consent_timer)
    consent_expired_head = append_transcript(
        consent_timer["prior_transcript_digest"], 19, timer_event_digest(consent_timer)
    )
    disclosure_after = _mutated(
        disclosure_source,
        prior=consent_expired_head,
        identity={
            "operation_id": "urn:private-match:test:operation:disclosure-after",
            "idempotency_key": "urn:private-match:test:operation-key:disclosure-after",
        },
        context=later[-1]["session_context"],
    )
    add("fixtures/messages/disclosure-after-expiry.json", disclosure_after)
    reordered = copy.deepcopy(base_messages[:5])
    reordered[1], reordered[2] = reordered[2], reordered[1]
    add("fixtures/traces/reordered.json", _trace(reordered))
    add(
        "fixtures/traces/omitted.json",
        _trace([*base_messages[:2], *base_messages[3:5]]),
    )
    fault = {
        "schema_version": "0.1",
        "kind": "controlled-fault-fixture",
        "fault_id": "STRICT-FIXTURE-PROCESSING-FAULT",
        "component": "reference-fixture-parser",
        "artifact_status": "test-only",
    }
    add("fixtures/runner/controlled-fault.json", fault)

    def trace_input(path: str) -> dict[str, Any]:
        return _input("trace-fixture", path, files)

    def local_input(name: str) -> dict[str, Any]:
        return _input(
            "profile-local-result-fixture", f"fixtures/local-results/{name}.json", files
        )

    def msg_input(name: str, *, requester: str | None = None) -> dict[str, Any]:
        return _input(
            "message-fixture",
            f"fixtures/messages/{name}.json",
            files,
            context_path="fixtures/context.v0.1.json",
            requester_path=(
                f"fixtures/requesters/{requester}.json" if requester else None
            ),
        )

    def timer_input(name: str) -> dict[str, Any]:
        return _input("timer-fixture", f"fixtures/timers/{name}.json", files)

    def raw_input(path: str, ctx: str) -> dict[str, Any]:
        return _input("raw-message-fixture", path, files, context_path=ctx)

    scenarios: dict[str, list[dict[str, Any]]] = {}
    for vector, variant in (
        ("CV-VALID-END-TO-END", "match"),
        ("CV-VALID-NO-MATCH", "no_match"),
        ("CV-VALID-INDETERMINATE", "indeterminate"),
    ):
        scenarios[vector] = [
            trace_input("fixtures/traces/prefix-through-contributions.json"),
            local_input(variant),
            trace_input("fixtures/traces/result-tail.json"),
        ]
    scenarios["CV-VALID-EXACT-DUPLICATE"] = [
        *scenarios["CV-VALID-END-TO-END"],
        msg_input("exact-duplicate", requester="party-a"),
    ]
    scenarios["CV-DUPLICATE-TRANSCRIPT-APPEND"] = [
        *scenarios["CV-VALID-END-TO-END"],
        msg_input("exact-duplicate"),
    ]
    scenarios["CV-VALID-EXPIRY"] = [
        *scenarios["CV-VALID-END-TO-END"],
        timer_input("session-expiry"),
    ]
    scenarios["CV-SESSION-EXPIRY"] = copy.deepcopy(scenarios["CV-VALID-EXPIRY"])
    scenarios["CV-EVALUATION-TIMEOUT"] = [
        trace_input("fixtures/traces/evaluation-start.json"),
        timer_input("evaluation-timeout"),
    ]
    scenarios["CV-CLOCK-ROLLBACK"] = [
        trace_input("fixtures/traces/created.json"),
        timer_input("rollback"),
    ]
    scenarios["CV-CLOCK-JUMP"] = [
        trace_input("fixtures/traces/created.json"),
        timer_input("jump"),
    ]
    scenarios["CV-CONSENT-EXPIRY"] = [
        trace_input("fixtures/traces/consent-expiry-contribution-prefix.json"),
        local_input("match"),
        trace_input("fixtures/traces/consent-expiry-result-tail.json"),
        timer_input("consent-expiry"),
    ]
    scenarios["CV-TRANSCRIPT-REORDER"] = [trace_input("fixtures/traces/reordered.json")]
    scenarios["CV-TRANSCRIPT-OMISSION"] = [trace_input("fixtures/traces/omitted.json")]
    for vector, name, prefix in (
        ("CV-NONCE-REUSE", "nonce-reuse", "created-and-accepted-a"),
        ("CV-CROSS-SESSION-REPLAY", "cross-session-replay", "created-and-accepted-a"),
        ("CV-STALE-SEQUENCE", "stale-sequence", "both-bound"),
        ("CV-OUT-OF-ORDER", "out-of-order", "both-bound"),
        ("CV-WRONG-COMMITMENT-PAIR", "wrong-commitment-pair", "committed"),
        ("CV-COMMITMENT-MISMATCH", "commitment-mismatch", "commitment-a"),
    ):
        scenarios[vector] = [
            trace_input(f"fixtures/traces/{prefix}.json"),
            msg_input(name),
        ]
    scenarios["CV-ASYMMETRIC-RESULT"] = [
        trace_input("fixtures/traces/prefix-through-contributions.json"),
        local_input("asymmetric"),
    ]
    scenarios["CV-CONFLICTING-RECEIPT"] = [
        trace_input("fixtures/traces/prefix-through-contributions.json"),
        local_input("match"),
        trace_input("fixtures/traces/receipt-a-tail.json"),
        msg_input("conflicting-receipt"),
    ]
    scenarios["CV-LOW-ENTROPY-RECEIPT"] = [
        trace_input("fixtures/traces/prefix-through-contributions.json"),
        local_input("low-entropy"),
    ]
    scenarios["CV-CACHED-RESPONSE-WRONG-REQUESTER"] = [
        *scenarios["CV-VALID-END-TO-END"],
        msg_input("exact-duplicate", requester="party-b"),
    ]
    scenarios["CV-CONSENT-BEFORE-RESULT"] = [
        trace_input("fixtures/traces/prefix-through-contributions.json"),
        local_input("match"),
        msg_input("consent-before-result"),
    ]
    scenarios["CV-CONSENT-WRONG-RECEIPT"] = [
        trace_input("fixtures/traces/prefix-through-contributions.json"),
        local_input("match"),
        trace_input("fixtures/traces/result-acceptance-tail.json"),
        msg_input("consent-wrong-receipt"),
    ]
    scenarios["CV-CONSENT-WRONG-SCOPE"] = [
        trace_input("fixtures/traces/prefix-through-contributions.json"),
        local_input("match"),
        trace_input("fixtures/traces/result-acceptance-tail.json"),
        trace_input("fixtures/traces/consent-a-tail.json"),
        msg_input("consent-wrong-scope"),
    ]
    scenarios["CV-CONSENT-WRONG-AUDIENCE"] = [
        trace_input("fixtures/traces/prefix-through-contributions.json"),
        local_input("match"),
        trace_input("fixtures/traces/result-acceptance-tail.json"),
        trace_input("fixtures/traces/consent-a-tail.json"),
        msg_input("consent-wrong-audience"),
    ]
    scenarios["CV-CONSENT-WITHDRAWAL"] = [
        *scenarios["CV-VALID-END-TO-END"],
        msg_input("consent-withdrawal"),
    ]
    scenarios["CV-DISCLOSURE-WITHOUT-PROFILE"] = [
        *scenarios["CV-VALID-END-TO-END"],
        msg_input("disclosure-extension"),
    ]
    scenarios["CV-DISCLOSURE-AFTER-EXPIRY"] = [
        trace_input("fixtures/traces/consent-expiry-contribution-prefix.json"),
        local_input("match"),
        trace_input("fixtures/traces/consent-expiry-result-tail.json"),
        timer_input("consent-expiry"),
        msg_input("disclosure-after-expiry"),
    ]
    for vector, name in (
        ("CV-EXACT-COUNT-PROHIBITED", "exact-count"),
        ("CV-MATCHING-ELEMENT-PROHIBITED", "matching-element"),
        ("CV-IDENTITY-DISCLOSURE-PROHIBITED", "identity-disclosure"),
    ):
        scenarios[vector] = [
            raw_input(
                f"fixtures/messages/{name}.json",
                "fixtures/contexts/result-acceptance-notice.json",
            )
        ]
    for vector, identifier in DIRECT_INVALID.items():
        scenarios[vector] = [
            raw_input(
                f"fixtures/messages/{identifier}.json",
                f"fixtures/contexts/{context_by_invalid[identifier]}",
            )
        ]
    scenarios["CV-MALFORMED-JSON"] = [
        raw_input(
            "fixtures/messages/malformed-json.json",
            "fixtures/contexts/session-acceptance-a.json",
        )
    ]
    scenarios["CV-INVALID-UNICODE"] = [
        raw_input(
            "fixtures/messages/invalid-unicode.json",
            "fixtures/contexts/session-acceptance-a.json",
        )
    ]
    scenarios["CV-UNSAFE-INTEGER"] = [
        raw_input(
            "fixtures/messages/unsafe-integer.json",
            "fixtures/contexts/session-proposal.json",
        )
    ]
    scenarios["CV-MESSAGE-DIGEST-TAMPER"] = [
        raw_input(
            "fixtures/messages/message-digest-tamper.json",
            "fixtures/contexts/session-acceptance-a.json",
        )
    ]
    scenarios["CV-WIRE-DIGEST-TAMPER"] = [
        *scenarios["CV-VALID-END-TO-END"],
        msg_input("wire-digest-tamper"),
    ]
    scenarios["CV-DUPLICATE-CONFLICT"] = [
        *scenarios["CV-VALID-END-TO-END"],
        msg_input("duplicate-conflict"),
    ]
    scenarios["CV-UNKNOWN-ALGORITHM"] = []
    scenarios["CV-RUNNER-EXPECTED-MISMATCH"] = [
        trace_input("fixtures/traces/created-and-accepted-a.json")
    ]
    scenarios["CV-RUNNER-REVIEWED-SKIP"] = []
    scenarios["CV-RUNNER-TIMEOUT"] = [
        trace_input("fixtures/traces/created-and-accepted-a.json")
    ]
    scenarios["CV-RUNNER-TOOL-ERROR"] = [
        _input(
            "controlled-fault-fixture", "fixtures/runner/controlled-fault.json", files
        )
    ]
    missing = set(REQUIRED_VECTOR_CLASSES) - set(scenarios)
    if missing:
        raise ValueError(f"no executable scenario for {sorted(missing)}")

    oracle_digest = sha256_bytes((root / NORMATIVE_ORACLE).read_bytes())
    definition_source_digest = sha256_bytes((root / CASE_DEFINITIONS).read_bytes())
    cases = []
    for definition in definitions:
        expected = oracle[definition["case_id"]]
        case = _base_case(
            definition,
            copy.deepcopy(scenarios[definition["vector_class"]]),
            expected,
            files,
        )
        case["normative_oracle_source_digest"] = oracle_digest
        case["case_definition_source_digest"] = definition_source_digest
        case["case_digest"] = case_digest(case)
        cases.append(case)
        files[SUITE_ROOT / "cases" / f"{_slug(case['vector_class'])}.v0.1.json"] = (
            _canonical(case)
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
            "message_input_manifest_path": MESSAGE_INPUT_MANIFEST.as_posix(),
            "message_input_manifest_digest": sha256_bytes(
                (root / MESSAGE_INPUT_MANIFEST).read_bytes()
            ),
            "case_definitions_path": CASE_DEFINITIONS.as_posix(),
            "case_definitions_digest": definition_source_digest,
            "normative_oracle_path": NORMATIVE_ORACLE.as_posix(),
            "normative_oracle_digest": oracle_digest,
            "state_projection_profile_path": STATE_PROJECTION_PROFILE.as_posix(),
            "state_projection_profile_digest": sha256_bytes(
                (root / STATE_PROJECTION_PROFILE).read_bytes()
            ),
        },
        "vector_classes": [
            {
                "id": v,
                "case_ids": [
                    next(c["case_id"] for c in cases if c["vector_class"] == v)
                ],
            }
            for v in REQUIRED_VECTOR_CLASSES
        ],
        "cases": [
            {
                "case_id": c["case_id"],
                "path": f"cases/{_slug(c['vector_class'])}.v0.1.json",
                "case_digest": c["case_digest"],
                "vector_class": c["vector_class"],
                "case_scope": c["case_scope"],
            }
            for c in cases
        ],
        "expected_results_path": "expected-results.v0.1.json",
        "suite_tree_manifest_path": "suite-tree-manifest.v0.1.json",
        "verification_material_path": "verification-material.v0.1.json",
        "reference_verifier": {
            "implementation_manifest_path": REFERENCE_IMPLEMENTATION_MANIFEST.as_posix(),
            "implementation_manifest_digest": sha256_bytes(
                (root / REFERENCE_IMPLEMENTATION_MANIFEST).read_bytes()
            ),
            "implementation_digest": implementation_manifest["implementation_digest"],
        },
        "planned_adapters_path": "conformance/interop/adapters.v0.1.yaml",
        "planned_adapters_digest": sha256_bytes(
            (root / "conformance/interop/adapters.v0.1.yaml").read_bytes()
        ),
        "fixture_adapter": {
            "id": "fixture-preverified",
            "version": "0.1",
            "artifact_status": "test-only",
            "cryptographic_validity": "not-evaluated",
            "digest": sha256_bytes(
                files[SUITE_ROOT / "verification-material.v0.1.json"]
            ),
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
            "deterministic_operation_budget": 128,
            "network_permitted": False,
            "subprocess_permitted": False,
        },
        "generation": {
            "generator_id": "private-match-conformance-generator/v0.1",
            "source_revision": SOURCE_REVISION,
            "deterministic": True,
            "case_count": len(cases),
            "vector_class_count": len(REQUIRED_VECTOR_CLASSES),
            "case_scope_counts": {
                "protocol-executable": sum(
                    c["case_scope"] == "protocol-executable" for c in cases
                ),
                "policy-projection": sum(
                    c["case_scope"] == "policy-projection" for c in cases
                ),
                "runner-self-test": sum(
                    c["case_scope"] == "runner-self-test" for c in cases
                ),
            },
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
        "normative_oracle_source_digest": oracle_digest,
        "results": [],
        "license": "Apache-2.0",
    }
    for case in cases:
        expected = case["expected"]
        record = {
            "case_id": case["case_id"],
            "case_digest": case["case_digest"],
            "vector_class": case["vector_class"],
            **copy.deepcopy(expected),
        }
        record["expected_result_digest"] = expected_result_digest(record)
        expected_results["results"].append(record)
    files[SUITE_ROOT / "suite-manifest.v0.1.json"] = _canonical(manifest)
    files[SUITE_ROOT / "expected-results.v0.1.json"] = _canonical(expected_results)
    adapter_case = cases[0]
    adapter_expected = adapter_case["expected"]
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
            "input_digest": adapter_case["conformance_input_digest"],
        },
        "adapter_mode": "test-fixture",
        "status": adapter_expected["runner_status"],
        "protocol_outcome": adapter_expected["protocol_outcome"],
        "error_codes": adapter_expected["error_codes"],
        "initial_state_digest": adapter_expected["initial_state_digest"],
        "final_state_digest": adapter_expected["state_digest"],
        "initial_transcript_head": adapter_expected["initial_transcript_head"],
        "final_transcript_head": adapter_expected["transcript_head"],
        "accepted_event_count": adapter_expected["accepted_event_count"],
        "mutation_summary": {
            key: value == "changed"
            for key, value in adapter_expected["mutation_assertions"].items()
        },
        "cached_response_authorized": adapter_expected["cached_response_authorized"],
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
    suite_entries = []
    for path, raw in sorted(files.items(), key=lambda item: item[0].as_posix()):
        if path == SUITE_TREE_MANIFEST:
            continue
        relative = path.relative_to(SUITE_ROOT).as_posix()
        role = (
            "case"
            if relative.startswith("cases/")
            else "expected-results"
            if relative == "expected-results.v0.1.json"
            else "suite-manifest"
            if relative == "suite-manifest.v0.1.json"
            else "verification-material"
            if relative == "verification-material.v0.1.json"
            else "fixture"
        )
        suite_entries.append(
            {"path": relative, "digest": sha256_bytes(raw), "role": role}
        )
    tree_manifest = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "schema_version": "0.1",
        "artifact_status": "draft",
        "suite": {"id": SUITE_ID, "version": SUITE_VERSION},
        "entries": suite_entries,
        "file_count": len(suite_entries),
        "tree_digest": suite_tree_digest(suite_entries),
        "source_bindings": {
            "generator_digest": sha256_bytes(
                (root / "scripts/generate_conformance_suite.py").read_bytes()
            ),
            "case_definitions_digest": definition_source_digest,
            "normative_oracle_digest": oracle_digest,
            "state_projection_profile_digest": sha256_bytes(
                (root / STATE_PROJECTION_PROFILE).read_bytes()
            ),
            "implementation_manifest_digest": sha256_bytes(
                (root / REFERENCE_IMPLEMENTATION_MANIFEST).read_bytes()
            ),
        },
        "calculation": "RFC8785 path-sorted entries excluding this manifest",
        "limitations": [
            "The suite-tree digest binds generated bytes but does not establish Protocol or implementation correctness."
        ],
        "license": "Apache-2.0",
    }
    files[SUITE_TREE_MANIFEST] = _canonical(tree_manifest)
    return files


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    root = args.root.resolve()
    try:
        files = generated_files(root)
    except (OSError, ValueError, KeyError, TypeError):
        print("conformance-generator: error [bounded]", file=sys.stderr)
        return 1
    try:
        if args.check:
            validate_generated_suite_tree(root, files)
        else:
            # Refuse to conceal stale or unexpected artifacts.  A reviewed
            # cleanup must precede regeneration if the exact path set changed.
            current = root / SUITE_ROOT
            if current.exists():
                validate_generated_suite_tree(root, files, compare_bytes=False)
            for relative, content in files.items():
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(content)
            validate_generated_suite_tree(root, files)
    except (OSError, ValueError, ConformanceError):
        print(
            "conformance-generator: error [stale-generated-artifact]", file=sys.stderr
        )
        return 1
    print(
        f"conformance-generator: {'checked' if args.check else 'generated'} files={len(files)} cases={len(REQUIRED_VECTOR_CLASSES)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
