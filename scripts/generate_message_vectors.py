#!/usr/bin/env python3
"""Generate deterministic synthetic message and transcript conformance vectors."""

from __future__ import annotations

import argparse
import copy
import json
import sys
from pathlib import Path
from typing import Any

import yaml

from canonicalize_message import (
    canonicalize,
    populate_digests,
    transcript_genesis_digest,
)
from strict_yaml import strict_yaml_load
from validate_messages import (
    MESSAGE_SCHEMA,
    TIMER_SCHEMA,
    AbstractStateRunner,
    TranscriptState,
    apply_trace_message_atomically,
    apply_trace_timer_atomically,
)


REGISTRY_PATH = Path("registry/message-types.v0.1.yaml")
CONTEXT_PATH = Path("conformance/messages/context.v0.1.yaml")
MATERIAL_PATH = Path("conformance/messages/verification-materials.v0.1.yaml")
VALID_DIR = Path("conformance/messages/valid")
INVALID_DIR = Path("conformance/messages/invalid")
EXPECTED_PATH = Path("conformance/messages/expected-digests/vectors.v0.1.json")

ISSUED_AT = "2026-07-21T00:00:00Z"
EXPIRES_AT = "2026-07-21T00:10:00Z"
POSITIVE_TRACE_SEQUENCE = [
    ("session_proposal", None),
    ("session_acceptance", "a"),
    ("session_acceptance", "b"),
    ("participant_binding", "a"),
    ("participant_binding", "b"),
    ("policy_acceptance", "a"),
    ("policy_acceptance", "b"),
    ("query_budget_reservation", None),
    ("commitment_registration", "a"),
    ("commitment_registration", "b"),
    ("evaluation_start", None),
    ("evaluation_contribution", "a"),
    ("evaluation_contribution", "b"),
    ("opaque_receipt_ack", "a"),
    ("opaque_receipt_ack", "b"),
    ("result_acceptance_notice", None),
    ("consent_grant", "a"),
    ("consent_grant", "b"),
]


def _digest(fill: str) -> str:
    return "sha256:" + fill * 64


def _load_yaml(path: Path) -> dict[str, Any]:
    value = strict_yaml_load(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a mapping")
    return value


def _entry_index(registry: dict[str, Any]) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    seen_versions: set[tuple[str, str]] = set()
    for item in registry["messages"]:
        key = (item["message_type"], item["message_version"])
        if key in seen_versions:
            raise ValueError(f"duplicate message type/version: {key[0]} {key[1]}")
        seen_versions.add(key)
        result[item["message_type"]] = item
    return result


def _payload(message_type: str, party: str | None = None) -> dict[str, Any]:
    slot = party or "a"
    return {
        "session_proposal": {
            "proposal_digest": _digest("2"),
            "selected_integration_profile": {
                "profile_id": "urn:private-match:test:profile:synthetic",
                "profile_version": "0.1",
                "profile_instance_id": "urn:private-match:test:profile-instance:0001",
            },
            "session_expires_at": "2026-07-21T01:00:00Z",
            "clock_policy": {
                "allowed_clock_skew_seconds": 60,
                "message_stale_threshold_seconds": 300,
                "evaluation_timeout_seconds": 600,
                "maximum_time_jump_seconds": 3600,
            },
        },
        "session_acceptance": {
            "proposal_digest": _digest("2"),
            "acceptance_digest": _digest("3"),
        },
        "participant_binding": {
            "participant_id": f"urn:private-match:test:participant:{slot}",
            "participant_key_id": f"urn:private-match:test:key:party-{slot}:v0.1",
        },
        "policy_acceptance": {
            "policy_id": "urn:private-match:test:policy:core",
            "policy_version": "0.1",
            "acceptance_digest": _digest("4" if slot == "a" else "5"),
        },
        "commitment_registration": {
            "opaque_commitment": f"urn:private-match:test:opaque-commitment:{slot}",
        },
        "query_budget_reservation": {
            "authorization_ref": "urn:private-match:test:budget-authorization:0001"
        },
        "evaluation_start": {
            "evaluation_attempt_id": "urn:private-match:test:evaluation:0001",
            "evaluation_deadline": "2026-07-21T00:10:00Z",
        },
        "evaluation_contribution": {
            "contribution_ref": f"urn:private-match:test:opaque-contribution:{slot}"
        },
        "opaque_receipt_ack": {
            "opaque_receipt_ref": "urn:private-match:test:opaque-receipt:9f2c7d8a",
            "acknowledgment_status": "ACKNOWLEDGED",
            "profile_evidence_ref": f"urn:private-match:test:profile-evidence:{slot}",
        },
        "result_acceptance_notice": {
            "opaque_receipt_ref": "urn:private-match:test:opaque-receipt:9f2c7d8a",
            "acknowledgment_status": "BOTH_ACKNOWLEDGED",
            "profile_evidence_ref": "urn:private-match:test:profile-evidence:both",
        },
        "consent_grant": {
            "opaque_receipt_ref": "urn:private-match:test:opaque-receipt:9f2c7d8a",
            "disclosure_profile_id": "urn:private-match:test:disclosure-profile:synthetic",
            "disclosure_profile_version": "0.1",
            "scope": ["urn:private-match:test:scope:contact-ref"],
            "audience": ["party_a_client", "party_b_client"],
            "issued_at": ISSUED_AT,
            "expires_at": EXPIRES_AT,
            "consent_nonce": f"urn:private-match:test:consent-nonce:{slot}",
            "consent_artifact_digest": _digest("6" if slot == "a" else "7"),
        },
        "consent_withdrawal": {
            "consent_nonce": f"urn:private-match:test:consent-nonce:{slot}",
            "consent_artifact_digest": _digest("8" if slot == "a" else "9"),
            "reason_category": "USER_WITHDRAWAL",
        },
        "disclosure_extension_authorization": {
            "profile_id": "urn:private-match:test:disclosure-profile:synthetic",
            "profile_version": "0.1",
            "scope": ["urn:private-match:test:scope:contact-ref"],
            "audience": ["party_a_client", "party_b_client"],
            "authorization_ref": "urn:private-match:test:authorization:synthetic",
        },
        "disclosure_completion_notice": {
            "profile_id": "urn:private-match:test:disclosure-profile:synthetic",
            "profile_version": "0.1",
            "scope": ["urn:private-match:test:scope:contact-ref"],
            "audience": ["party_a_client", "party_b_client"],
            "completion_ref": "urn:private-match:test:completion:synthetic",
            "authorization_ref": "urn:private-match:test:authorization:synthetic",
        },
        "abort_notice": {"internal_failure_code": "PARTIAL_PARTY_FAILURE"},
        "normalized_error_notice": {
            "party_error_category": "SESSION_UNAVAILABLE",
            "retry_class": "new-session",
            "new_session_required": True,
        },
        "close_notice": {"reason_category": "NORMAL_CLOSE"},
        "expiry_notice": {
            "party_error_category": "SESSION_UNAVAILABLE",
            "observed_at": "2026-07-21T01:00:00Z",
        },
    }[message_type]


def _sender_and_auth(actor: str) -> tuple[dict[str, Any], dict[str, Any]]:
    if actor == "party_a_client":
        participant = "urn:private-match:test:participant:a"
        key = "urn:private-match:test:key:party-a:v0.1"
        material = "urn:private-match:test:material:party-a:v0.1"
        mode = "signature"
        algorithm = "urn:private-match:test:signature-placeholder:v0.1"
    elif actor == "party_b_client":
        participant = "urn:private-match:test:participant:b"
        key = "urn:private-match:test:key:party-b:v0.1"
        material = "urn:private-match:test:material:party-b:v0.1"
        mode = "signature"
        algorithm = "urn:private-match:test:signature-placeholder:v0.1"
    elif actor == "selected_integration_profile":
        participant = None
        key = "urn:private-match:test:key:profile:v0.1"
        material = "urn:private-match:test:material:profile:v0.1"
        mode = "profile-attestation"
        algorithm = "urn:private-match:test:profile-attestation-placeholder:v0.1"
    else:
        participant = None
        key = "urn:private-match:test:key:coordinator:v0.1"
        material = "urn:private-match:test:material:coordinator:v0.1"
        mode = "signature"
        algorithm = "urn:private-match:test:signature-placeholder:v0.1"
    return (
        {"actor": actor, "participant_id": participant, "key_id": key},
        {
            "mode": mode,
            "algorithm_id": algorithm,
            "key_id": key,
            "verification_material_id": material,
            "value": "SYNTHETIC-NOT-A-CRYPTOGRAPHIC-AUTHENTICATOR",
        },
    )


def build_message(
    registry: dict[str, Any],
    context: dict[str, Any],
    message_type: str,
    *,
    party: str | None = None,
    serial: int = 1,
    prior: str | None = None,
    sequence: int | None = None,
) -> dict[str, Any]:
    entry = _entry_index(registry)[message_type]
    if party:
        actor = f"party_{party}_client"
    else:
        actor = entry["allowed_senders"][0]
    sender, authentication = _sender_and_auth(actor)
    delivery = entry["delivery_class"]
    if delivery == "party_message":
        identity = {
            "kind": delivery,
            "sender_participant_id": sender["participant_id"],
            "message_id": f"urn:private-match:test:message:{serial:04d}",
            "nonce": f"urn:private-match:test:nonce:{serial:04d}",
            "sequence": serial - 1 if sequence is None else sequence,
            "issued_at": ISSUED_AT,
        }
    elif delivery == "coordinator_command":
        identity = {
            "kind": delivery,
            "actor_id": "coordinator",
            "operation_id": f"urn:private-match:test:operation:{serial:04d}",
            "idempotency_key": f"urn:private-match:test:operation-key:{serial:04d}",
        }
    elif delivery == "profile_callback":
        profile = context["session_context"]["selected_integration_profile"]
        identity = {
            "kind": delivery,
            **profile,
            "callback_id": f"urn:private-match:test:callback:{serial:04d}",
            "idempotency_key": f"urn:private-match:test:callback-key:{serial:04d}",
            "session_id": context["session_context"]["session_id"],
            "evaluation_attempt_id": context["session_context"][
                "evaluation_attempt_id"
            ],
        }
    else:
        identity = {
            "kind": delivery,
            "notice_id": f"urn:private-match:test:notice:{serial:04d}",
        }
    message = {
        "protocol_profile": "private-match-core",
        "protocol_version": "0.1",
        "message_type": message_type,
        "message_version": "0.1",
        "delivery_class": delivery,
        "session_context": copy.deepcopy(context["session_context"]),
        "sender": sender,
        "audience": list(entry["intended_audience"]),
        "issued_at": ISSUED_AT,
        "expires_at": EXPIRES_AT,
        "identity": identity,
        "prior_transcript_digest": prior or context["prior_transcript_digest"],
        "payload": _payload(message_type, party),
        "payload_digest": _digest("0"),
        "authentication": authentication,
        "message_digest": _digest("0"),
    }
    return populate_digests(message)


def _mutated(message: dict[str, Any], mutator) -> dict[str, Any]:
    result = copy.deepcopy(message)
    mutator(result)
    return populate_digests(result)


def _canonical_file(value: Any) -> bytes:
    return canonicalize(value)


def generated_files(root: Path) -> dict[Path, bytes]:
    registry = _load_yaml(root / REGISTRY_PATH)
    context = _load_yaml(root / CONTEXT_PATH)
    materials = _load_yaml(root / MATERIAL_PATH)
    message_schema = json.loads((root / MESSAGE_SCHEMA).read_text(encoding="utf-8"))
    timer_schema = json.loads((root / TIMER_SCHEMA).read_text(encoding="utf-8"))
    context["prior_transcript_digest"] = transcript_genesis_digest()
    files: dict[Path, bytes] = {
        CONTEXT_PATH: yaml.safe_dump(context, sort_keys=False).encode()
    }

    full_context = copy.deepcopy(context)
    full_context["session_context"]["participants"] = {
        "party_a": {
            "participant_id": "urn:private-match:test:participant:a",
            "key_id": "urn:private-match:test:key:party-a:v0.1",
        },
        "party_b": {
            "participant_id": "urn:private-match:test:participant:b",
            "key_id": "urn:private-match:test:key:party-b:v0.1",
        },
    }
    full_context["session_context"]["evaluation_attempt_id"] = (
        "urn:private-match:test:evaluation:0001"
    )
    full_context["session_context"]["selected_integration_profile"] = {
        "profile_id": "urn:private-match:test:profile:synthetic",
        "profile_version": "0.1",
        "profile_instance_id": "urn:private-match:test:profile-instance:0001",
    }
    stage_contexts: dict[tuple[str, str | None], dict[str, Any]] = {}
    stage_runner = AbstractStateRunner(copy.deepcopy(context))
    stage_transcript = TranscriptState()
    for stage_index, (message_type, party) in enumerate(POSITIVE_TRACE_SEQUENCE, 1):
        stage_context = stage_runner.context(stage_transcript.head)
        stage_contexts[(message_type, party)] = copy.deepcopy(stage_context)
        stage_message = build_message(
            registry,
            stage_context,
            message_type,
            party=party,
            serial=6000 + stage_index,
            prior=stage_transcript.head,
            sequence=stage_runner.next_sequence[party] if party else None,
        )
        stage_outcome, stage_findings = apply_trace_message_atomically(
            stage_runner,
            stage_transcript,
            stage_message,
            message_schema,
            registry,
            materials,
        )
        if stage_findings or stage_outcome != "ACCEPTED":
            raise ValueError(
                "invalid standalone vector stage: "
                + "; ".join(map(str, stage_findings))
            )
    full_context["session_context"]["commitment_pair_id"] = (
        stage_runner.commitment_pair_id
    )
    cases: list[tuple[str, str, str | None]] = [
        ("session-proposal", "session_proposal", None),
        ("session-acceptance-a", "session_acceptance", "a"),
        ("session-acceptance-b", "session_acceptance", "b"),
        ("participant-binding-a", "participant_binding", "a"),
        ("participant-binding-b", "participant_binding", "b"),
        ("policy-acceptance-a", "policy_acceptance", "a"),
        ("policy-acceptance-b", "policy_acceptance", "b"),
        ("commitment-registration-a", "commitment_registration", "a"),
        ("commitment-registration-b", "commitment_registration", "b"),
        ("query-budget-reservation", "query_budget_reservation", None),
        ("evaluation-start", "evaluation_start", None),
        ("evaluation-contribution-a", "evaluation_contribution", "a"),
        ("evaluation-contribution-b", "evaluation_contribution", "b"),
        ("opaque-receipt-ack-a", "opaque_receipt_ack", "a"),
        ("opaque-receipt-ack-b", "opaque_receipt_ack", "b"),
        ("result-acceptance-notice", "result_acceptance_notice", None),
        ("consent-grant-a", "consent_grant", "a"),
        ("consent-grant-b", "consent_grant", "b"),
        ("consent-withdrawal-a", "consent_withdrawal", "a"),
        ("consent-withdrawal-b", "consent_withdrawal", "b"),
        (
            "disclosure-extension-authorization",
            "disclosure_extension_authorization",
            None,
        ),
        ("disclosure-completion-notice", "disclosure_completion_notice", None),
        ("abort-notice", "abort_notice", None),
        ("normalized-error-notice", "normalized_error_notice", None),
        ("close-notice", "close_notice", None),
        ("expiry-notice", "expiry_notice", None),
    ]
    built: dict[str, dict[str, Any]] = {}
    for serial, (filename, message_type, party) in enumerate(cases, 1):
        vector_context = stage_contexts.get((message_type, party), full_context)
        message = build_message(
            registry, vector_context, message_type, party=party, serial=serial
        )
        built[filename] = message
        files[VALID_DIR / f"{filename}.json"] = _canonical_file(message)

    invalid: list[dict[str, str]] = []
    context_reference_by_sender = {
        (message["message_type"], message["sender"]["actor"]): filename
        for filename, message in built.items()
    }

    def add_invalid(
        name: str,
        message: dict[str, Any],
        expected_code: str,
        *,
        raw: bytes | None = None,
    ) -> None:
        files[INVALID_DIR / f"{name}.json"] = raw or _canonical_file(message)
        context_reference = context_reference_by_sender.get(
            (message.get("message_type"), message.get("sender", {}).get("actor")),
            "session-acceptance-a",
        )
        invalid.append(
            {
                "id": name,
                "file": f"{name}.json",
                "context_file": f"{context_reference}.json",
                "expected_code": expected_code,
            }
        )

    base = built["session-acceptance-a"]
    m = copy.deepcopy(base)
    m["unexpected"] = True
    add_invalid("unknown-field", m, "schema")
    m = copy.deepcopy(built["commitment-registration-a"])
    m["payload"]["commitment_pair_id"] = "sha256:" + "a" * 64
    add_invalid("party-supplied-commitment-pair-id", populate_digests(m), "schema")
    m = copy.deepcopy(base)
    m["message_type"] = "unknown_message"
    add_invalid("unknown-message-type", m, "unknown-message-type")
    m = copy.deepcopy(base)
    m["protocol_version"] = "9.9"
    add_invalid("protocol-version-mismatch", m, "protocol-version")
    m = copy.deepcopy(base)
    m["message_version"] = "9.9"
    add_invalid("message-version-mismatch", m, "message-version")
    add_invalid(
        "cross-session-substitution",
        _mutated(
            base,
            lambda x: x["session_context"].__setitem__(
                "session_id", "urn:private-match:test:session:other"
            ),
        ),
        "context-binding",
    )
    add_invalid(
        "cross-policy-substitution",
        _mutated(
            base,
            lambda x: x["session_context"]["policy"].__setitem__(
                "policy_id", "urn:private-match:test:policy:other"
            ),
        ),
        "context-binding",
    )
    add_invalid(
        "cross-participant-substitution",
        _mutated(
            built["policy-acceptance-a"],
            lambda x: x["session_context"]["participants"]["party_a"].__setitem__(
                "participant_id", "urn:private-match:test:participant:other"
            ),
        ),
        "context-binding",
    )
    add_invalid(
        "wrong-audience",
        _mutated(base, lambda x: x.__setitem__("audience", ["party_b_client"])),
        "audience-binding",
    )
    add_invalid(
        "wrong-sender-key",
        _mutated(
            built["policy-acceptance-a"],
            lambda x: x["sender"].__setitem__(
                "key_id", "urn:private-match:test:key:party-b:v0.1"
            ),
        ),
        "key-binding",
    )
    add_invalid(
        "authentication-sender-key-mismatch",
        _mutated(
            base,
            lambda x: x["authentication"].__setitem__(
                "key_id", "urn:private-match:test:key:party-a:other:v0.1"
            ),
        ),
        "authentication-subject",
    )

    def other_active_key(x):
        x["authentication"].update(
            {
                "verification_material_id": "urn:private-match:test:material:party-a-other-key:v0.1",
                "key_id": "urn:private-match:test:key:party-a:other:v0.1",
            }
        )

    add_invalid(
        "same-role-other-active-key",
        _mutated(base, other_active_key),
        "authentication-subject",
    )
    add_invalid(
        "material-participant-mismatch",
        _mutated(
            base,
            lambda x: x["authentication"].__setitem__(
                "verification_material_id",
                "urn:private-match:test:material:party-a-wrong-participant:v0.1",
            ),
        ),
        "authentication-subject",
    )
    profile_base = built["result-acceptance-notice"]
    add_invalid(
        "profile-material-instance-mismatch",
        _mutated(
            profile_base,
            lambda x: x["authentication"].__setitem__(
                "verification_material_id",
                "urn:private-match:test:material:profile-wrong-instance:v0.1",
            ),
        ),
        "authentication-subject",
    )

    def coordinator_material_for_party(x):
        x["authentication"].update(
            {
                "verification_material_id": "urn:private-match:test:material:coordinator:v0.1",
                "key_id": "urn:private-match:test:key:coordinator:v0.1",
            }
        )

    add_invalid(
        "coordinator-material-for-party",
        _mutated(base, coordinator_material_for_party),
        "authentication-subject",
    )

    def party_a_material_for_party_b(x):
        x["authentication"].update(
            {
                "verification_material_id": "urn:private-match:test:material:party-a:v0.1",
                "key_id": "urn:private-match:test:key:party-a:v0.1",
            }
        )

    add_invalid(
        "party-a-material-for-party-b",
        _mutated(built["session-acceptance-b"], party_a_material_for_party_b),
        "authentication-subject",
    )
    for field in ("algorithm_id", "key_id", "verification_material_id"):
        m = copy.deepcopy(base)
        del m["authentication"][field]
        add_invalid(f"missing-{field.replace('_', '-')}", m, "schema")
    m = copy.deepcopy(base)
    m["authentication"]["mode"] = "unknown"
    add_invalid("unknown-authentication-mode", m, "schema")
    add_invalid(
        "unknown-verification-material",
        _mutated(
            base,
            lambda x: x["authentication"].__setitem__(
                "verification_material_id",
                "urn:private-match:test:material:unknown:v0.1",
            ),
        ),
        "verification-material",
    )

    def expired_material(x):
        x["authentication"].update(
            {
                "verification_material_id": "urn:private-match:test:material:expired:v0.1",
                "key_id": "urn:private-match:test:key:expired:v0.1",
            }
        )

    add_invalid(
        "expired-verification-material",
        _mutated(base, expired_material),
        "verification-material",
    )

    def revoked_material(x):
        x["authentication"].update(
            {
                "verification_material_id": "urn:private-match:test:material:revoked:v0.1",
                "key_id": "urn:private-match:test:key:revoked:v0.1",
            }
        )

    add_invalid(
        "revoked-verification-material",
        _mutated(base, revoked_material),
        "verification-material",
    )
    add_invalid(
        "material-expired-at-authoritative-time",
        _mutated(
            base,
            lambda x: x["authentication"].__setitem__(
                "verification_material_id",
                "urn:private-match:test:material:party-a-short-lived:v0.1",
            ),
        ),
        "verification-material",
    )
    add_invalid(
        "material-issued-before-not-before",
        _mutated(
            base,
            lambda x: x["authentication"].__setitem__(
                "verification_material_id",
                "urn:private-match:test:material:party-a-future:v0.1",
            ),
        ),
        "verification-material",
    )
    add_invalid(
        "expired-message",
        _mutated(base, lambda x: x.__setitem__("expires_at", "2026-07-21T00:00:10Z")),
        "message-expired",
    )

    def stale_message(x):
        x["issued_at"] = "2026-07-20T23:50:00Z"
        x["identity"]["issued_at"] = x["issued_at"]

    add_invalid("stale-message", _mutated(base, stale_message), "stale-message")

    def future_message(x):
        x["issued_at"] = "2026-07-21T00:05:00Z"
        x["identity"]["issued_at"] = x["issued_at"]

    add_invalid("future-issued-at", _mutated(base, future_message), "future-message")
    m = copy.deepcopy(base)
    m["payload"]["proposal_digest"] = _digest("e")
    add_invalid("payload-digest-mismatch", m, "payload-digest")
    add_invalid(
        "prior-transcript-digest-mismatch",
        _mutated(
            base, lambda x: x.__setitem__("prior_transcript_digest", _digest("f"))
        ),
        "prior-transcript",
    )
    callback = built["result-acceptance-notice"]
    add_invalid(
        "callback-profile-mismatch",
        _mutated(
            callback,
            lambda x: x["identity"].__setitem__(
                "profile_id", "urn:private-match:test:profile:other"
            ),
        ),
        "callback-binding",
    )
    add_invalid(
        "callback-attempt-mismatch",
        _mutated(
            callback,
            lambda x: x["identity"].__setitem__(
                "evaluation_attempt_id", "urn:private-match:test:evaluation:other"
            ),
        ),
        "callback-binding",
    )
    receipt = built["opaque-receipt-ack-a"]
    for name, key, value, code in (
        (
            "secret-input-in-receipt",
            "secret_input",
            "synthetic-secret",
            "prohibited-data",
        ),
        (
            "plaintext-decision-in-receipt",
            "plaintext_result",
            "MATCH",
            "plaintext-outcome",
        ),
        (
            "actual-disclosure-payload",
            "actual_disclosure_payload",
            "synthetic-payload",
            "prohibited-data",
        ),
    ):
        m = copy.deepcopy(receipt)
        m["payload"][key] = value
        m = populate_digests(m)
        add_invalid(name, m, code)
    notice = built["normalized-error-notice"]
    m = copy.deepcopy(notice)
    m["payload"]["failure_code"] = "RESULT_CONFLICT"
    m = populate_digests(m)
    add_invalid("raw-failure-code-in-party-notice", m, "failure-projection")

    canonical = _canonical_file(base)
    duplicate_raw = canonical.replace(
        b'"protocol_version":"0.1",',
        b'"protocol_version":"0.1","protocol_version":"0.1",',
        1,
    )
    add_invalid("duplicate-json-key", base, "json-parse", raw=duplicate_raw)
    proposal_raw = files[VALID_DIR / "session-proposal.json"]
    add_invalid(
        "nan",
        built["session-proposal"],
        "json-parse",
        raw=proposal_raw.replace(
            b'"allowed_clock_skew_seconds":60', b'"allowed_clock_skew_seconds":NaN', 1
        ),
    )
    add_invalid(
        "infinity",
        built["session-proposal"],
        "json-parse",
        raw=proposal_raw.replace(
            b'"allowed_clock_skew_seconds":60',
            b'"allowed_clock_skew_seconds":Infinity',
            1,
        ),
    )
    add_invalid(
        "negative-zero",
        built["session-proposal"],
        "json-parse",
        raw=proposal_raw.replace(
            b'"allowed_clock_skew_seconds":60', b'"allowed_clock_skew_seconds":-0', 1
        ),
    )
    add_invalid(
        "noncanonical-number",
        built["session-proposal"],
        "noncanonical-json",
        raw=proposal_raw.replace(
            b'"allowed_clock_skew_seconds":60', b'"allowed_clock_skew_seconds":6e1', 1
        ),
    )
    add_invalid(
        "noncanonical-whitespace", base, "noncanonical-json", raw=b" " + canonical
    )

    # RFC 8785 preserves Unicode as-is.  Replacing NFC with NFD while retaining
    # the prior digests is therefore a substitution, not a normalization step.
    unicode_notice = copy.deepcopy(notice)
    unicode_notice["payload"]["human_message"] = "Caf\u00e9"
    unicode_notice = populate_digests(unicode_notice)
    raw = _canonical_file(unicode_notice).replace(
        "Café".encode(), "Cafe\u0301".encode()
    )
    add_invalid(
        "unicode-normalization-substitution", unicode_notice, "payload-digest", raw=raw
    )

    files[INVALID_DIR / "manifest.v0.1.yaml"] = yaml.safe_dump(
        {"schema_version": "0.1", "cases": invalid}, sort_keys=False
    ).encode()

    # Build one authoritative positive chain.  Each message is rebuilt with the
    # actual prior head so routing/policy/authentication input is chain-bound.
    transcript = TranscriptState()
    entries = []
    runner = AbstractStateRunner(copy.deepcopy(context))
    for index, (message_type, party) in enumerate(POSITIVE_TRACE_SEQUENCE, 1):
        stage_context = runner.context(transcript.head)
        message = build_message(
            registry,
            stage_context,
            message_type,
            party=party,
            serial=1000 + index,
            prior=transcript.head,
            sequence=runner.next_sequence[party] if party else None,
        )
        outcome, trace_findings = apply_trace_message_atomically(
            runner,
            transcript,
            message,
            message_schema,
            registry,
            materials,
        )
        if trace_findings or outcome != "ACCEPTED":
            raise ValueError(
                "invalid generated state trace: " + "; ".join(map(str, trace_findings))
            )
        entries.append(
            {
                "kind": "message",
                "accepted_event_index": index,
                "message": message,
                "expected_head": transcript.head,
            }
        )
    timer = {
        "event_type": "authoritative_timer_event",
        "event_version": "0.1",
        "delivery_class": "timer",
        "session_id": runner.base_context["session_context"]["session_id"],
        "new_authoritative_time": "2026-07-21T00:00:31Z",
        "reason_or_source_class": "COORDINATOR_CLOCK",
        "prior_transcript_digest": transcript.head,
    }
    index = len(entries) + 1
    outcome, _, timer_findings = apply_trace_timer_atomically(
        runner, transcript, timer, timer_schema
    )
    if timer_findings or outcome != "ACCEPTED":
        raise ValueError(
            "invalid generated timer transition: " + "; ".join(map(str, timer_findings))
        )
    entries.append(
        {
            "kind": "timer",
            "accepted_event_index": index,
            "timer_event": timer,
            "expected_head": transcript.head,
        }
    )
    close_index = len(entries) + 1
    close_message = build_message(
        registry,
        runner.context(transcript.head),
        "close_notice",
        serial=1000 + close_index,
        prior=transcript.head,
    )
    close_outcome, trace_findings = apply_trace_message_atomically(
        runner,
        transcript,
        close_message,
        message_schema,
        registry,
        materials,
    )
    if trace_findings or close_outcome != "ACCEPTED":
        raise ValueError(
            "invalid generated close transition: " + "; ".join(map(str, trace_findings))
        )
    entries.append(
        {
            "kind": "message",
            "accepted_event_index": close_index,
            "message": close_message,
            "expected_head": transcript.head,
        }
    )

    party_conflict = copy.deepcopy(entries[1]["message"])
    party_conflict["payload"]["acceptance_digest"] = _digest("a")
    party_conflict = populate_digests(party_conflict)
    party_changed_authentication = copy.deepcopy(entries[1]["message"])
    party_changed_authentication["authentication"]["value"] += "-changed"
    op_original = build_message(registry, full_context, "evaluation_start", serial=4001)
    op_changed_key = _mutated(
        op_original,
        lambda x: x["identity"].__setitem__(
            "idempotency_key", "urn:private-match:test:operation-key:changed"
        ),
    )
    op_changed_id = _mutated(
        op_original,
        lambda x: x["identity"].__setitem__(
            "operation_id", "urn:private-match:test:operation:changed"
        ),
    )
    op_changed_authentication = copy.deepcopy(op_original)
    op_changed_authentication["authentication"]["value"] += "-changed"
    cb_original = build_message(
        registry, full_context, "result_acceptance_notice", serial=5001
    )
    cb_changed_key = _mutated(
        cb_original,
        lambda x: x["identity"].__setitem__(
            "idempotency_key", "urn:private-match:test:callback-key:changed"
        ),
    )
    cb_changed_id = _mutated(
        cb_original,
        lambda x: x["identity"].__setitem__(
            "callback_id", "urn:private-match:test:callback:changed"
        ),
    )
    cb_changed_authentication = copy.deepcopy(cb_original)
    cb_changed_authentication["authentication"]["value"] += "-changed"
    expected = {
        "schema_version": "0.1",
        "genesis_digest": transcript_genesis_digest(),
        "entries": entries,
        "final_head": transcript.head,
        "duplicate_vectors": {
            "party_exact": entries[1]["message"],
            "party_changed_payload": party_conflict,
            "party_changed_authentication_value": party_changed_authentication,
            "operation_exact": op_original,
            "operation_same_id_different_key": op_changed_key,
            "operation_same_key_different_id": op_changed_id,
            "operation_changed_authentication_value": op_changed_authentication,
            "callback_exact": cb_original,
            "callback_same_id_different_key": cb_changed_key,
            "callback_same_key_different_id": cb_changed_id,
            "callback_changed_authentication_value": cb_changed_authentication,
        },
        "negative_transcript_vectors": [
            {
                "id": "reordering",
                "operation": "swap first two accepted entries",
                "expected": "different-head-or-prior-mismatch",
            },
            {
                "id": "omission",
                "operation": "omit one accepted entry",
                "expected": "different-head-or-prior-mismatch",
            },
            {
                "id": "exact-duplicate-appended-twice",
                "operation": "repeat exact party message",
                "expected": "unchanged-head",
            },
            {
                "id": "rejected-message-appended",
                "operation": "mark message rejected",
                "expected": "unchanged-head",
            },
        ],
    }
    files[EXPECTED_PATH] = _canonical_file(expected)
    return files


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    root = args.root.resolve()
    try:
        files = generated_files(root)
    except (OSError, ValueError, KeyError, TypeError, yaml.YAMLError) as error:
        print(f"message-vectors: error: {error}", file=sys.stderr)
        return 1
    mismatches = []
    for relative, content in sorted(files.items(), key=lambda item: str(item[0])):
        path = root / relative
        if args.check:
            if not path.is_file() or path.read_bytes() != content:
                mismatches.append(str(relative))
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
    managed = {VALID_DIR, INVALID_DIR, EXPECTED_PATH.parent}
    expected_paths = {root / path for path in files}
    for directory in managed:
        for path in (root / directory).glob("*"):
            if path.is_file() and path not in expected_paths:
                if args.check:
                    mismatches.append(str(path.relative_to(root)))
                else:
                    path.unlink()
    if mismatches:
        print("message-vectors: stale: " + ", ".join(sorted(mismatches)))
        return 1
    print(
        f"message-vectors: {'current' if args.check else 'generated'} ({len(files)} files)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
