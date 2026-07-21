#!/usr/bin/env python3
"""Validate the draft core message registry, vectors, and transcript contract.

Validation is local-only and intentionally does not authenticate a signature,
MAC, or attestation.  It verifies the complete authentication input, strict JCS
encoding, synthetic verification-material metadata, replay identities, and
accepted transcript chain.  A selected cryptographic profile is still required
before any implementation or security claim.
"""

from __future__ import annotations

import argparse
import copy
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import SchemaError

from canonicalize_message import (
    CanonicalMessageError,
    append_transcript,
    bounded_error,
    canonicalize,
    commitment_pair_digest,
    message_digest,
    payload_digest,
    strict_loads,
    timer_event_digest,
    transcript_genesis_digest,
)
from strict_yaml import strict_yaml_load
from validate_session_state_machine import authoritative_time_transition


MESSAGE_SCHEMA = Path("schemas/messages/envelope.v0.1.schema.json")
TIMER_SCHEMA = Path("schemas/messages/timer-event.v0.1.schema.json")
REGISTRY_SCHEMA = Path("schemas/registry/message-types.v0.1.schema.json")
MATERIAL_SCHEMA = Path("schemas/registry/verification-materials.v0.1.schema.json")
REGISTRY_PATH = Path("registry/message-types.v0.1.yaml")
MATERIAL_PATH = Path("conformance/messages/verification-materials.v0.1.yaml")
CONTEXT_PATH = Path("conformance/messages/context.v0.1.yaml")
INVALID_MANIFEST = Path("conformance/messages/invalid/manifest.v0.1.yaml")
EXPECTED_DIGESTS = Path("conformance/messages/expected-digests/vectors.v0.1.json")
STATE_MACHINE_PATH = Path("specs/state-machines/private-match-core-session-v0.1.yaml")

PROHIBITED_CORE_KEYS = {
    "raw_identifiers",
    "normalized_identifiers",
    "matching_elements",
    "non_matching_elements",
    "exact_intersection_count",
    "private_attributes",
    "plaintext_result",
    "local_result",
    "local_result_binding",
    "actual_disclosure_payload",
    "secret_input",
}
PLAINTEXT_RESULTS = {"MATCH", "NO_MATCH", "INDETERMINATE"}
PARTY_ACTORS = {"party_a_client": "party_a", "party_b_client": "party_b"}
EXTERNAL_DELIVERY_CLASSES = {
    "party_message",
    "coordinator_command",
    "profile_callback",
    "derived_transition",
}

TRUSTED_SUBJECT_SOURCES = {
    "trusted.authenticated_subject.actor",
    "trusted.authenticated_subject.participant_id",
    "trusted.authenticated_subject.key_id",
    "trusted.authenticated_subject.subject_binding_id",
    "trusted.authenticated_subject.verification_material_id",
}

# These State Machine parameter paths are not merely documentary registry
# destinations: AbstractStateRunner executes the corresponding cross-message
# binding checks.  Registry validation fails if a required path is disconnected.
RUNNER_SECURITY_PARAMETER_READS = {
    "session_acceptance": {
        "session_acceptance_parameter.proposal_digest",
        "session_acceptance_parameter.acceptance_digest",
        *(
            source.replace(
                "trusted.authenticated_subject", "authenticated_subject_parameter"
            )
            for source in TRUSTED_SUBJECT_SOURCES
        ),
    },
    "participant_binding": {
        "participant_binding_parameter.participant_id",
        "participant_binding_parameter.key_id",
        *(
            source.replace(
                "trusted.authenticated_subject", "authenticated_subject_parameter"
            )
            for source in TRUSTED_SUBJECT_SOURCES
        ),
    },
    "policy_acceptance": {
        "policy_acceptance_parameter.policy_id",
        "policy_acceptance_parameter.policy_version",
        "policy_acceptance_parameter.acceptance_digest",
    },
    "commitment_registration": {"commitment_parameter.opaque_commitment"},
    "evaluation_contribution": {"evaluation_contribution_parameter.contribution_ref"},
    "opaque_receipt_ack": {
        "opaque_receipt_parameter.opaque_receipt_ref",
        "opaque_receipt_parameter.acknowledgment_status",
        "opaque_receipt_parameter.profile_evidence_ref",
    },
    "result_acceptance_notice": {
        "opaque_receipt_parameter.opaque_receipt_ref",
        "opaque_receipt_parameter.acknowledgment_status",
        "opaque_receipt_parameter.profile_evidence_ref",
    },
    "consent_grant": {
        f"consent_binding_parameter.{field}"
        for field in (
            "opaque_receipt_ref",
            "disclosure_profile_id",
            "disclosure_profile_version",
            "scope",
            "audience",
            "issued_at",
            "expires_at",
            "consent_nonce",
            "consent_artifact_digest",
        )
    },
}


@dataclass(frozen=True, order=True)
class Finding:
    code: str
    path: str
    message: str

    def __str__(self) -> str:
        return f"{self.path}: {self.code}: {self.message}"


def _finding(code: str, path: str, message: str) -> Finding:
    return Finding(code, path, message)


def _load_json(path: Path) -> tuple[Any | None, list[Finding]]:
    try:
        raw = path.read_bytes()
        return strict_loads(raw), []
    except OSError as error:
        return None, [_finding("file-read", str(path), bounded_error(error))]
    except (UnicodeError, CanonicalMessageError) as error:
        return None, [_finding("json-parse", str(path), bounded_error(error))]


def _load_yaml(path: Path) -> tuple[Any | None, list[Finding]]:
    try:
        return strict_yaml_load(path.read_text(encoding="utf-8")), []
    except OSError as error:
        return None, [_finding("file-read", str(path), bounded_error(error))]
    except UnicodeError as error:
        return None, [_finding("text-decode", str(path), bounded_error(error))]
    except yaml.YAMLError as error:
        return None, [_finding("yaml-parse", str(path), bounded_error(error))]


def _parse_time(value: Any, path: str, findings: list[Finding]) -> datetime | None:
    if not isinstance(value, str):
        findings.append(_finding("message-time", path, "timestamp must be a string"))
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        findings.append(_finding("message-time", path, "invalid RFC 3339 timestamp"))
        return None
    if parsed.tzinfo is None:
        findings.append(_finding("message-time", path, "timestamp requires a timezone"))
        return None
    return parsed.astimezone(timezone.utc)


def _schema_findings(
    value: Any, schema: dict[str, Any], path: str, *, code: str = "schema"
) -> list[Finding]:
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    findings: list[Finding] = []
    for error in sorted(validator.iter_errors(value), key=lambda item: list(item.path)):
        suffix = ".".join(str(part) for part in error.absolute_path)
        error_path = f"{path}.{suffix}" if suffix else path
        findings.append(_finding(code, error_path, bounded_error(error)))
    return findings


def _walk_prohibited(value: Any, path: str = "$") -> list[Finding]:
    findings: list[Finding] = []
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{key}"
            if key in PROHIBITED_CORE_KEYS:
                findings.append(
                    _finding(
                        "prohibited-data", child_path, "field is forbidden in core JSON"
                    )
                )
            findings.extend(_walk_prohibited(child, child_path))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            findings.extend(_walk_prohibited(child, f"{path}[{index}]"))
    return findings


def _walk_plaintext_result(value: Any, path: str = "$") -> list[Finding]:
    findings: list[Finding] = []
    if isinstance(value, dict):
        for key, child in value.items():
            findings.extend(_walk_plaintext_result(child, f"{path}.{key}"))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            findings.extend(_walk_plaintext_result(child, f"{path}[{index}]"))
    elif value in PLAINTEXT_RESULTS:
        findings.append(
            _finding(
                "plaintext-outcome",
                path,
                "Coordinator-readable core JSON cannot contain a decision value",
            )
        )
    return findings


def _unique_index(
    items: list[Any], key_fields: tuple[str, ...]
) -> dict[tuple[Any, ...], dict[str, Any]]:
    """Build an index without last-wins behavior.

    Duplicate semantic identifiers are intentionally omitted from the index;
    repository validation reports them separately and no arbitrary record is
    treated as authoritative.
    """

    index: dict[tuple[Any, ...], dict[str, Any]] = {}
    duplicate_keys: set[tuple[Any, ...]] = set()
    for item in items:
        if not isinstance(item, dict):
            continue
        key = tuple(item.get(field) for field in key_fields)
        if any(value is None for value in key):
            continue
        if key in index:
            duplicate_keys.add(key)
            del index[key]
        elif key not in duplicate_keys:
            index[key] = item
    return index


def _registry_index(registry: dict[str, Any]) -> dict[str, dict[str, Any]]:
    composite = _unique_index(
        registry.get("messages", []), ("message_type", "message_version")
    )
    return {str(key[0]): value for key, value in composite.items() if key[1] == "0.1"}


def _material_index(materials: dict[str, Any]) -> dict[str, dict[str, Any]]:
    composite = _unique_index(
        materials.get("materials", []), ("verification_material_id",)
    )
    return {str(key[0]): value for key, value in composite.items()}


def authenticated_subject_parameter(
    message: dict[str, Any],
    materials: dict[str, Any],
    authoritative_time: Any,
) -> tuple[dict[str, Any] | None, list[Finding]]:
    """Derive the trusted State Machine subject projection fail closed.

    This value is deliberately not copied from a wire parameter.  It is created
    only after the synthetic material registry has bound the sender, key,
    subject, validity interval, and current authoritative verification time.
    """

    findings: list[Finding] = []
    authentication = message.get("authentication", {})
    sender = message.get("sender", {})
    if not isinstance(authentication, dict) or not isinstance(sender, dict):
        return None, [
            _finding(
                "authentication-subject",
                "message",
                "trusted subject requires sender and authentication objects",
            )
        ]
    material_id = authentication.get("verification_material_id")
    material = _material_index(materials).get(str(material_id))
    if material is None:
        return None, [
            _finding(
                "authentication-subject",
                "message.authentication.verification_material_id",
                "trusted subject requires known verification material",
            )
        ]
    subject = material.get("subject", {})
    if not isinstance(subject, dict):
        subject = {}
    for condition, path, detail in (
        (
            material.get("status") == "active",
            "message.authentication.verification_material_id",
            "trusted subject requires active verification material",
        ),
        (
            authentication.get("key_id")
            == sender.get("key_id")
            == material.get("key_id"),
            "message.authentication.key_id",
            "sender, authentication, and material key IDs must match",
        ),
        (
            authentication.get("mode") == material.get("mode")
            and authentication.get("algorithm_id") == material.get("algorithm_id"),
            "message.authentication",
            "authentication mode and algorithm must match the reviewed material",
        ),
        (
            subject.get("actor") == sender.get("actor"),
            "message.sender.actor",
            "material subject actor must match sender",
        ),
        (
            subject.get("kind") != "party"
            or subject.get("participant_id") == sender.get("participant_id"),
            "message.sender.participant_id",
            "material subject participant must match sender",
        ),
        (
            sender.get("actor") not in PARTY_ACTORS or subject.get("kind") == "party",
            "message.authentication.verification_material_id",
            "Party event requires a Party verification-material subject",
        ),
    ):
        if not condition:
            findings.append(_finding("authentication-subject", path, detail))
    issued = _parse_time(message.get("issued_at"), "message.issued_at", findings)
    authoritative = _parse_time(
        authoritative_time, "context.authoritative_time", findings
    )
    not_before = _parse_time(
        material.get("not_before"), "material.not_before", findings
    )
    not_after = _parse_time(material.get("not_after"), "material.not_after", findings)
    if issued and not_before and issued < not_before:
        findings.append(
            _finding(
                "authentication-subject", "message.issued_at", "material not valid"
            )
        )
    if issued and not_after and issued >= not_after:
        findings.append(
            _finding("authentication-subject", "message.issued_at", "material expired")
        )
    if authoritative and not_before and authoritative < not_before:
        findings.append(
            _finding(
                "authentication-subject",
                "context.authoritative_time",
                "material not valid at authoritative time",
            )
        )
    if authoritative and not_after and authoritative >= not_after:
        findings.append(
            _finding(
                "authentication-subject",
                "context.authoritative_time",
                "material expired at authoritative time",
            )
        )
    if findings:
        return None, sorted(set(findings))
    return {
        "actor": subject.get("actor"),
        "participant_id": subject.get("participant_id"),
        "key_id": material.get("key_id"),
        "subject_binding_id": material.get("subject_binding_id"),
        "verification_material_id": material_id,
    }, []


def semantic_message_findings(
    message: dict[str, Any],
    registry: dict[str, Any],
    materials: dict[str, Any],
    context: dict[str, Any],
    *,
    path: str = "message",
    require_context_prior: bool = True,
) -> list[Finding]:
    """Validate a current-message attempt without authoritative replay state.

    This stateless path deliberately applies current transcript, clock, and
    verification-material gates.  It must never infer that an input is a
    historical exact duplicate; that decision belongs to the authoritative
    accepted-record path in :func:`apply_trace_message_atomically`.
    """
    findings: list[Finding] = []
    entry = _registry_index(registry).get(str(message.get("message_type")))
    if entry is None:
        return [
            _finding("unknown-message-type", path, "message type is not registered")
        ]

    if message.get("protocol_profile") != "private-match-core":
        findings.append(_finding("protocol-version", path, "protocol profile mismatch"))
    if message.get("protocol_version") != "0.1":
        findings.append(_finding("protocol-version", path, "protocol version mismatch"))
    if message.get("message_version") != entry.get("message_version"):
        findings.append(_finding("message-version", path, "message version mismatch"))
    if message.get("delivery_class") != entry.get("delivery_class"):
        findings.append(
            _finding("delivery-class", path, "registry delivery class mismatch")
        )

    if message.get("session_context") != context.get("session_context"):
        expected = context.get("session_context", {})
        actual = message.get("session_context", {})
        for key in (
            "session_id",
            "policy",
            "participants",
            "intended_audience",
            "commitment_pair_id",
            "evaluation_attempt_id",
            "selected_integration_profile",
        ):
            if isinstance(actual, dict) and actual.get(key) != expected.get(key):
                findings.append(
                    _finding(
                        "context-binding",
                        f"{path}.session_context.{key}",
                        "context mismatch",
                    )
                )

    sender = message.get("sender", {})
    sender_actor = sender.get("actor") if isinstance(sender, dict) else None
    if sender_actor not in entry.get("allowed_senders", []):
        findings.append(
            _finding("sender-binding", f"{path}.sender", "sender is not allowed")
        )
    if sorted(message.get("audience", [])) != sorted(
        entry.get("intended_audience", [])
    ):
        findings.append(
            _finding("audience-binding", f"{path}.audience", "audience mismatch")
        )

    identity = message.get("identity", {})
    if isinstance(identity, dict):
        delivery = message.get("delivery_class")
        if identity.get("kind") != delivery:
            findings.append(
                _finding(
                    "delivery-class", f"{path}.identity.kind", "identity class mismatch"
                )
            )
        if delivery == "party_message":
            party_slot = PARTY_ACTORS.get(str(sender_actor))
            participants = context.get("session_context", {}).get("participants", {})
            expected_party = participants.get(party_slot) if party_slot else None
            establishing_binding = message.get("message_type") in {
                "session_acceptance",
                "participant_binding",
            }
            if expected_party is not None and sender.get(
                "participant_id"
            ) != expected_party.get("participant_id"):
                findings.append(
                    _finding(
                        "participant-binding",
                        f"{path}.sender.participant_id",
                        "participant mismatch",
                    )
                )
            if expected_party is not None and sender.get(
                "key_id"
            ) != expected_party.get("key_id"):
                findings.append(
                    _finding(
                        "key-binding", f"{path}.sender.key_id", "Party key mismatch"
                    )
                )
            if expected_party is None and not establishing_binding:
                findings.append(
                    _finding(
                        "participant-binding",
                        f"{path}.sender.participant_id",
                        "Party is not yet bound for this message type",
                    )
                )
            if identity.get("sender_participant_id") != sender.get("participant_id"):
                findings.append(
                    _finding(
                        "participant-binding",
                        f"{path}.identity.sender_participant_id",
                        "replay sender mismatch",
                    )
                )
            if identity.get("issued_at") != message.get("issued_at"):
                findings.append(
                    _finding(
                        "message-time",
                        f"{path}.identity.issued_at",
                        "replay issued_at mismatch",
                    )
                )
        elif delivery == "coordinator_command":
            if (
                identity.get("actor_id") != "coordinator"
                or sender_actor != "coordinator"
            ):
                findings.append(
                    _finding(
                        "operation-binding",
                        f"{path}.identity.actor_id",
                        "operation actor mismatch",
                    )
                )
        elif delivery == "profile_callback":
            selected = (
                context.get("session_context", {}).get("selected_integration_profile")
                or {}
            )
            for key in ("profile_id", "profile_version", "profile_instance_id"):
                if identity.get(key) != selected.get(key):
                    findings.append(
                        _finding(
                            "callback-binding",
                            f"{path}.identity.{key}",
                            "profile callback mismatch",
                        )
                    )
            for key in ("session_id", "evaluation_attempt_id"):
                if identity.get(key) != context.get("session_context", {}).get(key):
                    findings.append(
                        _finding(
                            "callback-binding",
                            f"{path}.identity.{key}",
                            "callback context mismatch",
                        )
                    )

    issued_at = _parse_time(message.get("issued_at"), f"{path}.issued_at", findings)
    expires_at = _parse_time(message.get("expires_at"), f"{path}.expires_at", findings)
    authoritative = _parse_time(
        context.get("authoritative_time"), "context.authoritative_time", findings
    )
    if issued_at and expires_at and issued_at >= expires_at:
        findings.append(
            _finding("message-time", path, "issued_at must precede expires_at")
        )
    if authoritative and expires_at and authoritative >= expires_at:
        findings.append(_finding("message-expired", path, "message is expired"))
    if authoritative and issued_at:
        stale = int(context.get("message_stale_threshold_seconds", 0))
        skew = int(context.get("allowed_clock_skew_seconds", 0))
        age = (authoritative - issued_at).total_seconds()
        future = (issued_at - authoritative).total_seconds()
        if age > stale:
            findings.append(
                _finding("stale-message", path, "message exceeds stale threshold")
            )
        if future > skew:
            findings.append(
                _finding("future-message", path, "issued_at exceeds allowed clock skew")
            )

    if require_context_prior and message.get("prior_transcript_digest") != context.get(
        "prior_transcript_digest"
    ):
        findings.append(
            _finding("prior-transcript", path, "prior transcript digest mismatch")
        )

    payload = message.get("payload")
    if isinstance(payload, dict):
        missing = sorted(
            set(entry.get("payload", {}).get("required_fields", [])) - payload.keys()
        )
        if missing:
            findings.append(
                _finding(
                    "payload-fields",
                    f"{path}.payload",
                    "missing fields: " + ", ".join(missing),
                )
            )
        prohibited = sorted(
            set(entry.get("payload", {}).get("prohibited_fields", [])) & payload.keys()
        )
        if prohibited:
            findings.append(
                _finding(
                    "prohibited-data",
                    f"{path}.payload",
                    "prohibited fields: " + ", ".join(prohibited),
                )
            )

    findings.extend(_walk_prohibited(message, path))
    if (
        "coordinator" in message.get("audience", [])
        or entry.get("verifier") == "coordinator"
    ):
        findings.extend(_walk_plaintext_result(message, path))
    if any(audience in PARTY_ACTORS for audience in message.get("audience", [])):
        if isinstance(payload, dict) and (
            "failure_code" in payload or "internal_failure_code" in payload
        ):
            findings.append(
                _finding(
                    "failure-projection",
                    f"{path}.payload",
                    "raw failure detail cannot be Party-visible",
                )
            )

    try:
        expected_payload = payload_digest(payload)
        if message.get("payload_digest") != expected_payload:
            findings.append(
                _finding("payload-digest", f"{path}.payload_digest", "digest mismatch")
            )
        expected_message = message_digest(message)
        if message.get("message_digest") != expected_message:
            findings.append(
                _finding("message-digest", f"{path}.message_digest", "digest mismatch")
            )
    except CanonicalMessageError as error:
        findings.append(_finding("canonicalization", path, bounded_error(error)))

    authentication = message.get("authentication", {})
    if isinstance(authentication, dict):
        if message.get(
            "delivery_class"
        ) in EXTERNAL_DELIVERY_CLASSES and authentication.get("mode") in {None, "none"}:
            findings.append(
                _finding(
                    "authentication",
                    f"{path}.authentication.mode",
                    "external message authentication cannot be none",
                )
            )
        material = _material_index(materials).get(
            str(authentication.get("verification_material_id"))
        )
        if material is None:
            findings.append(
                _finding(
                    "verification-material",
                    f"{path}.authentication.verification_material_id",
                    "unknown verification material",
                )
            )
        else:
            for key in ("mode", "algorithm_id", "key_id"):
                if authentication.get(key) != material.get(key):
                    findings.append(
                        _finding(
                            "verification-material",
                            f"{path}.authentication.{key}",
                            f"does not match {key} registry binding",
                        )
                    )
            if authentication.get("key_id") != sender.get("key_id"):
                findings.append(
                    _finding(
                        "authentication-subject",
                        f"{path}.authentication.key_id",
                        "authentication key must equal the claimed sender key",
                    )
                )
            subject = material.get("subject", {})
            if not isinstance(subject, dict) or subject.get("actor") != sender_actor:
                findings.append(
                    _finding(
                        "authentication-subject",
                        f"{path}.authentication.verification_material_id",
                        "verification material subject actor does not match sender",
                    )
                )
            elif subject.get("kind") == "party":
                if subject.get("participant_id") != sender.get("participant_id"):
                    findings.append(
                        _finding(
                            "authentication-subject",
                            f"{path}.sender.participant_id",
                            "verification material participant does not match sender",
                        )
                    )
                if sender_actor in PARTY_ACTORS:
                    slot = PARTY_ACTORS[sender_actor]
                    payload_binding = message.get("payload", {})
                    if message.get("message_type") == "participant_binding":
                        if payload_binding.get("participant_id") != sender.get(
                            "participant_id"
                        ) or payload_binding.get("participant_key_id") != sender.get(
                            "key_id"
                        ):
                            findings.append(
                                _finding(
                                    "authentication-subject",
                                    f"{path}.payload",
                                    f"binding payload must match authenticated {slot}",
                                )
                            )
            elif subject.get("kind") == "integration-profile":
                selected = (
                    context.get("session_context", {}).get(
                        "selected_integration_profile"
                    )
                    or {}
                )
                for key in ("profile_id", "profile_version", "profile_instance_id"):
                    if subject.get(key) != selected.get(key):
                        findings.append(
                            _finding(
                                "authentication-subject",
                                f"{path}.authentication.verification_material_id",
                                f"verification material {key} does not match selected profile",
                            )
                        )
            if material.get("status") != "active":
                findings.append(
                    _finding(
                        "verification-material",
                        path,
                        f"material status is {material.get('status')}",
                    )
                )
            not_before = _parse_time(
                material.get("not_before"), "material.not_before", findings
            )
            not_after = _parse_time(
                material.get("not_after"), "material.not_after", findings
            )
            if issued_at and not_before and issued_at < not_before:
                findings.append(
                    _finding("verification-material", path, "material is not yet valid")
                )
            if issued_at and not_after and issued_at >= not_after:
                findings.append(
                    _finding("verification-material", path, "material is expired")
                )
            if authoritative and not_before and authoritative < not_before:
                findings.append(
                    _finding(
                        "verification-material",
                        path,
                        "material is not yet valid at authoritative time",
                    )
                )
            if authoritative and not_after and authoritative >= not_after:
                findings.append(
                    _finding(
                        "verification-material",
                        path,
                        "material is expired at authoritative time",
                    )
                )

    return sorted(set(findings))


@dataclass
class DedupRegistry:
    """Authoritative accepted-record indexes for cached-response replay.

    Records retain every replay identity field required by the State Machine,
    the validated material reference, canonical message digest, and a bounded
    response reference.  The response reference is a conformance-model token,
    not a transport response or protocol payload.
    """

    party_by_id: dict[tuple[str, str, str], dict[str, Any]] = field(
        default_factory=dict
    )
    party_by_nonce: dict[tuple[str, str, str], dict[str, Any]] = field(
        default_factory=dict
    )
    operation_by_id: dict[tuple[str, str], dict[str, Any]] = field(default_factory=dict)
    operation_by_key: dict[tuple[str, str], dict[str, Any]] = field(
        default_factory=dict
    )
    callback_by_id: dict[tuple[str, ...], dict[str, Any]] = field(default_factory=dict)
    callback_by_key: dict[tuple[str, ...], dict[str, Any]] = field(default_factory=dict)

    @staticmethod
    def _response_ref(message: dict[str, Any]) -> str:
        return "urn:private-match:normalized-response:" + str(
            message["message_digest"]
        ).removeprefix("sha256:")

    @classmethod
    def _party_record(cls, message: dict[str, Any]) -> dict[str, Any]:
        identity = message["identity"]
        return {
            "message_id": identity["message_id"],
            "nonce": identity["nonce"],
            "sequence": identity["sequence"],
            "issued_at": identity["issued_at"],
            "canonical_message_digest": message["message_digest"],
            "verification_material_id": message["authentication"][
                "verification_material_id"
            ],
            "recipient_actor": message["sender"]["actor"],
            "recipient_participant_id": identity["sender_participant_id"],
            "normalized_response_ref": cls._response_ref(message),
        }

    @classmethod
    def _operation_record(cls, message: dict[str, Any]) -> dict[str, Any]:
        identity = message["identity"]
        return {
            "operation_id": identity["operation_id"],
            "idempotency_key": identity["idempotency_key"],
            "canonical_message_digest": message["message_digest"],
            "verification_material_id": message["authentication"][
                "verification_material_id"
            ],
            "recipient_actor": "coordinator",
            "normalized_response_ref": cls._response_ref(message),
        }

    @classmethod
    def _callback_record(cls, message: dict[str, Any]) -> dict[str, Any]:
        identity = message["identity"]
        return {
            "profile_id": identity["profile_id"],
            "profile_version": identity["profile_version"],
            "profile_instance_id": identity["profile_instance_id"],
            "session_id": identity["session_id"],
            "evaluation_attempt_id": identity["evaluation_attempt_id"],
            "callback_id": identity["callback_id"],
            "idempotency_key": identity["idempotency_key"],
            "canonical_message_digest": message["message_digest"],
            "verification_material_id": message["authentication"][
                "verification_material_id"
            ],
            "recipient_actor": "selected_integration_profile",
            "normalized_response_ref": cls._response_ref(message),
        }

    def classify(self, message: dict[str, Any], *, commit: bool = True) -> str:
        delivery = message["delivery_class"]
        identity = message["identity"]
        if delivery == "party_message":
            domain = (
                message["session_context"]["session_id"],
                identity["sender_participant_id"],
            )
            by_id_key = (*domain, identity["message_id"])
            by_nonce_key = (*domain, identity["nonce"])
            record = self._party_record(message)
            old_id = self.party_by_id.get(by_id_key)
            old_nonce = self.party_by_nonce.get(by_nonce_key)
            if old_id is None and old_nonce is None:
                if commit:
                    self.party_by_id[by_id_key] = copy.deepcopy(record)
                    self.party_by_nonce[by_nonce_key] = copy.deepcopy(record)
                return "ACCEPTED"
            if old_id == record and old_nonce == record:
                return "EXACT_DUPLICATE"
            return "REPLAY_CONFLICT"
        if delivery == "coordinator_command":
            actor = identity["actor_id"]
            id_key = (actor, identity["operation_id"])
            idem_key = (actor, identity["idempotency_key"])
            record = self._operation_record(message)
            old_id, old_key = (
                self.operation_by_id.get(id_key),
                self.operation_by_key.get(idem_key),
            )
            if old_id is None and old_key is None:
                if commit:
                    self.operation_by_id[id_key] = copy.deepcopy(record)
                    self.operation_by_key[idem_key] = copy.deepcopy(record)
                return "ACCEPTED"
            if old_id == record and old_key == record:
                return "EXACT_DUPLICATE"
            return "REPLAY_CONFLICT"
        if delivery == "profile_callback":
            domain = tuple(
                identity[key]
                for key in (
                    "profile_id",
                    "profile_version",
                    "profile_instance_id",
                    "session_id",
                    "evaluation_attempt_id",
                )
            )
            id_key = (*domain, identity["callback_id"])
            idem_key = (*domain, identity["idempotency_key"])
            record = self._callback_record(message)
            old_id, old_key = (
                self.callback_by_id.get(id_key),
                self.callback_by_key.get(idem_key),
            )
            if old_id is None and old_key is None:
                if commit:
                    self.callback_by_id[id_key] = copy.deepcopy(record)
                    self.callback_by_key[idem_key] = copy.deepcopy(record)
                return "ACCEPTED"
            if old_id == record and old_key == record:
                return "EXACT_DUPLICATE"
            return "REPLAY_CONFLICT"
        # Derived notices are outbound projections, not accepted mutations.
        return "EXCLUDED"

    def cached_response(
        self,
        message: dict[str, Any],
        *,
        requester_actor: str,
        requester_participant_id: str | None = None,
    ) -> str | None:
        """Return only the exact accepted record's recipient-scoped response."""

        if self.classify(message, commit=False) != "EXACT_DUPLICATE":
            return None
        identity = message["identity"]
        delivery = message["delivery_class"]
        if delivery == "party_message":
            key = (
                message["session_context"]["session_id"],
                identity["sender_participant_id"],
                identity["message_id"],
            )
            record = self.party_by_id.get(key)
            if (
                record is None
                or requester_actor != record["recipient_actor"]
                or requester_participant_id != record["recipient_participant_id"]
            ):
                return None
        elif delivery == "coordinator_command":
            record = self.operation_by_id.get(
                (identity["actor_id"], identity["operation_id"])
            )
            if record is None or requester_actor != record["recipient_actor"]:
                return None
        elif delivery == "profile_callback":
            domain = tuple(
                identity[key]
                for key in (
                    "profile_id",
                    "profile_version",
                    "profile_instance_id",
                    "session_id",
                    "evaluation_attempt_id",
                )
            )
            record = self.callback_by_id.get((*domain, identity["callback_id"]))
            if record is None or requester_actor != record["recipient_actor"]:
                return None
        else:
            return None
        response = record.get("normalized_response_ref")
        return response if isinstance(response, str) else None


@dataclass
class TranscriptState:
    head: str = field(default_factory=transcript_genesis_digest)
    accepted_event_index: int = 0
    dedup: DedupRegistry = field(default_factory=DedupRegistry)

    def accept_message(self, message: dict[str, Any], *, rejected: bool = False) -> str:
        if rejected:
            return "REJECTED"
        # Classify without recording first. Dedup indexes and transcript state
        # become authoritative together only after the prior-head guard passes.
        classification = self.dedup.classify(message, commit=False)
        if classification == "REPLAY_CONFLICT":
            return classification
        if classification in {"EXACT_DUPLICATE", "EXCLUDED"}:
            return classification
        if message["prior_transcript_digest"] != self.head:
            return "PRIOR_TRANSCRIPT_MISMATCH"
        next_index = self.accepted_event_index + 1
        next_head = append_transcript(self.head, next_index, message["message_digest"])
        if self.dedup.classify(message, commit=True) != "ACCEPTED":
            raise RuntimeError("dedup state changed during accepted-event commit")
        self.accepted_event_index = next_index
        self.head = next_head
        return "ACCEPTED"

    def accept_timer(self, event: dict[str, Any], *, mutates: bool = True) -> str:
        """Append a pre-authorized timer event; use the atomic trace helper.

        This low-level transcript primitive intentionally has no State Machine
        authority.  Repository validation and vector generation must call
        :func:`apply_trace_timer_atomically`, which derives and commits runner
        effects before invoking this method on a candidate copy.
        """

        if not mutates:
            return "NO_OP"
        required = {
            "event_type",
            "event_version",
            "delivery_class",
            "session_id",
            "new_authoritative_time",
            "reason_or_source_class",
            "prior_transcript_digest",
        }
        if set(event) != required:
            raise CanonicalMessageError("timer event fields do not match v0.1 contract")
        if (
            event.get("event_type") != "authoritative_timer_event"
            or event.get("event_version") != "0.1"
            or event.get("delivery_class") != "timer"
            or event.get("reason_or_source_class")
            not in {
                "COORDINATOR_CLOCK",
                "SESSION_EXPIRY_THRESHOLD",
                "EVALUATION_DEADLINE",
                "CONSENT_EXPIRY_THRESHOLD",
            }
        ):
            raise CanonicalMessageError("unsupported timer event value")
        timer_findings: list[Finding] = []
        if (
            _parse_time(
                event.get("new_authoritative_time"),
                "timer.new_authoritative_time",
                timer_findings,
            )
            is None
        ):
            raise CanonicalMessageError("invalid timer authoritative time")
        if event["prior_transcript_digest"] != self.head:
            return "PRIOR_TRANSCRIPT_MISMATCH"
        next_index = self.accepted_event_index + 1
        event_digest = timer_event_digest(event)
        next_head = append_transcript(self.head, next_index, event_digest)
        # Commit both fields only after canonicalization, digest construction,
        # prior-head validation, and index bounds validation have succeeded.
        self.accepted_event_index, self.head = next_index, next_head
        return "ACCEPTED"


@dataclass
class AbstractStateRunner:
    """Minimal deterministic executor for the positive conformance trace.

    This is not a protocol implementation.  It enforces the stage prerequisites
    and pre-transition context bindings needed to prove that the message
    registry's positive chain is executable against the reviewed state-machine
    transition map.
    """

    base_context: dict[str, Any]
    phase: str = "UNINITIALIZED"
    proposal_digest: str | None = None
    session_acceptance: dict[str, dict[str, Any] | None] = field(
        default_factory=lambda: {"a": None, "b": None}
    )
    participants: dict[str, dict[str, str] | None] = field(
        default_factory=lambda: {"party_a": None, "party_b": None}
    )
    policy_acceptance: dict[str, dict[str, Any] | None] = field(
        default_factory=lambda: {"a": None, "b": None}
    )
    budget_reserved: bool = False
    commitments: dict[str, str | None] = field(
        default_factory=lambda: {"a": None, "b": None}
    )
    commitment_pair_id: str | None = None
    evaluation_attempt_id: str | None = None
    selected_integration_profile: dict[str, str] | None = None
    contributions: dict[str, str | None] = field(
        default_factory=lambda: {"a": None, "b": None}
    )
    receipt_acks: dict[str, dict[str, Any] | None] = field(
        default_factory=lambda: {"a": None, "b": None}
    )
    accepted_receipt: dict[str, Any] | None = None
    consents: dict[str, dict[str, Any] | None] = field(
        default_factory=lambda: {"a": None, "b": None}
    )
    next_sequence: dict[str, int] = field(default_factory=lambda: {"a": 0, "b": 0})
    authoritative_time: str | None = None
    session_expires_at: str | None = None
    evaluation_deadline: str | None = None
    maximum_time_jump_seconds: int | None = None
    evaluation_started: bool = False
    query_budget_state: str = "NONE"
    disclosure_state: str = "NONE"
    terminal_failure_code: str = "NONE"
    party_terminal_category: str = "NONE"
    audit_lifecycle: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.authoritative_time is None:
            value = self.base_context.get("authoritative_time")
            self.authoritative_time = value if isinstance(value, str) else None
        if self.maximum_time_jump_seconds is None:
            value = self.base_context.get("maximum_time_jump_seconds")
            if isinstance(value, int) and not isinstance(value, bool):
                self.maximum_time_jump_seconds = value

    def context(self, prior_head: str) -> dict[str, Any]:
        context = copy.deepcopy(self.base_context)
        context["authoritative_time"] = self.authoritative_time
        context["prior_transcript_digest"] = prior_head
        session = context["session_context"]
        session["participants"] = copy.deepcopy(self.participants)
        session["commitment_pair_id"] = self.commitment_pair_id
        session["evaluation_attempt_id"] = self.evaluation_attempt_id
        session["selected_integration_profile"] = copy.deepcopy(
            self.selected_integration_profile
        )
        return context

    def apply(
        self,
        message: dict[str, Any],
        registry: dict[str, Any],
        materials: dict[str, Any],
    ) -> list[Finding]:
        """Validate one enabled transition and atomically apply its abstract effect."""

        before = copy.deepcopy(self.__dict__)
        findings: list[Finding] = []
        message_type = str(message.get("message_type"))
        sender = message.get("sender", {})
        actor = sender.get("actor") if isinstance(sender, dict) else None
        party = (
            "a"
            if actor == "party_a_client"
            else "b"
            if actor == "party_b_client"
            else None
        )
        payload = message.get("payload", {})
        transition: str | None = None
        trusted_subject: dict[str, Any] | None = None

        if party:
            trusted_subject, subject_findings = authenticated_subject_parameter(
                message,
                materials,
                self.base_context.get("authoritative_time"),
            )
            findings.extend(subject_findings)

        def require(condition: bool, detail: str) -> None:
            if not condition:
                findings.append(_finding("state-trace", message_type, detail))

        if message_type == "session_proposal":
            transition = "TR-CREATE"
            require(
                self.phase == "UNINITIALIZED", "session proposal requires UNINITIALIZED"
            )
            if not findings:
                self.phase = "CREATED"
                self.proposal_digest = payload.get("proposal_digest")
                self.selected_integration_profile = copy.deepcopy(
                    payload.get("selected_integration_profile")
                )
                self.session_expires_at = payload.get("session_expires_at")
                clock_policy = payload.get("clock_policy", {})
                self.maximum_time_jump_seconds = clock_policy.get(
                    "maximum_time_jump_seconds"
                )
                self.base_context["allowed_clock_skew_seconds"] = clock_policy.get(
                    "allowed_clock_skew_seconds"
                )
                self.base_context["message_stale_threshold_seconds"] = clock_policy.get(
                    "message_stale_threshold_seconds"
                )
        elif message_type == "session_acceptance" and party:
            transition = f"TR-ACCEPT-SESSION-{party.upper()}"
            require(self.phase == "CREATED", "session acceptance requires CREATED")
            require(
                payload.get("proposal_digest") == self.proposal_digest,
                "acceptance must bind the exact proposal digest",
            )
            require(
                self.session_acceptance[party] is None, "acceptance slot is immutable"
            )
            require(
                trusted_subject is not None
                and trusted_subject.get("actor") == f"party_{party}_client",
                "acceptance requires the validated Party-slot subject projection",
            )
            if not findings:
                self.session_acceptance[party] = {
                    "proposal_digest": payload.get("proposal_digest"),
                    "acceptance_digest": payload.get("acceptance_digest"),
                    "participant_id": trusted_subject.get("participant_id"),
                    "key_id": trusted_subject.get("key_id"),
                    "subject_binding_id": trusted_subject.get("subject_binding_id"),
                    "verification_material_id": trusted_subject.get(
                        "verification_material_id"
                    ),
                }
        elif message_type == "participant_binding" and party:
            other = "b" if party == "a" else "a"
            transition = (
                f"TR-BIND-{party.upper()}-FIRST"
                if self.participants[f"party_{other}"] is None
                else f"TR-BIND-{party.upper()}-COMPLETE"
            )
            require(self.phase == "CREATED", "participant binding requires CREATED")
            require(
                self.session_acceptance[party] is not None,
                "participant binding requires Party-specific session acceptance",
            )
            require(
                self.participants[f"party_{party}"] is None,
                "participant slot is already bound",
            )
            acceptance = self.session_acceptance[party] or {}
            require(
                trusted_subject is not None
                and payload.get("participant_id")
                == acceptance.get("participant_id")
                == trusted_subject.get("participant_id")
                and payload.get("participant_key_id")
                == acceptance.get("key_id")
                == trusted_subject.get("key_id")
                and acceptance.get("subject_binding_id")
                == trusted_subject.get("subject_binding_id")
                and acceptance.get("verification_material_id")
                == trusted_subject.get("verification_material_id"),
                "participant binding must equal the immutable accepted authenticated subject",
            )
            if not findings:
                self.participants[f"party_{party}"] = {
                    "participant_id": payload.get("participant_id"),
                    "key_id": payload.get("participant_key_id"),
                }
                if all(self.participants.values()):
                    self.phase = "PARTICIPANTS_BOUND"
        elif message_type == "policy_acceptance" and party:
            transition = f"TR-ACCEPT-POLICY-{party.upper()}"
            require(
                self.phase == "PARTICIPANTS_BOUND",
                "policy acceptance requires both participants bound",
            )
            expected_policy = self.base_context.get("session_context", {}).get(
                "policy", {}
            )
            require(
                payload.get("policy_id") == expected_policy.get("policy_id")
                and payload.get("policy_version")
                == expected_policy.get("policy_version"),
                "policy acceptance must equal the current policy ID and version",
            )
            require(
                self.policy_acceptance[party] is None,
                "Party policy acceptance slot is immutable",
            )
            if not findings:
                self.policy_acceptance[party] = {
                    key: payload.get(key)
                    for key in ("policy_id", "policy_version", "acceptance_digest")
                }
        elif message_type == "query_budget_reservation":
            transition = "TR-RESERVE-BUDGET"
            require(
                self.phase == "PARTICIPANTS_BOUND"
                and all(self.policy_acceptance.values()),
                "budget reservation requires bilateral policy acceptance",
            )
            if not findings:
                self.budget_reserved = True
                self.query_budget_state = "RESERVED"
                self.phase = "COMMITMENTS_PENDING"
        elif message_type == "commitment_registration" and party:
            other = "b" if party == "a" else "a"
            transition = (
                f"TR-COMMIT-{party.upper()}-FIRST"
                if self.commitments[other] is None
                else f"TR-COMMIT-{party.upper()}-COMPLETE"
            )
            require(
                self.phase == "COMMITMENTS_PENDING",
                "commitment requires budget reservation",
            )
            require(
                self.commitments[party] is None,
                "Party commitment slot is immutable",
            )
            if not findings:
                self.commitments[party] = payload.get("opaque_commitment")
                if all(self.commitments.values()):
                    require(
                        self.commitment_pair_id is None,
                        "commitment pair identifier is immutable",
                    )
                    if not findings:
                        session = self.base_context["session_context"]
                        self.commitment_pair_id = commitment_pair_digest(
                            protocol_profile=(
                                f"{message['protocol_profile']}/v{message['protocol_version']}"
                            ),
                            policy_binding=copy.deepcopy(session["policy"]),
                            session_id=session["session_id"],
                            participant_binding=copy.deepcopy(self.participants),
                            selected_integration_profile_binding=copy.deepcopy(
                                self.selected_integration_profile or {}
                            ),
                            commitment_a=str(self.commitments["a"]),
                            commitment_b=str(self.commitments["b"]),
                        )
                    self.phase = "COMMITTED"
        elif message_type == "evaluation_start":
            transition = "TR-START-EVALUATION"
            require(
                self.phase == "COMMITTED" and self.budget_reserved,
                "evaluation start requires committed pair and reserved budget",
            )
            require(
                self.evaluation_attempt_id is None, "evaluation attempt already fixed"
            )
            if not findings:
                self.evaluation_attempt_id = payload.get("evaluation_attempt_id")
                self.evaluation_deadline = payload.get("evaluation_deadline")
                self.evaluation_started = True
                self.query_budget_state = "CONSUMED"
                self.phase = "EVALUATING"
        elif message_type == "evaluation_contribution" and party:
            transition = f"TR-SUBMIT-CONTRIBUTION-{party.upper()}"
            require(self.phase == "EVALUATING", "contribution requires EVALUATING")
            require(
                self.contributions[party] is None,
                "Party contribution slot is immutable",
            )
            if not findings:
                self.contributions[party] = payload.get("contribution_ref")
        elif message_type == "opaque_receipt_ack" and party:
            transition = f"TR-ACK-RECEIPT-{party.upper()}"
            require(
                self.phase == "EVALUATING", "receipt acknowledgment requires EVALUATING"
            )
            require(
                all(self.contributions.values()),
                "receipt acknowledgment requires both evaluation contributions",
            )
            require(
                self.receipt_acks[party] is None,
                "Party receipt acknowledgment slot is immutable",
            )
            require(
                payload.get("acknowledgment_status") == "ACKNOWLEDGED",
                "Party receipt status must be ACKNOWLEDGED",
            )
            session_context = message.get("session_context", {})
            require(
                isinstance(session_context, dict)
                and session_context.get("session_id")
                == self.base_context.get("session_context", {}).get("session_id")
                and session_context.get("evaluation_attempt_id")
                == self.evaluation_attempt_id
                and session_context.get("selected_integration_profile")
                == self.selected_integration_profile,
                "Party receipt must bind the current session, profile, and attempt",
            )
            peer_ack = self.receipt_acks["b" if party == "a" else "a"]
            if peer_ack is not None:
                require(
                    payload.get("opaque_receipt_ref")
                    == peer_ack.get("opaque_receipt_ref"),
                    "Party opaque receipt references must match exactly",
                )
            if not findings:
                self.receipt_acks[party] = {
                    key: copy.deepcopy(payload.get(key))
                    for key in (
                        "opaque_receipt_ref",
                        "acknowledgment_status",
                        "profile_evidence_ref",
                    )
                }
        elif message_type == "result_acceptance_notice":
            transition = "TR-ACCEPT-SYMMETRIC-RESULT"
            require(
                self.phase == "EVALUATING" and all(self.receipt_acks.values()),
                "result acceptance requires bilateral acknowledgments",
            )
            ack_a, ack_b = self.receipt_acks["a"] or {}, self.receipt_acks["b"] or {}
            require(
                ack_a.get("opaque_receipt_ref")
                == ack_b.get("opaque_receipt_ref")
                == payload.get("opaque_receipt_ref"),
                "Party and callback opaque receipt references must match exactly",
            )
            require(
                ack_a.get("acknowledgment_status")
                == ack_b.get("acknowledgment_status")
                == "ACKNOWLEDGED"
                and payload.get("acknowledgment_status") == "BOTH_ACKNOWLEDGED",
                "callback requires two ACKNOWLEDGED Party records and BOTH_ACKNOWLEDGED status",
            )
            require(
                bool(payload.get("profile_evidence_ref")),
                "result callback requires an opaque profile evidence reference",
            )
            identity = message.get("identity", {})
            require(
                isinstance(identity, dict)
                and all(
                    identity.get(key)
                    == (self.selected_integration_profile or {}).get(key)
                    for key in (
                        "profile_id",
                        "profile_version",
                        "profile_instance_id",
                    )
                )
                and identity.get("session_id")
                == self.base_context.get("session_context", {}).get("session_id")
                and identity.get("evaluation_attempt_id") == self.evaluation_attempt_id,
                "result callback must bind the current profile, session, and attempt",
            )
            if not findings:
                self.accepted_receipt = {
                    key: copy.deepcopy(payload.get(key))
                    for key in (
                        "opaque_receipt_ref",
                        "acknowledgment_status",
                        "profile_evidence_ref",
                    )
                }
                self.phase = "RESULT_ACCEPTED"
        elif message_type == "consent_grant" and party:
            transition = f"TR-GRANT-CONSENT-{party.upper()}"
            require(
                self.phase in {"RESULT_ACCEPTED", "CONSENT_PENDING"},
                "consent requires accepted result",
            )
            require(
                self.accepted_receipt is not None
                and payload.get("opaque_receipt_ref")
                == self.accepted_receipt.get("opaque_receipt_ref"),
                "consent receipt must equal the accepted bilateral receipt",
            )
            require(
                self.consents[party] is None,
                "Party consent slot is immutable and cannot be reused",
            )
            issued = _parse_time(
                payload.get("issued_at"), f"{message_type}.issued_at", findings
            )
            expires = _parse_time(
                payload.get("expires_at"), f"{message_type}.expires_at", findings
            )
            authoritative = _parse_time(
                self.base_context.get("authoritative_time"),
                "context.authoritative_time",
                findings,
            )
            require(
                bool(issued and expires and authoritative)
                and issued < expires
                and issued <= authoritative < expires,
                "consent must be active at coordinator authoritative time",
            )
            other = self.consents["b" if party == "a" else "a"]
            if other is not None:
                for key in (
                    "disclosure_profile_id",
                    "disclosure_profile_version",
                    "scope",
                    "audience",
                ):
                    require(
                        payload.get(key) == other.get(key),
                        f"bilateral consent {key} must match exactly",
                    )
            if not findings:
                self.consents[party] = copy.deepcopy(payload)
                self.disclosure_state = "CONSENT_PENDING"
                self.phase = "CONSENT_PENDING"
        elif message_type == "close_notice":
            transition = "TR-CLOSE"
            require(
                self.phase not in {"UNINITIALIZED", "CLOSED", "ABORTED", "EXPIRED"},
                "close requires a live session",
            )
            if not findings:
                if (
                    self.query_budget_state == "RESERVED"
                    and not self.evaluation_started
                ):
                    self.query_budget_state = "RELEASED"
                self.disclosure_state = "NONE"
                self.phase = "CLOSED"
        else:
            findings.append(
                _finding(
                    "state-trace",
                    message_type,
                    "message is not part of the positive state trace",
                )
            )

        entry = _registry_index(registry).get(message_type, {})
        if transition and transition not in entry.get("state_machine", {}).get(
            "transitions", []
        ):
            findings.append(
                _finding(
                    "state-trace-mapping",
                    message_type,
                    f"registry does not map enabled transition {transition}",
                )
            )
        if party and message.get("delivery_class") == "party_message":
            identity = message.get("identity", {})
            require(
                identity.get("sequence") == self.next_sequence[party],
                "Party sequence does not equal current next_sequence",
            )
            if not findings:
                self.next_sequence[party] += 1
        if findings:
            self.__dict__.clear()
            self.__dict__.update(before)
        return sorted(set(findings))


def trace_message_preflight_findings(
    message: dict[str, Any], message_schema: dict[str, Any]
) -> list[Finding]:
    """Validate schema and canonical digests before authoritative dedup lookup.

    The caller must have obtained ``message`` through strict JSON parsing.  This
    preflight intentionally excludes current clock, material-status, phase, and
    transcript-head gates so an already accepted exact record can reach its
    cached-response path.  New messages still receive every dynamic check below.
    """

    findings: list[Finding] = []
    for error in Draft202012Validator(
        message_schema, format_checker=FormatChecker()
    ).iter_errors(message):
        findings.append(
            _finding(
                "message-schema",
                ".".join(str(item) for item in error.absolute_path) or "message",
                bounded_error(error.message),
            )
        )
    if findings:
        return sorted(set(findings))
    try:
        canonicalize(message)
        if message.get("payload_digest") != payload_digest(message.get("payload")):
            findings.append(
                _finding("payload-digest", "message.payload_digest", "digest mismatch")
            )
        if message.get("message_digest") != message_digest(message):
            findings.append(
                _finding("message-digest", "message.message_digest", "digest mismatch")
            )
    except CanonicalMessageError as error:
        findings.append(_finding("canonicalization", "message", bounded_error(error)))
    return sorted(set(findings))


def _epoch_microseconds(value: Any, path: str, findings: list[Finding]) -> int | None:
    parsed = _parse_time(value, path, findings)
    return int(parsed.timestamp() * 1_000_000) if parsed is not None else None


def apply_timer_to_runner(
    runner: AbstractStateRunner, event: dict[str, Any]
) -> tuple[str, str | None, list[Finding]]:
    """Derive and apply exactly one reviewed timer relation to ``runner``.

    The caller operates on a copy.  Deadline precedence is session expiry,
    evaluation timeout, consent expiry, then a normal live advance.  A caller's
    reason class must describe the derived effect and cannot select it.
    """

    before = copy.deepcopy(runner.__dict__)
    findings: list[Finding] = []
    session_id = runner.base_context.get("session_context", {}).get("session_id")
    if event.get("session_id") != session_id:
        findings.append(
            _finding("timer-session", "timer.session_id", "active session mismatch")
        )
    current = _epoch_microseconds(
        runner.authoritative_time, "runner.authoritative_time", findings
    )
    proposed = _epoch_microseconds(
        event.get("new_authoritative_time"),
        "timer.new_authoritative_time",
        findings,
    )
    expiry = _epoch_microseconds(
        runner.session_expires_at, "runner.session_expires_at", findings
    )
    deadline = (
        _epoch_microseconds(
            runner.evaluation_deadline, "runner.evaluation_deadline", findings
        )
        if runner.evaluation_deadline is not None
        else None
    )
    maximum_jump = runner.maximum_time_jump_seconds
    if (
        not isinstance(maximum_jump, int)
        or isinstance(maximum_jump, bool)
        or maximum_jump < 0
    ):
        findings.append(
            _finding(
                "timer-policy",
                "runner.maximum_time_jump_seconds",
                "reviewed non-negative maximum jump is required",
            )
        )
    consent_state: dict[str, dict[str, Any]] = {}
    for party, consent in runner.consents.items():
        if not isinstance(consent, dict):
            continue
        consent_expiry = _epoch_microseconds(
            consent.get("expires_at"), f"runner.consent.{party}.expires_at", findings
        )
        consent_state[party] = {"status": "valid", "expires_at": consent_expiry}
    if findings or current is None or proposed is None or expiry is None:
        runner.__dict__.clear()
        runner.__dict__.update(before)
        return "REJECTED", None, sorted(set(findings))

    state = {
        "authoritative_time": current,
        "session_expires_at": expiry,
        "evaluation_deadline": deadline,
        "phase": runner.phase,
        "consent": consent_state,
        "query_budget_state": runner.query_budget_state,
        "evaluation_started": runner.evaluation_started,
        "disclosure_state": runner.disclosure_state,
        "terminal_failure_code": runner.terminal_failure_code,
        "party_terminal_category": runner.party_terminal_category,
    }
    updated, failure_codes = authoritative_time_transition(
        state, proposed, maximum_jump * 1_000_000
    )
    if failure_codes:
        findings.extend(
            _finding("timer-state", "timer.new_authoritative_time", code)
            for code in failure_codes
        )
        runner.__dict__.clear()
        runner.__dict__.update(before)
        return "REJECTED", None, sorted(set(findings))

    if proposed == current:
        transition = "TR-ADVANCE-TIME-NOOP"
        outcome = "NO_OP"
        expected_reason = "COORDINATOR_CLOCK"
    elif updated.get("terminal_failure_code") == "SESSION_EXPIRED":
        transition = "TR-ADVANCE-TIME-EXPIRE"
        outcome = "ACCEPTED"
        expected_reason = "SESSION_EXPIRY_THRESHOLD"
    elif updated.get("terminal_failure_code") == "EVALUATION_TIMEOUT":
        transition = "TR-EVALUATION-TIMEOUT"
        outcome = "ACCEPTED"
        expected_reason = "EVALUATION_DEADLINE"
    elif updated.get("terminal_failure_code") == "CONSENT_EXPIRED":
        transition = "TR-CONSENT-EXPIRED"
        outcome = "ACCEPTED"
        expected_reason = "CONSENT_EXPIRY_THRESHOLD"
    else:
        transition = "TR-ADVANCE-TIME-LIVE"
        outcome = "ACCEPTED"
        expected_reason = "COORDINATOR_CLOCK"
    if event.get("reason_or_source_class") != expected_reason:
        findings.append(
            _finding(
                "timer-reason-effect",
                "timer.reason_or_source_class",
                f"derived {transition} requires {expected_reason}",
            )
        )
        runner.__dict__.clear()
        runner.__dict__.update(before)
        return "REJECTED", None, sorted(set(findings))
    if outcome == "NO_OP":
        runner.__dict__.clear()
        runner.__dict__.update(before)
        return outcome, transition, []

    runner.authoritative_time = str(event["new_authoritative_time"])
    runner.base_context["authoritative_time"] = runner.authoritative_time
    runner.phase = str(updated.get("phase", runner.phase))
    runner.query_budget_state = str(
        updated.get("query_budget_state", runner.query_budget_state)
    )
    runner.disclosure_state = str(
        updated.get("disclosure_state", runner.disclosure_state)
    )
    runner.terminal_failure_code = str(
        updated.get("terminal_failure_code", runner.terminal_failure_code)
    )
    runner.party_terminal_category = str(
        updated.get("party_terminal_category", runner.party_terminal_category)
    )
    runner.audit_lifecycle.append(transition)
    return outcome, transition, []


def apply_trace_timer_atomically(
    runner: AbstractStateRunner,
    transcript: TranscriptState,
    event: dict[str, Any],
    timer_schema: dict[str, Any],
) -> tuple[str, str | None, list[Finding]]:
    """Validate and commit runner plus timer transcript as one transaction."""

    findings = [
        _finding(
            "timer-schema",
            ".".join(str(item) for item in error.absolute_path) or "timer",
            bounded_error(error.message),
        )
        for error in Draft202012Validator(
            timer_schema, format_checker=FormatChecker()
        ).iter_errors(event)
    ]
    if findings:
        return "REJECTED", None, sorted(set(findings))
    if event.get("prior_transcript_digest") != transcript.head:
        return "PRIOR_TRANSCRIPT_MISMATCH", None, []

    candidate_runner = copy.deepcopy(runner)
    outcome, transition, timer_findings = apply_timer_to_runner(candidate_runner, event)
    if timer_findings or outcome == "REJECTED":
        return "REJECTED", transition, timer_findings
    if outcome == "NO_OP":
        return outcome, transition, []

    candidate_transcript = copy.deepcopy(transcript)
    try:
        transcript_outcome = candidate_transcript.accept_timer(event)
    except CanonicalMessageError as error:
        return (
            "REJECTED",
            transition,
            [_finding("timer-canonicalization", "timer", bounded_error(error))],
        )
    if transcript_outcome != "ACCEPTED":
        return transcript_outcome, transition, []
    runner.__dict__.clear()
    runner.__dict__.update(candidate_runner.__dict__)
    transcript.__dict__.clear()
    transcript.__dict__.update(candidate_transcript.__dict__)
    return "ACCEPTED", transition, []


def apply_trace_message_atomically(
    runner: AbstractStateRunner,
    transcript: TranscriptState,
    message: dict[str, Any],
    message_schema: dict[str, Any],
    registry: dict[str, Any],
    materials: dict[str, Any],
) -> tuple[str, list[Finding]]:
    """Validate in replay-safe order, then apply one abstract transaction.

    Strict parsing occurs at the bytes boundary.  Schema and digest preflight
    precede authoritative accepted-record lookup.  Exact accepted duplicates
    bypass current prior-head, time, material, and phase gates and only expose
    their sender/actor-scoped cached response; conflicts and rejects are no-op.
    """

    preflight = trace_message_preflight_findings(message, message_schema)
    if preflight:
        return "REJECTED", preflight

    classification = transcript.dedup.classify(message, commit=False)
    if classification == "EXACT_DUPLICATE":
        sender = message.get("sender", {})
        response = transcript.dedup.cached_response(
            message,
            requester_actor=str(sender.get("actor")),
            requester_participant_id=sender.get("participant_id"),
        )
        if response is None:
            return "REPLAY_CONFLICT", []
        return "EXACT_DUPLICATE", []
    if classification in {"REPLAY_CONFLICT", "EXCLUDED"}:
        return transcript.accept_message(message), []

    dynamic_findings = semantic_message_findings(
        message,
        registry,
        materials,
        runner.context(transcript.head),
    )
    if dynamic_findings:
        return "REJECTED", dynamic_findings
    candidate_runner = copy.deepcopy(runner)
    findings = candidate_runner.apply(message, registry, materials)
    if findings:
        return "REJECTED", findings
    candidate_transcript = copy.deepcopy(transcript)
    outcome = candidate_transcript.accept_message(message)
    if outcome != "ACCEPTED":
        return outcome, []
    runner.__dict__.clear()
    runner.__dict__.update(candidate_runner.__dict__)
    transcript.__dict__.clear()
    transcript.__dict__.update(candidate_transcript.__dict__)
    return outcome, []


def registry_findings(
    registry: dict[str, Any],
    state_machine: dict[str, Any],
    message_schema: dict[str, Any] | None = None,
) -> list[Finding]:
    findings: list[Finding] = []
    messages = registry.get("messages", [])
    names = [item.get("message_type") for item in messages if isinstance(item, dict)]
    identities = [
        (item.get("message_type"), item.get("message_version"))
        for item in messages
        if isinstance(item, dict)
    ]
    duplicates = sorted(
        {identity for identity in identities if identities.count(identity) > 1}
    )
    for message_type, version in duplicates:
        findings.append(
            _finding(
                "registry-duplicate",
                "registry.messages",
                f"duplicate message type/version {message_type} {version}",
            )
        )
    event_index = {item.get("id"): item for item in state_machine.get("events", [])}
    transition_index = {
        item.get("id"): item for item in state_machine.get("transitions", [])
    }
    parameter_catalog = {
        item.get("id"): {field.get("id") for field in item.get("fields", [])}
        for item in state_machine.get("event_parameter_catalog", [])
    }
    if message_schema is not None:
        schema_names = set(
            message_schema.get("properties", {}).get("message_type", {}).get("enum", [])
        )
        if schema_names != set(names):
            findings.append(
                _finding(
                    "registry-schema-mapping",
                    "registry.messages",
                    "registry and envelope message-type sets differ",
                )
            )
    covered: dict[str, set[str]] = {
        key: set()
        for key in ("party_message", "coordinator_command", "profile_callback")
    }
    for item in messages:
        delivery = item.get("delivery_class")
        required_payload = set(item.get("payload", {}).get("required_fields", []))
        expected_payload_sources = {f"payload.{field}" for field in required_payload}
        if item.get("message_type") == "session_proposal":
            expected_payload_sources.remove("payload.clock_policy")
            expected_payload_sources.update(
                {
                    "payload.clock_policy.allowed_clock_skew_seconds",
                    "payload.clock_policy.message_stale_threshold_seconds",
                    "payload.clock_policy.evaluation_timeout_seconds",
                    "payload.clock_policy.maximum_time_jump_seconds",
                }
            )
        expected_sources = {
            *expected_payload_sources,
            "message.message_digest",
            "message.prior_transcript_digest",
        }
        common_message_sources = {
            "message.protocol_profile",
            "message.issued_at",
            "message.session_context.session_id",
            "message.session_context.policy",
            "message.session_context.participants",
            "message.session_context.intended_audience",
            "message.session_context.commitment_pair_id",
            "message.session_context.evaluation_attempt_id",
            "message.session_context.selected_integration_profile",
        }
        identity_sources = {
            "party_message": {
                f"message.identity.{field}"
                for field in (
                    "sender_participant_id",
                    "message_id",
                    "nonce",
                    "sequence",
                    "issued_at",
                )
            },
            "coordinator_command": {
                f"message.identity.{field}"
                for field in ("actor_id", "operation_id", "idempotency_key")
            },
            "profile_callback": {
                f"message.identity.{field}"
                for field in (
                    "profile_id",
                    "profile_version",
                    "profile_instance_id",
                    "callback_id",
                    "idempotency_key",
                    "session_id",
                    "evaluation_attempt_id",
                )
            },
            "derived_transition": set(),
        }
        allowed_sources = (
            expected_sources
            | common_message_sources
            | identity_sources.get(str(delivery), set())
            | {"absent.party_local_result"}
        )
        if item.get("message_type") in {"session_acceptance", "participant_binding"}:
            allowed_sources |= TRUSTED_SUBJECT_SOURCES
        observed_sources: list[str] = []
        observed_destinations: list[str] = []
        for mapping in item.get("parameter_sources", []):
            if not isinstance(mapping, dict):
                findings.append(
                    _finding(
                        "parameter-mapping",
                        str(item.get("message_type")),
                        "parameter source must use the structured mapping contract",
                    )
                )
                continue
            source = mapping.get("source")
            destination = mapping.get("destination")
            if not isinstance(source, str) or not isinstance(destination, dict):
                findings.append(
                    _finding(
                        "parameter-mapping",
                        str(item.get("message_type")),
                        "mapping source and destination must be declared",
                    )
                )
                continue
            observed_sources.append(source)
            if destination.get("kind") == "event-parameter":
                parameter = destination.get("parameter")
                field_name = destination.get("field")
                destination_path = f"{parameter}.{field_name}"
                observed_destinations.append(destination_path)
                if field_name not in parameter_catalog.get(parameter, set()):
                    findings.append(
                        _finding(
                            "parameter-mapping-destination",
                            str(item.get("message_type")),
                            f"unknown State Machine parameter path {destination_path}",
                        )
                    )
                declared_events = [
                    event_index.get(event_id, {})
                    for event_id in item.get("state_machine", {}).get("events", [])
                ]
                if not any(
                    parameter in event.get("parameters", [])
                    for event in declared_events
                ):
                    findings.append(
                        _finding(
                            "parameter-mapping-destination",
                            str(item.get("message_type")),
                            f"mapped events do not declare {parameter}",
                        )
                    )
                for consumer in destination.get("consumed_by", []):
                    transition_id = consumer.get("transition")
                    operation_id = consumer.get("operation")
                    transition = transition_index.get(transition_id, {})
                    operations = transition.get("guards", []) + transition.get(
                        "effects", []
                    )
                    operation = next(
                        (
                            entry
                            for entry in operations
                            if entry.get("id") == operation_id
                        ),
                        None,
                    )
                    if (
                        transition_id
                        not in item.get("state_machine", {}).get("transitions", [])
                        or operation is None
                        or destination_path not in operation.get("parameter_reads", [])
                    ):
                        findings.append(
                            _finding(
                                "parameter-mapping-destination",
                                str(item.get("message_type")),
                                f"{destination_path} is not consumed by {transition_id}/{operation_id}",
                            )
                        )
            elif destination.get("kind") != "special":
                findings.append(
                    _finding(
                        "parameter-mapping-destination",
                        str(item.get("message_type")),
                        "destination kind must be event-parameter or reviewed special",
                    )
                )
        observed_contract_sources = {
            source
            for source in observed_sources
            if source.startswith("payload.") or source.startswith("message.")
        }
        unknown_auxiliary_sources = {
            source
            for source in observed_sources
            if not source.startswith(("payload.", "message."))
            and source != "absent.party_local_result"
            and source not in TRUSTED_SUBJECT_SOURCES
        }
        protected_result_marker = "absent.party_local_result" in observed_sources
        protected_result_marker_invalid = protected_result_marker != (
            item.get("message_type") == "opaque_receipt_ack"
        )
        if (
            not expected_sources.issubset(observed_contract_sources)
            or set(observed_sources) - allowed_sources
            or unknown_auxiliary_sources
            or protected_result_marker_invalid
        ):
            findings.append(
                _finding(
                    "parameter-mapping",
                    str(item.get("message_type")),
                    "required payload/digest sources must be mapped exactly once",
                )
            )
        declared_parameters = {
            parameter
            for event_id in item.get("state_machine", {}).get("events", [])
            for parameter in event_index.get(event_id, {}).get("parameters", [])
        }
        required_state_paths = {
            parameter_path
            for transition_id in item.get("state_machine", {}).get("transitions", [])
            for operation in (
                transition_index.get(transition_id, {}).get("guards", [])
                + transition_index.get(transition_id, {}).get("effects", [])
            )
            for parameter_path in operation.get("parameter_reads", [])
            if parameter_path.split(".", 1)[0] in declared_parameters
        }
        mapped_state_paths = set(observed_destinations)
        if protected_result_marker:
            mapped_state_paths.add("local_result_parameter.local_result")
        missing_state_paths = (
            sorted(required_state_paths - mapped_state_paths)
            if delivery != "derived_transition"
            else []
        )
        if missing_state_paths:
            findings.append(
                _finding(
                    "parameter-mapping-destination",
                    str(item.get("message_type")),
                    "required State Machine destinations are unmapped: "
                    + ", ".join(missing_state_paths),
                )
            )
        if len(observed_destinations) != len(set(observed_destinations)):
            findings.append(
                _finding(
                    "parameter-mapping-destination",
                    str(item.get("message_type")),
                    "event-parameter destination must be mapped exactly once",
                )
            )
        runner_required = RUNNER_SECURITY_PARAMETER_READS.get(
            str(item.get("message_type")), set()
        )
        missing_runner_paths = sorted(runner_required - mapped_state_paths)
        if missing_runner_paths:
            findings.append(
                _finding(
                    "state-runner-mapping",
                    str(item.get("message_type")),
                    "security-relevant State Machine destinations are not executed: "
                    + ", ".join(missing_runner_paths),
                )
            )
        if message_schema is not None:
            definition = message_schema.get("$defs", {}).get(
                f"payload_{item.get('message_type')}", {}
            )
            if (
                set(definition.get("required", [])) != required_payload
                or definition.get("additionalProperties") is not False
            ):
                findings.append(
                    _finding(
                        "registry-schema-mapping",
                        str(item.get("message_type")),
                        "registry payload fields differ from the strict payload schema",
                    )
                )
        for event_id in item.get("state_machine", {}).get("events", []):
            event = event_index.get(event_id)
            if event is None:
                findings.append(
                    _finding(
                        "state-mapping",
                        str(item.get("message_type")),
                        f"unknown event {event_id}",
                    )
                )
            elif (
                event.get("delivery_class") != delivery
                and delivery != "derived_transition"
            ):
                findings.append(
                    _finding(
                        "state-mapping",
                        str(item.get("message_type")),
                        f"delivery class differs from {event_id}",
                    )
                )
            if delivery in covered:
                covered[delivery].add(str(event_id))
        for transition_id in item.get("state_machine", {}).get("transitions", []):
            transition = transition_index.get(transition_id)
            if transition is None:
                findings.append(
                    _finding(
                        "state-mapping",
                        str(item.get("message_type")),
                        f"unknown transition {transition_id}",
                    )
                )
            elif transition.get("event") not in item.get("state_machine", {}).get(
                "events", []
            ):
                findings.append(
                    _finding(
                        "state-mapping",
                        str(item.get("message_type")),
                        f"transition {transition_id} event is not mapped",
                    )
                )
    retry_events = {
        "retry_idempotent_message",
        "retry_idempotent_operation",
        "retry_idempotent_profile_callback",
    }
    for delivery in covered:
        expected = {
            event_id
            for event_id, event in event_index.items()
            if event.get("delivery_class") == delivery and event_id not in retry_events
        }
        missing = sorted(expected - covered[delivery])
        if missing:
            findings.append(
                _finding(
                    "state-mapping",
                    f"registry.{delivery}",
                    "unmapped events: " + ", ".join(missing),
                )
            )
    internal_items = registry.get("internal_event_contracts", [])
    internal_ids = [item.get("id") for item in internal_items if isinstance(item, dict)]
    for identifier in sorted(
        {
            identifier
            for identifier in internal_ids
            if internal_ids.count(identifier) > 1
        }
    ):
        findings.append(
            _finding(
                "registry-duplicate",
                "registry.internal_event_contracts",
                f"duplicate internal event contract {identifier}",
            )
        )
    internal = {
        key[0]: value for key, value in _unique_index(internal_items, ("id",)).items()
    }
    if set(internal) != {
        "authoritative_timer_event",
        "reject_message_relation",
        "new_session_guidance",
    }:
        findings.append(
            _finding(
                "state-mapping",
                "registry.internal_event_contracts",
                "timer/derived/local contracts must be explicit",
            )
        )
    return sorted(set(findings))


def material_registry_findings(materials: dict[str, Any]) -> list[Finding]:
    """Reject duplicate semantic identities before authorization lookup."""

    findings: list[Finding] = []
    items = [item for item in materials.get("materials", []) if isinstance(item, dict)]
    for identity_field in ("verification_material_id", "subject_binding_id"):
        values = [item.get(identity_field) for item in items]
        for value in sorted({value for value in values if values.count(value) > 1}):
            findings.append(
                _finding(
                    "material-duplicate",
                    "verification-materials.materials",
                    f"duplicate {identity_field} {value}",
                )
            )
    return sorted(set(findings))


def validate_message_bytes(
    raw: bytes,
    schema: dict[str, Any],
    registry: dict[str, Any],
    materials: dict[str, Any],
    context: dict[str, Any],
    *,
    path: str,
    require_canonical: bool = True,
    require_context_prior: bool = True,
) -> tuple[dict[str, Any] | None, list[Finding]]:
    try:
        value = strict_loads(raw)
    except CanonicalMessageError as error:
        return None, [_finding("json-parse", path, bounded_error(error))]
    if not isinstance(value, dict):
        return None, [_finding("schema", path, "message must be a JSON object")]
    findings: list[Finding] = []
    if require_canonical:
        try:
            if raw != canonicalize(value):
                findings.append(
                    _finding(
                        "noncanonical-json",
                        path,
                        "wire bytes are not exact RFC 8785 JSON",
                    )
                )
        except CanonicalMessageError as error:
            findings.append(_finding("canonicalization", path, bounded_error(error)))
    findings.extend(_schema_findings(value, schema, path))
    findings.extend(
        semantic_message_findings(
            value,
            registry,
            materials,
            context,
            path=path,
            require_context_prior=require_context_prior,
        )
    )
    return value, sorted(set(findings))


def validate_repository(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    loaded: dict[str, Any] = {}
    for name, relative, loader in (
        ("message_schema", MESSAGE_SCHEMA, _load_json),
        ("timer_schema", TIMER_SCHEMA, _load_json),
        ("registry_schema", REGISTRY_SCHEMA, _load_json),
        ("material_schema", MATERIAL_SCHEMA, _load_json),
        ("registry", REGISTRY_PATH, _load_yaml),
        ("materials", MATERIAL_PATH, _load_yaml),
        ("context", CONTEXT_PATH, _load_yaml),
        ("state_machine", STATE_MACHINE_PATH, _load_yaml),
    ):
        value, load_findings = loader(root / relative)
        findings.extend(load_findings)
        if value is not None:
            loaded[name] = value
    if findings:
        return sorted(set(findings))
    for schema_name in (
        "message_schema",
        "timer_schema",
        "registry_schema",
        "material_schema",
    ):
        try:
            Draft202012Validator.check_schema(loaded[schema_name])
        except SchemaError as error:
            findings.append(_finding("schema-self", schema_name, bounded_error(error)))
    findings.extend(
        _schema_findings(loaded["registry"], loaded["registry_schema"], "registry")
    )
    findings.extend(
        _schema_findings(
            loaded["materials"], loaded["material_schema"], "verification-materials"
        )
    )
    findings.extend(material_registry_findings(loaded["materials"]))
    findings.extend(
        registry_findings(
            loaded["registry"],
            loaded["state_machine"],
            loaded["message_schema"],
        )
    )

    valid_dir = root / "conformance/messages/valid"
    for path in sorted(valid_dir.glob("*.json")):
        value, value_errors = _load_json(path)
        findings.extend(value_errors)
        vector_context = copy.deepcopy(loaded["context"])
        if isinstance(value, dict) and isinstance(value.get("session_context"), dict):
            # Standalone vectors declare their explicit pre-transition stage.
            # The authoritative evolving chain below is validated separately.
            vector_context["session_context"] = copy.deepcopy(value["session_context"])
            vector_context["prior_transcript_digest"] = value["prior_transcript_digest"]
        _, vector_findings = validate_message_bytes(
            path.read_bytes(),
            loaded["message_schema"],
            loaded["registry"],
            loaded["materials"],
            vector_context,
            path=str(path.relative_to(root)),
        )
        findings.extend(vector_findings)

    manifest, load_findings = _load_yaml(root / INVALID_MANIFEST)
    findings.extend(load_findings)
    if isinstance(manifest, dict):
        for case in manifest.get("cases", []):
            path = root / "conformance/messages/invalid" / case["file"]
            invalid_context = copy.deepcopy(loaded["context"])
            context_reference, context_errors = _load_json(
                root / "conformance/messages/valid" / case["context_file"]
            )
            findings.extend(context_errors)
            if isinstance(context_reference, dict):
                invalid_context["session_context"] = copy.deepcopy(
                    context_reference["session_context"]
                )
                invalid_context["prior_transcript_digest"] = context_reference[
                    "prior_transcript_digest"
                ]
            _, case_findings = validate_message_bytes(
                path.read_bytes(),
                loaded["message_schema"],
                loaded["registry"],
                loaded["materials"],
                invalid_context,
                path=str(path.relative_to(root)),
                require_context_prior=True,
            )
            codes = {finding.code for finding in case_findings}
            if case["expected_code"] not in codes:
                findings.append(
                    _finding(
                        "negative-vector",
                        str(path.relative_to(root)),
                        f"expected {case['expected_code']}; observed {', '.join(sorted(codes)) or 'no error'}",
                    )
                )

    expected, digest_findings = _load_json(root / EXPECTED_DIGESTS)
    findings.extend(digest_findings)
    if isinstance(expected, dict):
        state = TranscriptState()
        runner = AbstractStateRunner(copy.deepcopy(loaded["context"]))
        if expected.get("genesis_digest") != state.head:
            findings.append(
                _finding("transcript-digest", str(EXPECTED_DIGESTS), "genesis mismatch")
            )
        for index, entry in enumerate(expected.get("entries", []), 1):
            if entry.get("kind") == "message":
                message = entry["message"]
                outcome, trace_findings = apply_trace_message_atomically(
                    runner,
                    state,
                    message,
                    loaded["message_schema"],
                    loaded["registry"],
                    loaded["materials"],
                )
                findings.extend(trace_findings)
            else:
                outcome, _, timer_findings = apply_trace_timer_atomically(
                    runner,
                    state,
                    entry["timer_event"],
                    loaded["timer_schema"],
                )
                findings.extend(timer_findings)
            if (
                outcome != "ACCEPTED"
                or entry.get("expected_head") != state.head
                or entry.get("accepted_event_index") != index
            ):
                findings.append(
                    _finding(
                        "transcript-digest",
                        f"{EXPECTED_DIGESTS}.entries.{index - 1}",
                        f"chain mismatch ({outcome})",
                    )
                )
        if expected.get("final_head") != state.head:
            findings.append(
                _finding(
                    "transcript-digest", str(EXPECTED_DIGESTS), "final head mismatch"
                )
            )

    return sorted(set(findings))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--file", type=Path)
    args = parser.parse_args(argv)
    root = args.root.resolve()
    if args.file:
        dependencies: dict[str, Any] = {}
        for name, relative, loader in (
            ("schema", MESSAGE_SCHEMA, _load_json),
            ("registry", REGISTRY_PATH, _load_yaml),
            ("materials", MATERIAL_PATH, _load_yaml),
            ("context", CONTEXT_PATH, _load_yaml),
        ):
            value, errors = loader(root / relative)
            if errors:
                for error in errors:
                    print(f"message-contract: error: {error}")
                return 1
            dependencies[name] = value
        file_path = args.file if args.file.is_absolute() else root / args.file
        try:
            raw = file_path.read_bytes()
        except OSError as error:
            print(f"message-contract: error: {bounded_error(error)}")
            return 1
        _, findings = validate_message_bytes(raw, path=str(file_path), **dependencies)
    else:
        findings = validate_repository(root)
    for finding in findings:
        print(f"message-contract: error: {finding}")
    if findings:
        print(f"message-contract: {len(findings)} error(s)")
        return 1
    print("message-contract: valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
