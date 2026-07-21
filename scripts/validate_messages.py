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
    message_digest,
    payload_digest,
    strict_loads,
    timer_event_digest,
    transcript_genesis_digest,
)


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
        return yaml.safe_load(path.read_text(encoding="utf-8")), []
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


def _registry_index(registry: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        item["message_type"]: item
        for item in registry.get("messages", [])
        if isinstance(item, dict) and isinstance(item.get("message_type"), str)
    }


def _material_index(materials: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        item["verification_material_id"]: item
        for item in materials.get("materials", [])
        if isinstance(item, dict)
        and isinstance(item.get("verification_material_id"), str)
    }


def semantic_message_findings(
    message: dict[str, Any],
    registry: dict[str, Any],
    materials: dict[str, Any],
    context: dict[str, Any],
    *,
    path: str = "message",
    require_context_prior: bool = True,
) -> list[Finding]:
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
            expected_party = participants.get(party_slot, {}) if party_slot else {}
            if sender.get("participant_id") != expected_party.get("participant_id"):
                findings.append(
                    _finding(
                        "participant-binding",
                        f"{path}.sender.participant_id",
                        "participant mismatch",
                    )
                )
            if sender.get("key_id") != expected_party.get("key_id"):
                findings.append(
                    _finding(
                        "key-binding", f"{path}.sender.key_id", "Party key mismatch"
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
            if sender_actor not in material.get("allowed_senders", []):
                findings.append(
                    _finding(
                        "verification-material",
                        f"{path}.sender.actor",
                        "material is not authorized for sender",
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

    return sorted(set(findings))


@dataclass
class DedupRegistry:
    party_by_id: dict[tuple[str, str, str], tuple[str, str, str]] = field(
        default_factory=dict
    )
    party_by_nonce: dict[tuple[str, str, str], tuple[str, str, str]] = field(
        default_factory=dict
    )
    operation_by_id: dict[tuple[str, str], tuple[str, str]] = field(
        default_factory=dict
    )
    operation_by_key: dict[tuple[str, str], tuple[str, str]] = field(
        default_factory=dict
    )
    callback_by_id: dict[tuple[str, ...], tuple[str, str]] = field(default_factory=dict)
    callback_by_key: dict[tuple[str, ...], tuple[str, str]] = field(
        default_factory=dict
    )

    def classify(self, message: dict[str, Any], *, commit: bool = True) -> str:
        delivery = message["delivery_class"]
        identity = message["identity"]
        digest = message["message_digest"]
        if delivery == "party_message":
            domain = (
                message["session_context"]["session_id"],
                identity["sender_participant_id"],
            )
            by_id_key = (*domain, identity["message_id"])
            by_nonce_key = (*domain, identity["nonce"])
            record = (identity["nonce"], identity["issued_at"], digest)
            inverse = (identity["message_id"], identity["issued_at"], digest)
            old_id = self.party_by_id.get(by_id_key)
            old_nonce = self.party_by_nonce.get(by_nonce_key)
            if old_id is None and old_nonce is None:
                if commit:
                    self.party_by_id[by_id_key] = record
                    self.party_by_nonce[by_nonce_key] = inverse
                return "ACCEPTED"
            if old_id == record and old_nonce == inverse:
                return "EXACT_DUPLICATE"
            return "REPLAY_CONFLICT"
        if delivery == "coordinator_command":
            actor = identity["actor_id"]
            id_key = (actor, identity["operation_id"])
            idem_key = (actor, identity["idempotency_key"])
            id_record = (identity["idempotency_key"], digest)
            key_record = (identity["operation_id"], digest)
            old_id, old_key = (
                self.operation_by_id.get(id_key),
                self.operation_by_key.get(idem_key),
            )
            if old_id is None and old_key is None:
                if commit:
                    self.operation_by_id[id_key] = id_record
                    self.operation_by_key[idem_key] = key_record
                return "ACCEPTED"
            if old_id == id_record and old_key == key_record:
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
            id_record = (identity["idempotency_key"], digest)
            key_record = (identity["callback_id"], digest)
            old_id, old_key = (
                self.callback_by_id.get(id_key),
                self.callback_by_key.get(idem_key),
            )
            if old_id is None and old_key is None:
                if commit:
                    self.callback_by_id[id_key] = id_record
                    self.callback_by_key[idem_key] = key_record
                return "ACCEPTED"
            if old_id == id_record and old_key == key_record:
                return "EXACT_DUPLICATE"
            return "REPLAY_CONFLICT"
        # Derived notices are outbound projections, not accepted mutations.
        return "EXCLUDED"


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
        if not mutates:
            return "NO_OP"
        if event["prior_transcript_digest"] != self.head:
            return "PRIOR_TRANSCRIPT_MISMATCH"
        self.accepted_event_index += 1
        self.head = append_transcript(
            self.head, self.accepted_event_index, timer_event_digest(event)
        )
        return "ACCEPTED"


def registry_findings(
    registry: dict[str, Any],
    state_machine: dict[str, Any],
    message_schema: dict[str, Any] | None = None,
) -> list[Finding]:
    findings: list[Finding] = []
    messages = registry.get("messages", [])
    names = [item.get("message_type") for item in messages if isinstance(item, dict)]
    duplicates = sorted({name for name in names if names.count(name) > 1})
    for name in duplicates:
        findings.append(_finding("registry-duplicate", "registry.messages", str(name)))
    event_index = {item.get("id"): item for item in state_machine.get("events", [])}
    transition_index = {
        item.get("id"): item for item in state_machine.get("transitions", [])
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
        expected_sources = {
            *(f"payload.{field}" for field in required_payload),
            "message.message_digest",
            "message.prior_transcript_digest",
        }
        observed_sources: list[str] = []
        for mapping in item.get("parameter_sources", []):
            if not isinstance(mapping, str) or mapping.count(" -> ") != 1:
                findings.append(
                    _finding(
                        "parameter-mapping",
                        str(item.get("message_type")),
                        "parameter source must use one 'source -> destination' mapping",
                    )
                )
                continue
            source, destination = mapping.split(" -> ", 1)
            observed_sources.append(source)
            if not source or not destination:
                findings.append(
                    _finding(
                        "parameter-mapping",
                        str(item.get("message_type")),
                        "parameter mapping source and destination must be nonempty",
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
        }
        protected_result_marker = "absent.party_local_result" in observed_sources
        protected_result_marker_invalid = protected_result_marker != (
            item.get("message_type") == "opaque_receipt_ack"
        )
        if (
            observed_contract_sources != expected_sources
            or len(observed_sources) != len(set(observed_sources))
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
    internal = {
        item.get("id"): item for item in registry.get("internal_event_contracts", [])
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
    findings.extend(
        registry_findings(
            loaded["registry"],
            loaded["state_machine"],
            loaded["message_schema"],
        )
    )

    valid_dir = root / "conformance/messages/valid"
    for path in sorted(valid_dir.glob("*.json")):
        _, vector_findings = validate_message_bytes(
            path.read_bytes(),
            loaded["message_schema"],
            loaded["registry"],
            loaded["materials"],
            loaded["context"],
            path=str(path.relative_to(root)),
        )
        findings.extend(vector_findings)

    manifest, load_findings = _load_yaml(root / INVALID_MANIFEST)
    findings.extend(load_findings)
    if isinstance(manifest, dict):
        for case in manifest.get("cases", []):
            path = root / "conformance/messages/invalid" / case["file"]
            _, case_findings = validate_message_bytes(
                path.read_bytes(),
                loaded["message_schema"],
                loaded["registry"],
                loaded["materials"],
                loaded["context"],
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
        if expected.get("genesis_digest") != state.head:
            findings.append(
                _finding("transcript-digest", str(EXPECTED_DIGESTS), "genesis mismatch")
            )
        for index, entry in enumerate(expected.get("entries", []), 1):
            if entry.get("kind") == "message":
                outcome = state.accept_message(entry["message"])
            else:
                outcome = state.accept_timer(entry["timer_event"])
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
