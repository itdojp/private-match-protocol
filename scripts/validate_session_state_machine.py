#!/usr/bin/env python3
"""Validate the draft Private Match core session state-machine artifact.

This validator is intentionally local-only.  It validates structure, references, and
the fail-closed protocol constraints recorded in the repository.  It does not make a
network request, select a PET, execute a protocol, or establish cryptographic security.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import SchemaError


ARTIFACT_PATH = Path("specs/state-machines/private-match-core-session-v0.1.yaml")
SCHEMA_PATH = Path("schema/session-state-machine.schema.json")

REQUIRED_PHASES = {
    "UNINITIALIZED",
    "CREATED",
    "PARTICIPANTS_BOUND",
    "COMMITMENTS_PENDING",
    "COMMITTED",
    "EVALUATING",
    "RESULT_ACCEPTED",
    "CONSENT_PENDING",
    "DISCLOSURE_AUTHORIZED",
    "CLOSED",
    "ABORTED",
    "EXPIRED",
}
TERMINAL_PHASES = {"CLOSED", "ABORTED", "EXPIRED"}
REQUIRED_ACTORS = {
    "party_a_client",
    "party_b_client",
    "coordinator",
    "selected_integration_profile",
    "service_operator",
    "assurance_pipeline",
    "network_observer",
    "malicious_participant",
}
REQUIRED_EVENTS = {
    "create_session",
    "accept_session_a",
    "accept_session_b",
    "bind_participant_a",
    "bind_participant_b",
    "accept_policy",
    "reserve_query_budget",
    "register_commitment_a",
    "register_commitment_b",
    "start_evaluation",
    "submit_evaluation_contribution",
    "acknowledge_opaque_receipt_a",
    "acknowledge_opaque_receipt_b",
    "accept_symmetric_result",
    "grant_consent_a",
    "grant_consent_b",
    "withdraw_consent_a",
    "withdraw_consent_b",
    "authorize_disclosure_extension",
    "record_disclosure_completion",
    "reject_message",
    "abort_session",
    "expire_session",
    "close_session",
    "retry_idempotent_message",
    "request_new_evaluation_session",
    "advance_authoritative_time",
    "retry_idempotent_operation",
    "retry_idempotent_profile_callback",
}
REQUIRED_STATE_VARIABLES = {
    "phase",
    "session_id",
    "session_proposal_digest",
    "session_acceptance",
    "protocol_profile",
    "policy_binding",
    "intended_audience",
    "participant_binding",
    "commitment",
    "commitment_pair_id",
    "evaluation_started",
    "evaluation_attempt_id",
    "evaluation_deadline",
    "query_budget_state",
    "proposed_result_state",
    "accepted_result_state",
    "opaque_receipt_ref",
    "result_ack",
    "consent",
    "disclosure_profile_ref",
    "disclosure_state",
    "session_created_at",
    "session_expires_at",
    "authoritative_time",
    "next_sequence",
    "accepted_message_ids",
    "accepted_nonces",
    "accepted_message_records",
    "normalized_message_responses",
    "operation_by_id",
    "operation_by_key",
    "callback_by_id",
    "callback_by_key",
    "selected_integration_profile_binding",
    "terminal_failure_code",
    "party_terminal_category",
    "accepted_event_index",
    "canonical_transcript_head",
}
REQUIRED_INVARIANTS = {
    "INV-REVEAL-SAFETY",
    "INV-RESULT-SYMMETRY",
    "INV-COMMITMENT-IMMUTABILITY",
    "INV-SESSION-BINDING",
    "INV-SESSION-ACCEPTANCE",
    "INV-NO-REPLAY",
    "INV-IDEMPOTENCY",
    "INV-ONE-EVALUATION",
    "INV-EXPIRY",
    "INV-MINIMUM-DISCLOSURE",
    "INV-OPAQUE-RECEIPT",
    "INV-QUERY-BUDGET",
    "INV-COORDINATOR-OUTCOME-CONFIDENTIALITY",
    "INV-CANONICAL-TRANSCRIPT",
}
REQUIRED_FAILURE_CODES = {
    "PARTICIPANT_MISMATCH",
    "PROTOCOL_VERSION_MISMATCH",
    "POLICY_VERSION_MISMATCH",
    "SESSION_MISMATCH",
    "AUDIENCE_MISMATCH",
    "REPLAY",
    "REPLAY_CONFLICT",
    "OUT_OF_ORDER",
    "STALE_MESSAGE",
    "COMMITMENT_MISMATCH",
    "COMMITMENT_MUTATION",
    "QUERY_BUDGET_MISSING",
    "QUERY_BUDGET_EXHAUSTED",
    "VERIFICATION_MATERIAL_MISSING",
    "VERIFICATION_MATERIAL_EXPIRED",
    "EVALUATION_TIMEOUT",
    "PARTIAL_PARTY_FAILURE",
    "RESULT_CONFLICT",
    "CONSENT_MISSING",
    "CONSENT_EXPIRED",
    "CONSENT_WITHDRAWN",
    "DISCLOSURE_PROFILE_REQUIRED",
    "DISCLOSURE_SCOPE_MISMATCH",
    "SESSION_EXPIRED",
    "SESSION_CLOSED",
    "SESSION_ABORTED",
    "UNKNOWN_STATE",
    "UNKNOWN_EVENT",
    "UNKNOWN_VERSION",
    "UNKNOWN_FIELD",
    "CLOCK_DOMAIN_INVALID",
    "CLOCK_ROLLBACK",
    "CLOCK_JUMP_EXCEEDED",
}
REQUIRED_DISCLOSURE_GUARDS = {
    "G-DISCLOSURE-MATCH",
    "G-BILATERAL-CONSENT",
    "G-CONSENT-RECEIPT-BINDING",
    "G-CONSENT-PARTICIPANT-BINDING",
    "G-CONSENT-PROFILE-BINDING",
    "G-CONSENT-SCOPE-BINDING",
    "G-CONSENT-AUDIENCE-BINDING",
    "G-CONSENT-EXPIRY",
    "G-PROFILE-REVIEWED",
    "G-ACTIVE-SESSION",
}
REQUIRED_AUDIT_FIELDS = {
    "event_id",
    "authoritative_timestamp",
    "actor_category_or_pseudonymous_ref",
    "protocol_profile",
    "policy_version",
    "normalized_lifecycle_status",
    "normalized_error_category",
    "opaque_artifact_or_transcript_reference",
    "approved_size_class",
}
PROHIBITED_AUDIT_FIELDS = {
    "plaintext decision outcome",
    "raw or normalized private input",
    "matching or non-matching element",
    "exact intersection count",
    "secret consent payload",
    "local secret",
    "actual disclosure payload",
    "raw failure code",
}
REQUIRED_SCOPE_EXCLUSIONS = {
    "PET selection or cryptographic implementation",
    "transport-specific wire framing, production API fields, or persistence encoding",
    "transport, persistence, or production coordinator implementation",
    "actual identity, private-data, or disclosure payload",
    "TLA+ model checking or any production/security certification",
}
REQUIRED_COORDINATOR_PROHIBITIONS = {
    "MATCH, NO_MATCH, or INDETERMINATE plaintext outcome",
    "raw identifiers or normalized private inputs",
    "matching or non-matching elements",
    "exact intersection count",
    "private attributes",
    "local secrets",
    "actual disclosure payload",
}
REQUIRED_RESULT_PROHIBITIONS = {
    "single-party accepted result",
    "party-specific accepted result",
    "coordinator plaintext result",
    "bare digest of a three-value result",
    "automatic mismatch fallback",
}
REQUIRED_CONSENT_BINDINGS = {
    "session_id",
    "participant set",
    "opaque receipt reference",
    "disclosure profile ID and version",
    "exact disclosure scope",
    "recipient or intended audience",
    "issued_at",
    "expires_at",
    "consent nonce",
    "consent artifact digest",
}

DELIVERY_CLASSES = {
    "party_message",
    "coordinator_command",
    "profile_callback",
    "timer",
    "derived_transition",
    "local_guidance",
}
DELIVERY_ENVELOPES = {
    "party_message": "replay_envelope",
    "coordinator_command": "operation_envelope",
    "profile_callback": "profile_callback_envelope",
    "timer": "time_advance_parameter",
    "derived_transition": "none",
    "local_guidance": "none",
}
RESULT_LOCAL_VARIABLES = {
    "proposed_result_state",
    "accepted_result_state",
    "result_ack",
}
SESSION_ABORT_CODES = {
    "REPLAY_CONFLICT",
    "COMMITMENT_MUTATION",
    "EVALUATION_TIMEOUT",
    "PARTIAL_PARTY_FAILURE",
    "RESULT_CONFLICT",
    "CONSENT_EXPIRED",
    "CONSENT_WITHDRAWN",
    "UNKNOWN_STATE",
}
PARTY_ERROR_CATEGORIES = {
    "BINDING_ERROR",
    "VERSION_ERROR",
    "REPLAY_ERROR",
    "ORDERING_ERROR",
    "COMMITMENT_ERROR",
    "AUTHORIZATION_ERROR",
    "VERIFICATION_ERROR",
    "EVALUATION_ERROR",
    "RESULT_ERROR",
    "CONSENT_ERROR",
    "DISCLOSURE_ERROR",
    "SESSION_UNAVAILABLE",
    "UNSUPPORTED",
    "CLOCK_ERROR",
}
CLOCK_FAILURE_CODES = {
    "CLOCK_DOMAIN_INVALID",
    "CLOCK_ROLLBACK",
    "CLOCK_JUMP_EXCEEDED",
}
AUTHORITATIVE_TIME_FAILURE_CODES = {
    *CLOCK_FAILURE_CODES,
    "SESSION_CLOSED",
    "SESSION_ABORTED",
    "SESSION_EXPIRED",
}
REQUIRED_ENVELOPE_BINDINGS = {
    (
        "coordinator_command",
        "operation_envelope.actor_id",
        "transition.actor",
    ),
    (
        "profile_callback",
        "profile_callback_envelope.profile_id",
        "state.selected_integration_profile_binding.profile_id",
    ),
    (
        "profile_callback",
        "profile_callback_envelope.profile_version",
        "state.selected_integration_profile_binding.profile_version",
    ),
    (
        "profile_callback",
        "profile_callback_envelope.profile_instance_id",
        "state.selected_integration_profile_binding.profile_instance_id",
    ),
    (
        "profile_callback",
        "profile_callback_envelope.session_id",
        "state.session_id",
    ),
    (
        "profile_callback",
        "profile_callback_envelope.evaluation_attempt_id",
        "state.evaluation_attempt_id",
    ),
}

TRANSCRIPT_CLASS_CONTRACTS = {
    "party_message": (
        "G-PARTY-TRANSCRIPT-CHAIN",
        "E-APPEND-PARTY-TRANSCRIPT",
        "replay_envelope.prior_transcript_digest",
        "replay_envelope.canonical_message_digest",
    ),
    "coordinator_command": (
        "G-OPERATION-TRANSCRIPT-CHAIN",
        "E-APPEND-OPERATION-TRANSCRIPT",
        "operation_envelope.prior_transcript_digest",
        "operation_envelope.canonical_message_digest",
    ),
    "profile_callback": (
        "G-CALLBACK-TRANSCRIPT-CHAIN",
        "E-APPEND-CALLBACK-TRANSCRIPT",
        "profile_callback_envelope.prior_transcript_digest",
        "profile_callback_envelope.canonical_message_digest",
    ),
    "timer": (
        "G-TIMER-TRANSCRIPT-CHAIN",
        "E-APPEND-TIMER-TRANSCRIPT",
        "time_advance_parameter.prior_transcript_digest",
        "time_advance_parameter.canonical_event_digest",
    ),
}


class NoDatesSafeLoader(yaml.SafeLoader):
    """Safe loader that preserves protocol date strings without global mutation."""


NoDatesSafeLoader.yaml_implicit_resolvers = {
    first_char: list(resolvers)
    for first_char, resolvers in yaml.SafeLoader.yaml_implicit_resolvers.items()
}
NoDatesSafeLoader.yaml_constructors = dict(yaml.SafeLoader.yaml_constructors)
for first_char, resolvers in list(NoDatesSafeLoader.yaml_implicit_resolvers.items()):
    NoDatesSafeLoader.yaml_implicit_resolvers[first_char] = [
        entry for entry in resolvers if entry[0] != "tag:yaml.org,2002:timestamp"
    ]


def _construct_unique_mapping(
    loader: NoDatesSafeLoader, node: yaml.MappingNode, deep: bool = False
) -> dict[Any, Any]:
    loader.flatten_mapping(node)
    mapping: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in mapping
        except TypeError as error:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                "found an unhashable mapping key",
                key_node.start_mark,
            ) from error
        if duplicate:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                f"found duplicate key {key!r}",
                key_node.start_mark,
            )
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


NoDatesSafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_unique_mapping
)


@dataclass(frozen=True, order=True)
class Finding:
    code: str
    path: str
    message: str

    def format(self) -> str:
        return f"session-state-machine: error [{self.code}] {self.path}: {self.message}"


def _bounded_message(error: BaseException, limit: int = 320) -> str:
    message = " ".join(str(error).split())
    if not message:
        message = error.__class__.__name__
    return message if len(message) <= limit else f"{message[: limit - 3]}..."


def _yaml_error_message(error: yaml.YAMLError) -> str:
    problem = getattr(error, "problem", None) or error.__class__.__name__
    mark = getattr(error, "problem_mark", None)
    if mark is not None:
        return f"{problem} at line {mark.line + 1}, column {mark.column + 1}"
    return _bounded_message(error)


def _relative_findings(findings: list[Finding], root: Path) -> list[Finding]:
    relative: list[Finding] = []
    for finding in findings:
        try:
            path = str(Path(finding.path).resolve().relative_to(root))
        except (OSError, ValueError):
            path = finding.path
        relative.append(Finding(finding.code, path, finding.message))
    return relative


def load_yaml(path: Path) -> tuple[dict[str, Any] | None, list[Finding]]:
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeError as error:
        return None, [Finding("text-decode", str(path), _bounded_message(error))]
    except OSError as error:
        return None, [Finding("file-read", str(path), _bounded_message(error))]

    try:
        value = yaml.load(text, Loader=NoDatesSafeLoader)
    except yaml.YAMLError as error:
        return None, [Finding("yaml-parse", str(path), _yaml_error_message(error))]
    if not isinstance(value, dict):
        return None, [
            Finding("yaml-shape", str(path), "top level must be a YAML mapping")
        ]
    return value, []


def load_json(path: Path) -> tuple[dict[str, Any] | None, list[Finding]]:
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeError as error:
        return None, [Finding("text-decode", str(path), _bounded_message(error))]
    except OSError as error:
        return None, [Finding("file-read", str(path), _bounded_message(error))]

    try:
        value = json.loads(text)
    except json.JSONDecodeError as error:
        return None, [Finding("json-parse", str(path), _bounded_message(error))]
    if not isinstance(value, dict):
        return None, [
            Finding("json-shape", str(path), "top level must be a JSON object")
        ]
    return value, []


def canonical_digest(model: dict[str, Any]) -> str:
    encoded = json.dumps(
        model, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def disclosure_authorization_guard_failures(
    state: dict[str, Any], reviewed_profiles: set[str]
) -> list[str]:
    """Evaluate only the abstract disclosure-extension guard.

    This helper deliberately receives a synthetic state and an explicit reviewed-profile
    set.  It performs no lookup and does not handle, construct, or return a payload.
    """

    failures: list[str] = []
    phase = state.get("phase")
    if phase in TERMINAL_PHASES or phase != "CONSENT_PENDING":
        failures.append("G-ACTIVE-SESSION")

    results = state.get("accepted_result_state", {})
    if results != {"A": "MATCH", "B": "MATCH"}:
        failures.append("G-DISCLOSURE-MATCH")

    profile = state.get("disclosure_profile_ref")
    if not profile or profile == "NONE" or profile not in reviewed_profiles:
        failures.append("G-PROFILE-REVIEWED")

    consents = state.get("consent", {})
    if not all(isinstance(consents.get(party), dict) for party in ("A", "B")):
        failures.append("G-BILATERAL-CONSENT")
        return sorted(set(failures))

    now = state.get("authoritative_time")
    session_expiry = state.get("session_expires_at")
    if (
        not isinstance(now, int)
        or not isinstance(session_expiry, int)
        or now >= session_expiry
    ):
        failures.extend(["G-ACTIVE-SESSION", "G-CONSENT-EXPIRY"])

    expected = {
        "session_id": state.get("session_id"),
        "participant_set": state.get("participant_binding"),
        "opaque_receipt_ref": state.get("opaque_receipt_ref"),
        "disclosure_profile_ref": profile,
        "scope": state.get("disclosure_scope"),
        "audience": state.get("intended_audience"),
    }
    guard_for_field = {
        "session_id": "G-CONSENT-PARTICIPANT-BINDING",
        "participant_set": "G-CONSENT-PARTICIPANT-BINDING",
        "opaque_receipt_ref": "G-CONSENT-RECEIPT-BINDING",
        "disclosure_profile_ref": "G-CONSENT-PROFILE-BINDING",
        "scope": "G-CONSENT-SCOPE-BINDING",
        "audience": "G-CONSENT-AUDIENCE-BINDING",
    }
    for consent in (consents["A"], consents["B"]):
        if consent.get("status") != "valid":
            failures.append("G-BILATERAL-CONSENT")
        for field, value in expected.items():
            if consent.get(field) != value:
                failures.append(guard_for_field[field])
        expiry = consent.get("expires_at")
        if not isinstance(expiry, int) or not isinstance(now, int) or now >= expiry:
            failures.append("G-CONSENT-EXPIRY")
        for field in ("issued_at", "consent_nonce", "artifact_digest"):
            if not consent.get(field):
                failures.append("G-BILATERAL-CONSENT")
    return sorted(set(failures))


def terminal_budget_disposition(
    query_budget_state: str, evaluation_started: bool, terminal_event: str
) -> str:
    """Return the v0.1 terminal disposition for an opaque reservation.

    This models only the normalized state. The authorization ledger is an atomic
    environment assumption and no budget/refund implementation is supplied here.
    """

    if query_budget_state == "RESERVED" and not evaluation_started:
        return "EXPIRED" if terminal_event == "expire" else "RELEASED"
    return query_budget_state


def message_time_failures(
    authoritative_time: int,
    issued_at: int,
    allowed_clock_skew: int,
    message_stale_threshold: int,
) -> list[str]:
    """Evaluate the bounded party-message time relation."""

    if any(
        not isinstance(value, int) or value < 0
        for value in (
            authoritative_time,
            issued_at,
            allowed_clock_skew,
            message_stale_threshold,
        )
    ):
        return ["STALE_MESSAGE"]
    if issued_at < authoritative_time - message_stale_threshold:
        return ["STALE_MESSAGE"]
    if issued_at > authoritative_time + allowed_clock_skew:
        return ["STALE_MESSAGE"]
    return []


def authoritative_time_transition(
    state: dict[str, Any], new_authoritative_time: int, maximum_jump: int
) -> tuple[dict[str, Any], list[str]]:
    """Apply the abstract bounded coordinator-clock relation to a synthetic state."""

    current = state.get("authoritative_time")
    if (
        not isinstance(current, int)
        or not isinstance(new_authoritative_time, int)
        or not isinstance(maximum_jump, int)
        or current < 0
        or new_authoritative_time < 0
        or maximum_jump < 0
    ):
        return dict(state), ["CLOCK_DOMAIN_INVALID"]
    if state.get("phase") in TERMINAL_PHASES:
        return dict(state), [f"SESSION_{state['phase']}"]
    if new_authoritative_time < current:
        return dict(state), ["CLOCK_ROLLBACK"]
    if new_authoritative_time - current > maximum_jump:
        return dict(state), ["CLOCK_JUMP_EXCEEDED"]

    updated = dict(state)
    updated["authoritative_time"] = new_authoritative_time
    session_expiry = state.get("session_expires_at")
    if isinstance(session_expiry, int) and new_authoritative_time >= session_expiry:
        updated["phase"] = "EXPIRED"
        updated["terminal_failure_code"] = "SESSION_EXPIRED"
        updated["party_terminal_category"] = "SESSION_UNAVAILABLE"
        updated["disclosure_state"] = "NONE"
        updated["query_budget_state"] = terminal_budget_disposition(
            str(state.get("query_budget_state")),
            bool(state.get("evaluation_started")),
            "expire",
        )
        return updated, []

    deadline = state.get("evaluation_deadline")
    if (
        state.get("phase") == "EVALUATING"
        and isinstance(deadline, int)
        and new_authoritative_time >= deadline
    ):
        updated["phase"] = "ABORTED"
        updated["terminal_failure_code"] = "EVALUATION_TIMEOUT"
        updated["party_terminal_category"] = "EVALUATION_ERROR"
        updated["disclosure_state"] = "NONE"
        return updated, []

    if state.get("phase") in {"CONSENT_PENDING", "DISCLOSURE_AUTHORIZED"}:
        consents = state.get("consent", {})
        expiries = (
            [
                consent.get("expires_at")
                for consent in consents.values()
                if isinstance(consent, dict) and consent.get("status") == "valid"
            ]
            if isinstance(consents, dict)
            else []
        )
        if any(
            isinstance(expiry, int) and new_authoritative_time >= expiry
            for expiry in expiries
        ):
            updated["phase"] = "ABORTED"
            updated["terminal_failure_code"] = "CONSENT_EXPIRED"
            updated["party_terminal_category"] = "CONSENT_ERROR"
            updated["disclosure_state"] = "NONE"
    return updated, []


def message_response_outcome(
    registry: dict[tuple[str, str, str], dict[str, Any]],
    session_id: str,
    sender_participant_id: str,
    message_id: str,
    nonce: str,
    sequence: int,
    issued_at: int,
    canonical_digest_value: str,
) -> tuple[str, str | None]:
    """Classify a sender-scoped message retry without peer-domain access."""

    prior = registry.get((session_id, sender_participant_id, message_id))
    if prior is None:
        return "new", None
    identity = {
        "nonce": nonce,
        "sequence": sequence,
        "issued_at": issued_at,
        "canonical_digest": canonical_digest_value,
    }
    if all(prior.get(key) == value for key, value in identity.items()):
        response = prior.get("normalized_response")
        return "exact-duplicate", response if isinstance(response, str) else None
    return "REPLAY_CONFLICT", None


def independent_idempotency_outcome(
    by_id: dict[tuple[str, str], dict[str, str]],
    by_key: dict[tuple[str, str], dict[str, str]],
    domain: str,
    identifier: str,
    idempotency_key: str,
    canonical_digest_value: str,
) -> tuple[str, str | None]:
    """Check ID and idempotency-key indexes independently and fail closed."""

    prior_by_id = by_id.get((domain, identifier))
    prior_by_key = by_key.get((domain, idempotency_key))
    if prior_by_id is None and prior_by_key is None:
        return "new", None
    if prior_by_id is None or prior_by_key is None:
        return "REPLAY_CONFLICT", None
    expected_by_id = {
        "idempotency_key": idempotency_key,
        "canonical_digest": canonical_digest_value,
    }
    expected_by_key = {
        "identifier": identifier,
        "canonical_digest": canonical_digest_value,
    }
    if not all(prior_by_id.get(key) == value for key, value in expected_by_id.items()):
        return "REPLAY_CONFLICT", None
    if not all(
        prior_by_key.get(key) == value for key, value in expected_by_key.items()
    ):
        return "REPLAY_CONFLICT", None
    response_by_id = prior_by_id.get("normalized_response")
    response_by_key = prior_by_key.get("normalized_response")
    if response_by_id != response_by_key or not isinstance(response_by_id, str):
        return "REPLAY_CONFLICT", None
    return "exact-duplicate", response_by_id


def operation_envelope_failures(
    transition_actor: str, envelope: dict[str, Any]
) -> list[str]:
    """Fail closed when a coordinator operation claims another actor domain."""

    if (
        transition_actor != "coordinator"
        or envelope.get("actor_id") != transition_actor
    ):
        return ["REPLAY_CONFLICT"]
    return []


def profile_callback_binding_failures(
    state: dict[str, Any], envelope: dict[str, Any]
) -> list[str]:
    """Compare a callback envelope to the current abstract profile/session/attempt."""

    selected = state.get("selected_integration_profile_binding")
    if not isinstance(selected, dict):
        return ["REPLAY_CONFLICT"]
    expected = {
        "profile_id": selected.get("profile_id"),
        "profile_version": selected.get("profile_version"),
        "profile_instance_id": selected.get("profile_instance_id"),
        "session_id": state.get("session_id"),
        "evaluation_attempt_id": state.get("evaluation_attempt_id"),
    }
    if any(envelope.get(key) != value for key, value in expected.items()):
        return ["REPLAY_CONFLICT"]
    return []


def duplicate_delivery_outcome(
    registry: dict[tuple[str, str, str], str],
    domain: str,
    identifier: str,
    idempotency_key: str,
    canonical_digest_value: str,
) -> str:
    """Deprecated compatibility classifier for the earlier draft test surface."""

    prior = registry.get((domain, identifier, idempotency_key))
    if prior is None:
        return "new"
    if prior == canonical_digest_value:
        return "exact-duplicate"
    return "REPLAY_CONFLICT"


def party_error_category(model: dict[str, Any], failure_code: str) -> str | None:
    """Return only the reviewed Party projection for a detailed failure."""

    for failure in model.get("failure_taxonomy", []):
        if failure.get("code") == failure_code:
            category = failure.get("party_error_category")
            return category if category in PARTY_ERROR_CATEGORIES else None
    return None


def generic_abort_guard_failures(
    model: dict[str, Any], actor: str, failure_code: str
) -> list[str]:
    """Validate the supplied generic-abort parameter against the taxonomy."""

    failures: list[str] = []
    if actor != "coordinator":
        failures.append("ABORT_AUTHORITY")
    taxonomy = {
        item.get("code"): item
        for item in model.get("failure_taxonomy", [])
        if isinstance(item, dict)
    }
    failure = taxonomy.get(failure_code)
    if failure is None:
        failures.append("UNDECLARED_FAILURE")
    elif failure.get("disposition") != "session-abort":
        failures.append("NON_ABORT_DISPOSITION")
    return sorted(failures)


def apply_generic_abort(
    model: dict[str, Any], state: dict[str, Any], actor: str, failure_code: str
) -> tuple[dict[str, Any], list[str]]:
    """Apply the parameter-bound generic abort to a synthetic state atomically."""

    failures = generic_abort_guard_failures(model, actor, failure_code)
    if state.get("phase") in TERMINAL_PHASES:
        failures = sorted(set(failures + ["TERMINAL_STATE"]))
    if failures:
        return dict(state), failures
    updated = dict(state)
    updated["phase"] = "ABORTED"
    updated["terminal_failure_code"] = failure_code
    updated["party_terminal_category"] = party_error_category(model, failure_code)
    updated["disclosure_state"] = "NONE"
    updated["query_budget_state"] = terminal_budget_disposition(
        str(state.get("query_budget_state")),
        bool(state.get("evaluation_started")),
        "abort",
    )
    return updated, []


def schema_findings(model: dict[str, Any], schema: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    try:
        Draft202012Validator.check_schema(schema)
    except SchemaError as error:
        return [Finding("schema-invalid", "$schema", _bounded_message(error))]

    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    for error in sorted(
        validator.iter_errors(model), key=lambda item: list(item.absolute_path)
    ):
        path = ".".join(str(part) for part in error.absolute_path) or "$"
        findings.append(Finding("schema", path, _bounded_message(error)))
    return findings


def _ids(items: list[dict[str, Any]]) -> list[str]:
    return [item.get("id", "") for item in items if isinstance(item, dict)]


def _duplicates(values: list[str]) -> list[str]:
    seen: set[str] = set()
    duplicate: set[str] = set()
    for value in values:
        if value in seen:
            duplicate.add(value)
        seen.add(value)
    return sorted(duplicate)


def _index(items: list[dict[str, Any]], key: str = "id") -> dict[str, dict[str, Any]]:
    return {
        item[key]: item
        for item in items
        if isinstance(item, dict) and isinstance(item.get(key), str)
    }


def _transition_guard_ids(transition: dict[str, Any]) -> set[str]:
    return {
        guard.get("id", "")
        for guard in transition.get("guards", [])
        if isinstance(guard, dict)
    }


def _transition_writes(transition: dict[str, Any]) -> set[str]:
    return {
        variable
        for effect in transition.get("effects", [])
        if isinstance(effect, dict)
        for variable in effect.get("writes", [])
        if isinstance(variable, str)
    }


def _finding(code: str, path: str, message: str) -> Finding:
    return Finding(code, path, message)


def semantic_findings(model: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    actors = model.get("actors", [])
    event_parameters = model.get("event_parameter_catalog", [])
    phases = model.get("phases", [])
    variables = model.get("state_variables", [])
    events = model.get("events", [])
    transitions = model.get("transitions", [])
    invariants = model.get("invariants", [])
    failures = model.get("failure_taxonomy", [])

    collections = {
        "actors": actors,
        "event_parameter_catalog": event_parameters,
        "phases": phases,
        "state_variables": variables,
        "events": events,
        "transitions": transitions,
        "invariants": invariants,
    }
    for name, items in collections.items():
        for duplicate in _duplicates(_ids(items)):
            findings.append(_finding("duplicate-id", name, f"duplicate ID {duplicate}"))
    failure_ids = [item.get("code", "") for item in failures if isinstance(item, dict)]
    for duplicate in _duplicates(failure_ids):
        findings.append(
            _finding("duplicate-id", "failure_taxonomy", f"duplicate code {duplicate}")
        )

    actor_ids = set(_ids(actors))
    event_parameter_ids = set(_ids(event_parameters))
    phase_ids = set(_ids(phases))
    variable_ids = set(_ids(variables))
    event_ids = set(_ids(events))
    invariant_ids = set(_ids(invariants))
    failure_code_ids = set(failure_ids)

    required_sets = [
        ("actors", REQUIRED_ACTORS, actor_ids),
        ("phases", REQUIRED_PHASES, phase_ids),
        ("state_variables", REQUIRED_STATE_VARIABLES, variable_ids),
        ("events", REQUIRED_EVENTS, event_ids),
        ("invariants", REQUIRED_INVARIANTS, invariant_ids),
        ("failure_taxonomy", REQUIRED_FAILURE_CODES, failure_code_ids),
    ]
    for path, required, actual in required_sets:
        missing = sorted(required - actual)
        if missing:
            findings.append(
                _finding("required-set", path, f"missing: {', '.join(missing)}")
            )

    phase_index = _index(phases)
    event_index = _index(events)
    transition_index = _index(transitions)
    variable_index = _index(variables)

    # Event parameters are field catalogs, and predicate/operation contracts
    # make every incoming value consumed by the state relation explicit.
    parameter_catalog = _index(event_parameters)
    parameter_paths: set[str] = set()
    for parameter_id, parameter in parameter_catalog.items():
        fields = parameter.get("fields", [])
        field_ids = [item.get("id", "") for item in fields if isinstance(item, dict)]
        for duplicate in _duplicates(field_ids):
            findings.append(
                _finding(
                    "parameter-flow",
                    f"event_parameter_catalog.{parameter_id}.fields",
                    f"duplicate field {duplicate}",
                )
            )
        for field_id in field_ids:
            parameter_paths.add(f"{parameter_id}.{field_id}")

    required_transcript_parameter_fields = {
        "replay_envelope": {
            "prior_transcript_digest",
            "canonical_message_digest",
        },
        "operation_envelope": {
            "prior_transcript_digest",
            "canonical_message_digest",
        },
        "profile_callback_envelope": {
            "prior_transcript_digest",
            "canonical_message_digest",
        },
        "time_advance_parameter": {
            "prior_transcript_digest",
            "canonical_event_digest",
        },
    }
    for parameter_id, required_fields in required_transcript_parameter_fields.items():
        actual_fields = {
            field.get("id")
            for field in parameter_catalog.get(parameter_id, {}).get("fields", [])
            if isinstance(field, dict)
        }
        missing = sorted(required_fields - actual_fields)
        if missing:
            findings.append(
                _finding(
                    "canonical-transcript",
                    f"event_parameter_catalog.{parameter_id}",
                    "missing transcript fields: " + ", ".join(missing),
                )
            )

    flow_contracts = model.get("parameter_flow_contracts", [])
    contract_index: dict[tuple[str, str], dict[str, Any]] = {}
    for index, contract in enumerate(flow_contracts):
        key = (str(contract.get("kind", "")), str(contract.get("id", "")))
        if key in contract_index:
            findings.append(
                _finding(
                    "parameter-flow",
                    f"parameter_flow_contracts.{index}",
                    f"duplicate contract {key[0]} {key[1]}",
                )
            )
        contract_index[key] = contract
        unknown = set(contract.get("required_parameter_reads", [])) - parameter_paths
        if unknown:
            findings.append(
                _finding(
                    "parameter-flow",
                    f"parameter_flow_contracts.{index}.required_parameter_reads",
                    f"unknown parameter paths: {', '.join(sorted(unknown))}",
                )
            )

    envelope_bindings = model.get("envelope_binding_contracts", [])
    actual_envelope_bindings = {
        (
            str(item.get("delivery_class", "")),
            str(item.get("parameter_path", "")),
            str(item.get("state_path", "")),
        )
        for item in envelope_bindings
        if isinstance(item, dict)
        and item.get("operator") == "equals"
        and item.get("failure_code") == "REPLAY_CONFLICT"
    }
    missing_envelope_bindings = REQUIRED_ENVELOPE_BINDINGS - actual_envelope_bindings
    if missing_envelope_bindings:
        findings.append(
            _finding(
                "envelope-binding",
                "envelope_binding_contracts",
                "missing exact bindings: "
                + ", ".join(
                    sorted(
                        f"{delivery}:{parameter}->{state}"
                        for delivery, parameter, state in missing_envelope_bindings
                    )
                ),
            )
        )

    for phase_id in REQUIRED_PHASES:
        phase = phase_index.get(phase_id, {})
        expected_terminal = phase_id in TERMINAL_PHASES
        if phase and phase.get("terminal") is not expected_terminal:
            findings.append(
                _finding(
                    "expiry",
                    f"phases.{phase_id}.terminal",
                    f"must be {str(expected_terminal).lower()}",
                )
            )

    for index, transition in enumerate(transitions):
        path = f"transitions.{index}"
        event_id = transition.get("event")
        if event_id not in event_ids:
            findings.append(
                _finding("reference", f"{path}.event", f"undefined event {event_id}")
            )
        if transition.get("actor") not in actor_ids:
            findings.append(_finding("reference", f"{path}.actor", "undefined actor"))
        event_definition = event_index.get(event_id, {})
        event_authorities = set(event_definition.get("initiator", [])) | set(
            event_definition.get("authoritative_state_owner", [])
        )
        if event_definition and transition.get("actor") not in event_authorities:
            findings.append(
                _finding(
                    "reference",
                    f"{path}.actor",
                    "transition actor must be an event initiator or authoritative state owner",
                )
            )
        for phase in transition.get("from_phase", []):
            if phase not in phase_ids:
                findings.append(
                    _finding(
                        "reference", f"{path}.from_phase", f"undefined phase {phase}"
                    )
                )
        to_phase = transition.get("to_phase")
        if to_phase != "SAME" and to_phase not in phase_ids:
            findings.append(
                _finding("reference", f"{path}.to_phase", f"undefined phase {to_phase}")
            )
        for invariant in transition.get("related_invariants", []):
            if invariant not in invariant_ids:
                findings.append(
                    _finding(
                        "reference",
                        f"{path}.related_invariants",
                        f"undefined invariant {invariant}",
                    )
                )
        for code in transition.get("failure_code", []):
            if code not in failure_code_ids:
                findings.append(
                    _finding(
                        "failure-taxonomy",
                        f"{path}.failure_code",
                        f"undeclared failure {code}",
                    )
                )
        for kind in ("guards", "effects"):
            for item_index, item in enumerate(transition.get(kind, [])):
                key = "reads" if kind == "guards" else "writes"
                for variable in item.get(key, []):
                    if variable not in variable_ids:
                        findings.append(
                            _finding(
                                "reference",
                                f"{path}.{kind}.{item_index}.{key}",
                                f"undefined state variable {variable}",
                            )
                        )
                event_parameters_for_transition = set(
                    event_definition.get("parameters", [])
                )
                parameter_reads = set(item.get("parameter_reads", []))
                for parameter_read in parameter_reads:
                    parameter = str(parameter_read).split(".", 1)[0]
                    if parameter not in event_parameters_for_transition:
                        findings.append(
                            _finding(
                                "reference",
                                f"{path}.{kind}.{item_index}.parameter_reads",
                                f"event does not declare parameter {parameter}",
                            )
                        )
                    if parameter_read not in parameter_paths:
                        findings.append(
                            _finding(
                                "parameter-flow",
                                f"{path}.{kind}.{item_index}.parameter_reads",
                                f"unknown parameter field {parameter_read}",
                            )
                        )
                contract_kind = "predicate" if kind == "guards" else "operation"
                contract = contract_index.get((contract_kind, str(item.get("id", ""))))
                if contract:
                    required_reads = set(contract.get("required_parameter_reads", []))
                    missing_reads = required_reads - parameter_reads
                    if missing_reads:
                        findings.append(
                            _finding(
                                "parameter-flow",
                                f"{path}.{kind}.{item_index}.parameter_reads",
                                "missing contract fields: "
                                + ", ".join(sorted(missing_reads)),
                            )
                        )

        for from_phase in transition.get("from_phase", []):
            if from_phase not in TERMINAL_PHASES:
                continue
            event = event_index.get(event_id, {})
            permitted = set(
                phase_index.get(from_phase, {}).get("allowed_terminal_operations", [])
            )
            if (
                transition.get("mutating")
                or event.get("mutating")
                or event_id not in permitted
            ):
                findings.append(
                    _finding(
                        "terminal-transition",
                        path,
                        f"terminal phase {from_phase} has illegal outgoing event {event_id}",
                    )
                )
            if _transition_writes(transition):
                findings.append(
                    _finding(
                        "terminal-transition",
                        path,
                        f"terminal phase {from_phase} transition writes state",
                    )
                )

    for index, invariant in enumerate(invariants):
        path = f"invariants.{index}"
        for variable in invariant.get("state_variables", []):
            if variable not in variable_ids:
                findings.append(
                    _finding(
                        "reference",
                        f"{path}.state_variables",
                        f"undefined state variable {variable}",
                    )
                )
        for condition_index, condition in enumerate(invariant.get("conditions", [])):
            for variable in condition.get("reads", []):
                if variable not in variable_ids:
                    findings.append(
                        _finding(
                            "reference",
                            f"{path}.conditions.{condition_index}.reads",
                            f"undefined state variable {variable}",
                        )
                    )
            parameter_reads = set(condition.get("parameter_reads", []))
            unknown = parameter_reads - parameter_paths
            if unknown:
                findings.append(
                    _finding(
                        "parameter-flow",
                        f"{path}.conditions.{condition_index}.parameter_reads",
                        f"unknown parameter fields: {', '.join(sorted(unknown))}",
                    )
                )
            contract = contract_index.get(("predicate", str(condition.get("id", ""))))
            if contract:
                missing = (
                    set(contract.get("required_parameter_reads", [])) - parameter_reads
                )
                if missing:
                    findings.append(
                        _finding(
                            "parameter-flow",
                            f"{path}.conditions.{condition_index}.parameter_reads",
                            f"missing contract fields: {', '.join(sorted(missing))}",
                        )
                    )

    for event_id in sorted(event_ids):
        if not any(transition.get("event") == event_id for transition in transitions):
            findings.append(
                _finding(
                    "event-coverage", "events", f"event {event_id} has no transition"
                )
            )
    for index, event in enumerate(events):
        if event.get("default_failure_code") not in failure_code_ids:
            findings.append(
                _finding(
                    "failure-taxonomy",
                    f"events.{index}.default_failure_code",
                    f"undeclared failure {event.get('default_failure_code')}",
                )
            )
        for parameter in event.get("parameters", []):
            if parameter not in event_parameter_ids:
                findings.append(
                    _finding(
                        "reference",
                        f"events.{index}.parameters",
                        f"undefined abstract event parameter {parameter}",
                    )
                )
        used_parameters = {
            parameter_read.split(".", 1)[0]
            for transition in transitions
            if transition.get("event") == event.get("id")
            for collection in ("guards", "effects")
            for item in transition.get(collection, [])
            for parameter_read in item.get("parameter_reads", [])
        }
        unused_parameters = set(event.get("parameters", [])) - used_parameters
        if unused_parameters:
            findings.append(
                _finding(
                    "parameter-flow",
                    f"events.{index}.parameters",
                    "declared required parameters are unused: "
                    + ", ".join(sorted(unused_parameters)),
                )
            )
        unexpected_audit = set(event.get("audit_fields", [])) - REQUIRED_AUDIT_FIELDS
        if unexpected_audit:
            findings.append(
                _finding(
                    "audit-policy",
                    f"events.{index}.audit_fields",
                    f"unapproved fields: {', '.join(sorted(unexpected_audit))}",
                )
            )
    for transition in transitions:
        event = event_index.get(transition.get("event"), {})
        if transition.get("idempotency_behavior") != event.get("idempotency_behavior"):
            findings.append(
                _finding(
                    "idempotency",
                    transition.get("id", "transition"),
                    "transition and event idempotency semantics differ",
                )
            )
        if transition.get("duplicate_behavior") != event.get("duplicate_behavior"):
            findings.append(
                _finding(
                    "idempotency",
                    transition.get("id", "transition"),
                    "transition and event duplicate semantics differ",
                )
            )
    parameter_catalog = _index(event_parameters)
    replay_type = str(parameter_catalog.get("replay_envelope", {}).get("type", ""))
    if "issued_at" not in replay_type:
        findings.append(
            _finding(
                "message-time",
                "event_parameter_catalog.replay_envelope",
                "party replay envelope must carry issued_at for stale/future checks",
            )
        )

    for index, event in enumerate(events):
        path = f"events.{index}"
        delivery_class = event.get("delivery_class")
        if delivery_class not in DELIVERY_CLASSES:
            findings.append(
                _finding(
                    "delivery-class",
                    f"{path}.delivery_class",
                    "event has an unknown delivery class",
                )
            )
            continue
        expected_envelope = DELIVERY_ENVELOPES[delivery_class]
        if event.get("required_envelope") != expected_envelope:
            findings.append(
                _finding(
                    "delivery-class",
                    f"{path}.required_envelope",
                    f"{delivery_class} requires {expected_envelope}",
                )
            )

        parameters = set(event.get("parameters", []))
        idempotency = str(event.get("idempotency_behavior", ""))
        duplicate = str(event.get("duplicate_behavior", ""))
        if delivery_class == "party_message":
            if not {"session_context", "replay_envelope"}.issubset(parameters):
                findings.append(
                    _finding(
                        "delivery-class",
                        f"{path}.parameters",
                        "party_message requires session_context and replay_envelope",
                    )
                )
            if not set(event.get("initiator", [])).issubset(
                {"party_a_client", "party_b_client"}
            ):
                findings.append(
                    _finding(
                        "delivery-class",
                        f"{path}.initiator",
                        "party_message initiator must be a bound party",
                    )
                )
            if (
                "prior normalized message response" not in idempotency
                or "canonical event digest" not in duplicate
                or "REPLAY_CONFLICT" not in duplicate
            ):
                findings.append(
                    _finding(
                        "idempotency",
                        path,
                        "party_message must use replay-envelope exact/conflicting duplicate semantics",
                    )
                )
        elif delivery_class == "coordinator_command":
            if not {"session_context", "operation_envelope"}.issubset(parameters):
                findings.append(
                    _finding(
                        "delivery-class",
                        f"{path}.parameters",
                        "coordinator_command requires session_context and operation_envelope",
                    )
                )
            if event.get("initiator") != ["coordinator"]:
                findings.append(
                    _finding(
                        "delivery-class",
                        f"{path}.initiator",
                        "coordinator_command is coordinator-initiated only",
                    )
                )
            if (
                "prior normalized operation response" not in idempotency
                or "canonical operation digest" not in duplicate
                or "REPLAY_CONFLICT" not in duplicate
            ):
                findings.append(
                    _finding(
                        "idempotency",
                        path,
                        "coordinator_command must use actor-scoped operation duplicate semantics",
                    )
                )
        elif delivery_class == "profile_callback":
            if not {"session_context", "profile_callback_envelope"}.issubset(
                parameters
            ):
                findings.append(
                    _finding(
                        "delivery-class",
                        f"{path}.parameters",
                        "profile_callback requires session_context and profile_callback_envelope",
                    )
                )
            if (
                "prior normalized callback response" not in idempotency
                or "canonical callback digest" not in duplicate
                or "REPLAY_CONFLICT" not in duplicate
            ):
                findings.append(
                    _finding(
                        "idempotency",
                        path,
                        "profile_callback must use profile/session/attempt-scoped duplicate semantics",
                    )
                )
        elif delivery_class == "timer":
            if parameters != {"time_advance_parameter"}:
                findings.append(
                    _finding(
                        "delivery-class",
                        f"{path}.parameters",
                        "timer accepts only time_advance_parameter",
                    )
                )
            timer_text = f"{idempotency} {duplicate}".lower()
            if (
                any(
                    token in timer_text
                    for token in (
                        "message_id",
                        "nonce",
                        "prior normalized message response",
                    )
                )
                or "threshold" not in timer_text
            ):
                findings.append(
                    _finding(
                        "delivery-class",
                        path,
                        "timer must be threshold-triggered without message replay prose",
                    )
                )
        else:
            if expected_envelope != "none" or any(
                envelope in parameters
                for envelope in (
                    "replay_envelope",
                    "operation_envelope",
                    "profile_callback_envelope",
                    "time_advance_parameter",
                )
            ):
                findings.append(
                    _finding(
                        "delivery-class",
                        path,
                        f"{delivery_class} must not require an external envelope",
                    )
                )
            if (
                "external delivery" not in idempotency
                or "not externally" not in duplicate
            ):
                findings.append(
                    _finding(
                        "idempotency",
                        path,
                        f"{delivery_class} must explicitly reject external duplicate/retry semantics",
                    )
                )

    for transition in transitions:
        event = event_index.get(transition.get("event"), {})
        delivery_class = event.get("delivery_class")
        guard_ids = _transition_guard_ids(transition)
        effect_ids = {
            item.get("id")
            for item in transition.get("effects", [])
            if isinstance(item, dict)
        }
        transcript_contract = TRANSCRIPT_CLASS_CONTRACTS.get(str(delivery_class))
        if transition.get("mutating") and transcript_contract:
            guard_id, effect_id, prior_path, digest_path = transcript_contract
            if guard_id not in guard_ids or effect_id not in effect_ids:
                findings.append(
                    _finding(
                        "canonical-transcript",
                        transition.get("id", "transition"),
                        "accepted mutating delivery must guard and atomically append the transcript",
                    )
                )
            guard = next(
                (
                    item
                    for item in transition.get("guards", [])
                    if item.get("id") == guard_id
                ),
                {},
            )
            effect = next(
                (
                    item
                    for item in transition.get("effects", [])
                    if item.get("id") == effect_id
                ),
                {},
            )
            expected_reads = {prior_path, digest_path}
            if (
                not {"accepted_event_index", "canonical_transcript_head"}.issubset(
                    set(guard.get("reads", []))
                )
                or set(guard.get("parameter_reads", [])) != expected_reads
                or set(effect.get("parameter_reads", [])) != expected_reads
                or set(effect.get("writes", []))
                != {"accepted_event_index", "canonical_transcript_head"}
            ):
                findings.append(
                    _finding(
                        "canonical-transcript",
                        transition.get("id", "transition"),
                        "transcript guard/effect must bind the class digest and prior head exactly once",
                    )
                )
            if "INV-CANONICAL-TRANSCRIPT" not in transition.get(
                "related_invariants", []
            ):
                findings.append(
                    _finding(
                        "canonical-transcript",
                        transition.get("id", "transition"),
                        "mutating transition must reference INV-CANONICAL-TRANSCRIPT",
                    )
                )
        elif not transition.get("mutating"):
            all_transcript_ids = {
                item
                for contract in TRANSCRIPT_CLASS_CONTRACTS.values()
                for item in contract[:2]
            }
            if (guard_ids | effect_ids) & all_transcript_ids:
                findings.append(
                    _finding(
                        "canonical-transcript",
                        transition.get("id", "transition"),
                        "reject, duplicate, derived/local, and no-op relations must not append the transcript",
                    )
                )
        if transition.get("mutating") and delivery_class == "party_message":
            if (
                not {"G-MESSAGE-TIME-VALID", "G-ORDER-AND-REPLAY"}.issubset(guard_ids)
                or "E-ACCEPT-MESSAGE" not in effect_ids
            ):
                findings.append(
                    _finding(
                        "message-time",
                        transition.get("id", "transition"),
                        "mutating party_message must validate time/order and atomically record its replay envelope",
                    )
                )
        if transition.get("mutating") and delivery_class == "coordinator_command":
            if (
                "G-OPERATION-DEDUP" not in guard_ids
                or "E-ACCEPT-OPERATION" not in effect_ids
            ):
                findings.append(
                    _finding(
                        "delivery-class",
                        transition.get("id", "transition"),
                        "mutating coordinator command must atomically deduplicate and record its operation envelope",
                    )
                )
        if transition.get("mutating") and delivery_class == "profile_callback":
            if (
                "G-PROFILE-CALLBACK-DEDUP" not in guard_ids
                or "E-ACCEPT-PROFILE-CALLBACK" not in effect_ids
            ):
                findings.append(
                    _finding(
                        "delivery-class",
                        transition.get("id", "transition"),
                        "mutating profile callback must atomically deduplicate and record its callback envelope",
                    )
                )

        for guard_item in transition.get("guards", []):
            if guard_item.get("id") == "G-OPERATION-DEDUP":
                if (
                    set(guard_item.get("reads", []))
                    != {
                        "operation_by_id",
                        "operation_by_key",
                    }
                    or guard_item.get("predicate")
                    != "new_or_exact_actor_scoped_operation"
                    or "operation_envelope.actor_id"
                    not in guard_item.get("parameter_reads", [])
                ):
                    findings.append(
                        _finding(
                            "independent-idempotency-key",
                            transition.get("id", "transition"),
                            "operation dedup must check actor-bound ID and key indexes independently",
                        )
                    )
            if guard_item.get("id") == "G-PROFILE-CALLBACK-DEDUP":
                if (
                    not {
                        "callback_by_id",
                        "callback_by_key",
                        "selected_integration_profile_binding",
                        "session_id",
                        "evaluation_attempt_id",
                    }.issubset(set(guard_item.get("reads", [])))
                    or guard_item.get("predicate") != "new_or_exact_profile_callback"
                ):
                    findings.append(
                        _finding(
                            "independent-idempotency-key",
                            transition.get("id", "transition"),
                            "callback dedup must check both indexes and current profile/session/attempt binding",
                        )
                    )
        for effect_item in transition.get("effects", []):
            if effect_item.get("id") == "E-ACCEPT-OPERATION" and set(
                effect_item.get("writes", [])
            ) != {"operation_by_id", "operation_by_key"}:
                findings.append(
                    _finding(
                        "independent-idempotency-key",
                        transition.get("id", "transition"),
                        "first operation acceptance must atomically write both indexes",
                    )
                )
            if effect_item.get("id") == "E-ACCEPT-PROFILE-CALLBACK" and set(
                effect_item.get("writes", [])
            ) != {"callback_by_id", "callback_by_key"}:
                findings.append(
                    _finding(
                        "independent-idempotency-key",
                        transition.get("id", "transition"),
                        "first callback acceptance must atomically write both indexes",
                    )
                )

        if transition.get("to_phase") in {"ABORTED", "EXPIRED"}:
            writes = _transition_writes(transition)
            if not {"terminal_failure_code", "party_terminal_category"}.issubset(
                writes
            ):
                findings.append(
                    _finding(
                        "failure-projection",
                        transition.get("id", "transition"),
                        "terminal detail and Party category must be written atomically",
                    )
                )

    result_values = model.get("artifact", {}).get("decision_output")
    if result_values != ["MATCH", "NO_MATCH", "INDETERMINATE"]:
        findings.append(
            _finding(
                "result-values",
                "artifact.decision_output",
                "allowed values must be exactly MATCH, NO_MATCH, INDETERMINATE",
            )
        )
    if (
        model.get("result_acceptance_semantics", {}).get("allowed_values")
        != result_values
    ):
        findings.append(
            _finding(
                "result-values",
                "result_acceptance_semantics.allowed_values",
                "must equal artifact decision output",
            )
        )

    scope_exclusions = set(model.get("scope", {}).get("excludes", []))
    missing_scope_exclusions = REQUIRED_SCOPE_EXCLUSIONS - scope_exclusions
    if missing_scope_exclusions:
        findings.append(
            _finding(
                "minimum-disclosure",
                "scope.excludes",
                f"missing core exclusions: {', '.join(sorted(missing_scope_exclusions))}",
            )
        )
    coordinator_prohibited = set(
        model.get("authority_model", {}).get("coordinator_prohibited_state", [])
    )
    missing_coordinator_prohibitions = (
        REQUIRED_COORDINATOR_PROHIBITIONS - coordinator_prohibited
    )
    if missing_coordinator_prohibitions:
        findings.append(
            _finding(
                "minimum-disclosure",
                "authority_model.coordinator_prohibited_state",
                "missing coordinator prohibitions: "
                + ", ".join(sorted(missing_coordinator_prohibitions)),
            )
        )
    result_prohibitions = set(
        model.get("result_acceptance_semantics", {}).get("forbidden", [])
    )
    missing_result_prohibitions = REQUIRED_RESULT_PROHIBITIONS - result_prohibitions
    if missing_result_prohibitions:
        findings.append(
            _finding(
                "minimum-disclosure",
                "result_acceptance_semantics.forbidden",
                f"missing result prohibitions: {', '.join(sorted(missing_result_prohibitions))}",
            )
        )
    consent_bindings = set(
        model.get("consent_semantics", {}).get("required_binding_fields", [])
    )
    missing_consent_bindings = REQUIRED_CONSENT_BINDINGS - consent_bindings
    if missing_consent_bindings:
        findings.append(
            _finding(
                "disclosure-guard",
                "consent_semantics.required_binding_fields",
                f"missing consent bindings: {', '.join(sorted(missing_consent_bindings))}",
            )
        )

    for result_variable in ("proposed_result_state", "accepted_result_state"):
        result_state = variable_index.get(result_variable, {})
        if result_state.get(
            "coordinator_access"
        ) != "prohibited" or "coordinator" in result_state.get("visibility", []):
            findings.append(
                _finding(
                    "coordinator-plaintext-outcome",
                    f"state_variables.{result_variable}",
                    "coordinator must not own or see party-local plaintext results",
                )
            )
    expected_entry_visibility = {
        "A": ["party_a_client"],
        "B": ["party_b_client"],
    }
    for result_variable in sorted(RESULT_LOCAL_VARIABLES):
        variable = variable_index.get(result_variable, {})
        if variable.get("visibility") != []:
            findings.append(
                _finding(
                    "result-visibility",
                    f"state_variables.{result_variable}.visibility",
                    "party-indexed result state must not grant whole-map actor visibility",
                )
            )
        if variable.get("entry_visibility") != expected_entry_visibility:
            findings.append(
                _finding(
                    "result-visibility",
                    f"state_variables.{result_variable}.entry_visibility",
                    "A and B may read only their own entry",
                )
            )
        profile_visibility = variable.get("profile_visibility", {})
        if profile_visibility.get("status") != "profile-dependent":
            findings.append(
                _finding(
                    "result-visibility",
                    f"state_variables.{result_variable}.profile_visibility",
                    "selected integration profile access must remain profile-dependent",
                )
            )
        observer = variable.get("global_invariant_observer", {})
        if observer != {
            "may_compare_entries": True,
            "implementation_actor_access": False,
        }:
            findings.append(
                _finding(
                    "result-visibility",
                    f"state_variables.{result_variable}.global_invariant_observer",
                    "formal comparison must not grant implementation actor access",
                )
            )
        coordinator_projection = variable.get("coordinator_projection", {})
        permitted = set(coordinator_projection.get("permitted_fields", []))
        prohibited = set(coordinator_projection.get("prohibited_fields", []))
        expected_permitted = (
            {"opaque_receipt_ref", "normalized_ack_status"}
            if result_variable == "result_ack"
            else set()
        )
        if permitted != expected_permitted or not {
            "local_result",
            "local_result_binding",
        }.issubset(prohibited):
            findings.append(
                _finding(
                    "result-visibility",
                    f"state_variables.{result_variable}.coordinator_projection",
                    "coordinator projection must exclude local result values and bindings",
                )
            )

    message_cache = variable_index.get("normalized_message_responses", {})
    expected_recipient_projection = {
        "replay_domain": ["session_id", "sender_participant_id"],
        "recipient_by_sender": {
            "A": "party_a_client",
            "B": "party_b_client",
        },
        "whole_map_party_access": False,
        "peer_entry_access": "forbidden",
        "authorization_source": "independent authenticated_requester trusted projection; never replayed message sender",
        "exact_subject_match": "required against response_recipient_binding",
        "no_requester_behavior": "classify exact duplicate internally but return no response",
    }
    if (
        message_cache.get("visibility") != ["coordinator"]
        or message_cache.get("recipient_projection") != expected_recipient_projection
    ):
        findings.append(
            _finding(
                "message-response-scope",
                "state_variables.normalized_message_responses",
                "message responses require coordinator-only whole-map access and own-sender recipient projections",
            )
        )
    accepted_records = variable_index.get("accepted_message_records", {})
    accepted_record_type = str(accepted_records.get("type", ""))
    if not {
        "replay_domain",
        "message_id",
        "nonce",
        "sequence",
        "issued_at",
        "canonical_message_digest",
        "canonical_wire_digest",
        "verification_material_id",
        "original_authenticated_subject",
        "response_recipient_binding",
    }.issubset(
        set(accepted_record_type.replace("<", ",").replace(">", ",").split(","))
    ):
        findings.append(
            _finding(
                "message-response-scope",
                "state_variables.accepted_message_records",
                "accepted message identity must persist domain, replay identity, semantic/full-wire digests, material, subject, and recipient",
            )
        )

    operation_variables = {"operation_by_id", "operation_by_key"}
    callback_variables = {"callback_by_id", "callback_by_key"}
    if not operation_variables.issubset(variable_ids):
        findings.append(
            _finding(
                "independent-idempotency-key",
                "state_variables",
                "coordinator operations require independent ID and key indexes",
            )
        )
    if not callback_variables.issubset(variable_ids):
        findings.append(
            _finding(
                "independent-idempotency-key",
                "state_variables",
                "profile callbacks require independent ID and key indexes",
            )
        )

    detailed_failure = variable_index.get("terminal_failure_code", {})
    party_failure = variable_index.get("party_terminal_category", {})
    if detailed_failure.get("visibility") != ["coordinator", "assurance_pipeline"]:
        findings.append(
            _finding(
                "failure-projection",
                "state_variables.terminal_failure_code.visibility",
                "detailed failure code is coordinator/private-assurance only",
            )
        )
    if not {
        "party_a_client",
        "party_b_client",
    }.issubset(set(party_failure.get("visibility", []))):
        findings.append(
            _finding(
                "failure-projection",
                "state_variables.party_terminal_category.visibility",
                "both Parties require only the reviewed normalized category projection",
            )
        )
    projection = model.get("failure_projection_semantics", {})
    if (
        projection.get("detail_state_variable") != "terminal_failure_code"
        or projection.get("party_state_variable") != "party_terminal_category"
        or projection.get("mapping_source") != "failure_taxonomy.party_error_category"
        or projection.get("atomic_terminal_projection") is not True
        or not {
            "terminal_failure_code",
            "raw failure_code",
            "private failure detail",
        }.issubset(set(projection.get("normalized_response_prohibited_fields", [])))
    ):
        findings.append(
            _finding(
                "failure-projection",
                "failure_projection_semantics",
                "raw detail must be separated from the taxonomy-derived Party projection and normalized response",
            )
        )
    for failure in failures:
        if failure.get("party_error_category") not in PARTY_ERROR_CATEGORIES:
            findings.append(
                _finding(
                    "failure-projection",
                    f"failure_taxonomy.{failure.get('code')}.party_error_category",
                    "unknown Party error category",
                )
            )

    expected_event_visibility = {
        "acknowledge_opaque_receipt_a": "party_a_client",
        "acknowledge_opaque_receipt_b": "party_b_client",
    }
    for event_id, own_actor in expected_event_visibility.items():
        event = event_index.get(event_id, {})
        actors = {item.get("actor") for item in event.get("visibility", [])}
        peer_actor = (
            "party_b_client" if own_actor == "party_a_client" else "party_a_client"
        )
        own_data = next(
            (
                item.get("data", [])
                for item in event.get("visibility", [])
                if item.get("actor") == own_actor
            ),
            [],
        )
        coordinator_data = next(
            (
                item.get("data", [])
                for item in event.get("visibility", [])
                if item.get("actor") == "coordinator"
            ),
            [],
        )
        if peer_actor in actors or not any("own" in value for value in own_data):
            findings.append(
                _finding(
                    "result-visibility",
                    f"events.{event_id}.visibility",
                    "acknowledgment event must expose only the sender's own result entry",
                )
            )
        if set(coordinator_data) != {"opaque_receipt_ref", "normalized_ack_status"}:
            findings.append(
                _finding(
                    "result-visibility",
                    f"events.{event_id}.visibility",
                    "coordinator event projection is limited to opaque receipt and normalized ack status",
                )
            )
        for transition in transitions:
            if transition.get("event") == event_id and transition.get(
                "visibility"
            ) != event.get("visibility"):
                findings.append(
                    _finding(
                        "result-visibility",
                        transition.get("id", "transition"),
                        "event and transition result visibility must match",
                    )
                )
    for collection_name, items in (("events", events), ("transitions", transitions)):
        for index, item in enumerate(items):
            for visible in item.get("visibility", []):
                if visible.get("actor") != "coordinator":
                    continue
                data = " ".join(visible.get("data", [])).lower()
                if "plaintext" in data or any(
                    value.lower() in data
                    for value in (
                        "match outcome",
                        "no_match outcome",
                        "indeterminate outcome",
                    )
                ):
                    findings.append(
                        _finding(
                            "coordinator-plaintext-outcome",
                            f"{collection_name}.{index}.visibility",
                            "coordinator visibility includes a plaintext outcome",
                        )
                    )
                if visible.get("actor") == "coordinator" and any(
                    token in data
                    for token in ("local_result", "local-result", "peer result")
                ):
                    findings.append(
                        _finding(
                            "result-visibility",
                            f"{collection_name}.{index}.visibility",
                            "coordinator visibility includes a local result binding",
                        )
                    )

    receipt = model.get("authority_model", {}).get("opaque_receipt_reference", {})
    construction = str(receipt.get("construction_policy", "")).lower().replace(" ", "")
    if any(
        token in construction
        for token in (
            "hash(match)",
            "hash(no_match)",
            "hash(indeterminate)",
            "barelow-entropydigest",
        )
    ):
        findings.append(
            _finding(
                "opaque-receipt",
                "authority_model.opaque_receipt_reference.construction_policy",
                "bare low-entropy result digest is forbidden",
            )
        )
    forbidden = set(receipt.get("forbidden_constructions", []))
    expected_forbidden = {
        "hash(MATCH)",
        "hash(NO_MATCH)",
        "hash(INDETERMINATE)",
        "any bare low-entropy digest dictionary over the decision output",
    }
    if not expected_forbidden.issubset(forbidden):
        findings.append(
            _finding(
                "opaque-receipt",
                "authority_model.opaque_receipt_reference.forbidden_constructions",
                "all low-entropy result digest constructions must be forbidden",
            )
        )

    disclosure_ids = {
        "TR-AUTHORIZE-DISCLOSURE-EXTENSION",
        "TR-RECORD-DISCLOSURE-COMPLETION",
    }
    for transition_id in disclosure_ids:
        transition = transition_index.get(transition_id)
        if not transition:
            findings.append(
                _finding("disclosure-guard", "transitions", f"missing {transition_id}")
            )
            continue
        missing = REQUIRED_DISCLOSURE_GUARDS - _transition_guard_ids(transition)
        if missing:
            findings.append(
                _finding(
                    "disclosure-guard",
                    transition_id,
                    f"missing guards: {', '.join(sorted(missing))}",
                )
            )
        match_guard = next(
            (
                guard
                for guard in transition.get("guards", [])
                if guard.get("id") == "G-DISCLOSURE-MATCH"
            ),
            {},
        )
        if match_guard.get("reads") != ["accepted_result_state"] or set(
            match_guard.get("arguments", [])
        ) != {"A=MATCH", "B=MATCH"}:
            findings.append(
                _finding(
                    "disclosure-guard",
                    transition_id,
                    "disclosure must require bilateral MATCH only",
                )
            )
        if not transition.get("extension_only"):
            findings.append(
                _finding(
                    "core-reveal-unreachable",
                    transition_id,
                    "disclosure transitions must be extension-only",
                )
            )

    scope = model.get("scope", {})
    if (
        scope.get("core_disclosure_profile") != "NONE"
        or scope.get("actual_disclosure_completion")
        != "unreachable in private-match-core/v0.1"
    ):
        findings.append(
            _finding(
                "core-reveal-unreachable",
                "scope",
                "core must have no disclosure profile and no reachable completion",
            )
        )
    disclosure_phase = phase_index.get("DISCLOSURE_AUTHORIZED", {})
    if disclosure_phase.get("core_reachable") is not False:
        findings.append(
            _finding(
                "core-reveal-unreachable",
                "phases.DISCLOSURE_AUTHORIZED",
                "must be unreachable in core",
            )
        )

    reachable = {"UNINITIALIZED"}
    changed = True
    while changed:
        changed = False
        for transition in transitions:
            if transition.get("extension_only"):
                continue
            if not set(transition.get("from_phase", [])).intersection(reachable):
                continue
            to_phase = transition.get("to_phase")
            if to_phase != "SAME" and to_phase not in reachable:
                reachable.add(to_phase)
                changed = True
    if "DISCLOSURE_AUTHORIZED" in reachable:
        findings.append(
            _finding(
                "core-reveal-unreachable",
                "transitions",
                "core graph reaches DISCLOSURE_AUTHORIZED",
            )
        )

    accept_result = transition_index.get("TR-ACCEPT-SYMMETRIC-RESULT", {})
    required_result_guards = {
        "G-BOTH-ACKS",
        "G-SAME-OPAQUE-RECEIPT",
        "G-SAME-PARTY-RESULT",
        "G-RESULT-ALLOWED",
        "G-ONE-ACCEPTED-EVALUATION",
    }
    missing_result_guards = required_result_guards - _transition_guard_ids(
        accept_result
    )
    if missing_result_guards or accept_result.get("to_phase") != "RESULT_ACCEPTED":
        findings.append(
            _finding(
                "result-symmetry",
                "TR-ACCEPT-SYMMETRIC-RESULT",
                f"missing or invalid symmetry guards: {', '.join(sorted(missing_result_guards))}",
            )
        )
    same_result_guard = next(
        (
            guard
            for guard in accept_result.get("guards", [])
            if guard.get("id") == "G-SAME-PARTY-RESULT"
        ),
        {},
    )
    if same_result_guard.get("reads") != ["proposed_result_state"]:
        findings.append(
            _finding(
                "result-symmetry",
                "TR-ACCEPT-SYMMETRIC-RESULT",
                "acceptance must compare both party-local proposed results before writing accepted state",
            )
        )
    if not {"accepted_result_state", "accepted_evaluation_count"}.issubset(
        _transition_writes(accept_result)
    ):
        findings.append(
            _finding(
                "one-evaluation",
                "TR-ACCEPT-SYMMETRIC-RESULT",
                "acceptance must set symmetric results and increment accepted count",
            )
        )
    conflict = transition_index.get("TR-RESULT-CONFLICT", {})
    if (
        conflict.get("to_phase") != "ABORTED"
        or conflict.get("terminal_effect") != "abort"
        or "RESULT_CONFLICT" not in conflict.get("failure_code", [])
    ):
        findings.append(
            _finding(
                "result-symmetry",
                "TR-RESULT-CONFLICT",
                "result conflict must fail closed to ABORTED",
            )
        )

    immutable = {
        "commitment",
        "commitment_pair_id",
        "policy_binding",
        "participant_binding",
    }
    post_start = {
        "EVALUATING",
        "RESULT_ACCEPTED",
        "CONSENT_PENDING",
        "DISCLOSURE_AUTHORIZED",
        *TERMINAL_PHASES,
    }
    for transition in transitions:
        if set(transition.get("from_phase", [])).intersection(
            post_start
        ) and _transition_writes(transition).intersection(immutable):
            findings.append(
                _finding(
                    "commitment-immutability",
                    transition.get("id", "transition"),
                    f"post-evaluation transition writes {', '.join(sorted(_transition_writes(transition).intersection(immutable)))}",
                )
            )

    start = transition_index.get("TR-START-EVALUATION", {})
    if not {
        "G-BUDGET-RESERVED",
        "G-NO-PRIOR-EVALUATION",
        "G-VERIFICATION-MATERIAL-VALID",
    }.issubset(_transition_guard_ids(start)):
        findings.append(
            _finding(
                "query-budget",
                "TR-START-EVALUATION",
                "start must require reserved budget, no prior evaluation, and valid verification material",
            )
        )
    if not {
        "query_budget_state",
        "evaluation_started",
        "evaluation_attempt_id",
    }.issubset(_transition_writes(start)):
        findings.append(
            _finding(
                "query-budget",
                "TR-START-EVALUATION",
                "start must atomically consume budget and bind the attempt",
            )
        )
    required_start_failures = {
        "QUERY_BUDGET_MISSING",
        "QUERY_BUDGET_EXHAUSTED",
        "VERIFICATION_MATERIAL_MISSING",
        "VERIFICATION_MATERIAL_EXPIRED",
    }
    missing_start_failures = required_start_failures - set(
        start.get("failure_code", [])
    )
    if missing_start_failures:
        findings.append(
            _finding(
                "query-budget",
                "TR-START-EVALUATION",
                f"missing fail-closed cases: {', '.join(sorted(missing_start_failures))}",
            )
        )
    budget = model.get("query_budget_semantics", {})
    if (
        budget.get("authority") != "coordinator"
        or budget.get("reservation_required_before_evaluation") is not True
        or budget.get("consumption_point")
        != "atomically on first accepted start_evaluation"
    ):
        findings.append(
            _finding(
                "query-budget",
                "query_budget_semantics",
                "coordinator reservation and atomic first-start consumption are required",
            )
        )
    required_budget_semantics = {
        "unused_reservation_on_close": "RELEASED",
        "unused_reservation_on_abort": "RELEASED",
        "unused_reservation_on_expiry": "EXPIRED",
        "post_start_terminal_disposition": "CONSUMED",
        "authorization_ledger_assumption": "atomic",
        "released_reservation_reuse": "forbidden",
    }
    for field, token in required_budget_semantics.items():
        if token not in str(budget.get(field, "")):
            findings.append(
                _finding(
                    "query-budget",
                    f"query_budget_semantics.{field}",
                    f"must define the reviewed terminal reservation rule containing {token}",
                )
            )
    budget_type = str(variable_index.get("query_budget_state", {}).get("type", ""))
    if not {"RELEASED", "EXPIRED"}.issubset(
        set(budget_type.replace(">", "").split(","))
    ):
        findings.append(
            _finding(
                "query-budget",
                "state_variables.query_budget_state.type",
                "budget state must distinguish RELEASED and EXPIRED reservations",
            )
        )
    for transition_id, expected in (
        ("TR-CLOSE", "RELEASED"),
        ("TR-ABORT", "RELEASED"),
        ("TR-ADVANCE-TIME-EXPIRE", "EXPIRED"),
    ):
        transition = transition_index.get(transition_id, {})
        effect_text = " ".join(
            argument
            for item in transition.get("effects", [])
            for argument in item.get("arguments", [])
        )
        if (
            "query_budget_state" not in _transition_writes(transition)
            or expected not in effect_text
            or "CONSUMED remains CONSUMED" not in effect_text
        ):
            findings.append(
                _finding(
                    "query-budget",
                    transition_id,
                    "terminal transition must atomically dispose unused reservation without post-start refund",
                )
            )

    # Explicit authoritative-time semantics make expiry and deadline behavior a
    # literal next-state relation rather than a future TLA+ invention.
    required_time_transitions = {
        "TR-ADVANCE-TIME-NOOP",
        "TR-ADVANCE-TIME-LIVE",
        "TR-EVALUATION-TIMEOUT",
        "TR-CONSENT-EXPIRED",
        "TR-ADVANCE-TIME-EXPIRE",
    }
    missing_time_transitions = required_time_transitions - set(transition_index)
    if missing_time_transitions:
        findings.append(
            _finding(
                "authoritative-time",
                "transitions",
                f"missing time relations: {', '.join(sorted(missing_time_transitions))}",
            )
        )
    time_event = event_index.get("advance_authoritative_time", {})
    expire_event = event_index.get("expire_session", {})
    for event_id, event in (
        ("advance_authoritative_time", time_event),
        ("expire_session", expire_event),
    ):
        if event.get("delivery_class") != "timer" or event.get("parameters") != [
            "time_advance_parameter"
        ]:
            findings.append(
                _finding(
                    "authoritative-time",
                    f"events.{event_id}",
                    "clock event must be a timer with only time_advance_parameter",
                )
            )
        if event.get("default_failure_code") != "CLOCK_DOMAIN_INVALID":
            findings.append(
                _finding(
                    "clock-taxonomy",
                    f"events.{event_id}.default_failure_code",
                    "timer default must use the clock-specific declared taxonomy",
                )
            )
    if not AUTHORITATIVE_TIME_FAILURE_CODES.issubset(failure_code_ids):
        findings.append(
            _finding(
                "clock-taxonomy",
                "failure_taxonomy",
                "authoritative-time helper outcomes must all be declared",
            )
        )
    for code in CLOCK_FAILURE_CODES:
        failure = next((item for item in failures if item.get("code") == code), {})
        if failure.get(
            "party_error_category"
        ) != "CLOCK_ERROR" or "coordinator" not in str(
            failure.get("detail_visibility", "")
        ):
            findings.append(
                _finding(
                    "clock-taxonomy",
                    f"failure_taxonomy.{code}",
                    "clock detail must map to CLOCK_ERROR and remain coordinator/private-assurance only",
                )
            )
    for transition in transitions:
        if transition.get("event") not in {
            "advance_authoritative_time",
            "expire_session",
        }:
            continue
        failures_for_transition = set(transition.get("failure_code", []))
        if (
            "STALE_MESSAGE" in failures_for_transition
            or not CLOCK_FAILURE_CODES.issubset(failures_for_transition)
        ):
            findings.append(
                _finding(
                    "clock-taxonomy",
                    transition.get("id", "transition"),
                    "timer failures must declare clock codes and never reuse STALE_MESSAGE",
                )
            )
    live_time = transition_index.get("TR-ADVANCE-TIME-LIVE", {})
    if _transition_writes(live_time) != {
        "authoritative_time",
        "accepted_event_index",
        "canonical_transcript_head",
    } or not {
        "G-TIME-MONOTONIC",
        "G-TIME-DOMAIN",
        "G-TIME-INCREASES",
        "G-BEFORE-ALL-ACTIVE-DEADLINES",
    }.issubset(_transition_guard_ids(live_time)):
        findings.append(
            _finding(
                "authoritative-time",
                "TR-ADVANCE-TIME-LIVE",
                "live clock transition must update only time plus the accepted transcript and stay below every active deadline",
            )
        )
    expire_transition = transition_index.get("TR-ADVANCE-TIME-EXPIRE", {})
    if expire_transition.get("to_phase") != "EXPIRED" or not {
        "authoritative_time",
        "phase",
        "disclosure_state",
        "terminal_failure_code",
        "party_terminal_category",
        "query_budget_state",
    }.issubset(_transition_writes(expire_transition)):
        findings.append(
            _finding(
                "authoritative-time",
                "TR-ADVANCE-TIME-EXPIRE",
                "expiry crossing must atomically update time and terminal state",
            )
        )
    timeout = transition_index.get("TR-EVALUATION-TIMEOUT", {})
    if (
        "G-EVALUATION-DEADLINE-CROSSED" not in _transition_guard_ids(timeout)
        or timeout.get("to_phase") != "ABORTED"
        or "EVALUATION_TIMEOUT" not in timeout.get("failure_code", [])
    ):
        findings.append(
            _finding(
                "authoritative-time",
                "TR-EVALUATION-TIMEOUT",
                "evaluation timeout must compare authoritative time to the explicit deadline",
            )
        )
    if "evaluation_deadline" not in _transition_writes(start):
        findings.append(
            _finding(
                "authoritative-time",
                "TR-START-EVALUATION",
                "start_evaluation must set evaluation_deadline",
            )
        )
    clock = model.get("clock_and_expiry", {})
    if (
        clock.get("time_advance_event") != "advance_authoritative_time"
        or "authoritative_time" not in str(clock.get("stale_message_relation", ""))
        or "issued_at" not in str(clock.get("stale_message_relation", ""))
        or "atomic" not in str(clock.get("atomic_deadline_crossing", ""))
    ):
        findings.append(
            _finding(
                "authoritative-time",
                "clock_and_expiry",
                "clock policy must define event, message-time relation, and atomic deadline crossing",
            )
        )

    # Generic abort uses the supplied parameter and only declared abort-disposition
    # failures. It is never a participant-controlled failure selector.
    generic_abort = transition_index.get("TR-ABORT", {})
    abort_guard = next(
        (
            item
            for item in generic_abort.get("guards", [])
            if item.get("id") == "G-ABORT-REASON"
        ),
        {},
    )
    abort_effect = next(
        (
            item
            for item in generic_abort.get("effects", [])
            if item.get("id") == "E-ABORT"
        ),
        {},
    )
    failure_index = {item.get("code"): item for item in failures}
    invalid_abort_codes = {
        code
        for code in generic_abort.get("failure_code", [])
        if failure_index.get(code, {}).get("disposition") != "session-abort"
    }
    if (
        event_index.get("abort_session", {}).get("initiator") != ["coordinator"]
        or generic_abort.get("actor") != "coordinator"
        or generic_abort.get("to_phase") != "ABORTED"
        or abort_guard.get("reads")
        or abort_guard.get("parameter_reads")
        != ["normalized_failure_parameter.failure_code"]
        or not {"terminal_failure_code", "party_terminal_category"}.issubset(
            set(abort_effect.get("writes", []))
        )
        or abort_effect.get("parameter_reads")
        != ["normalized_failure_parameter.failure_code"]
        or invalid_abort_codes
    ):
        findings.append(
            _finding(
                "generic-abort",
                "TR-ABORT",
                "generic abort must be coordinator-only and atomically bind a declared abort-disposition event failure",
            )
        )

    consent_semantics = model.get("consent_semantics", {})
    if consent_semantics.get("expiry_or_withdrawal_policy") != "new-session-required":
        findings.append(
            _finding(
                "consent-lifecycle",
                "consent_semantics.expiry_or_withdrawal_policy",
                "v0.1 requires a new session after consent expiry or withdrawal",
            )
        )
    for party in ("A", "B"):
        grant = transition_index.get(f"TR-GRANT-CONSENT-{party}", {})
        withdrawal = transition_index.get(f"TR-WITHDRAW-CONSENT-{party}", {})
        if f"G-CONSENT-SLOT-EMPTY-{party}" not in _transition_guard_ids(grant):
            findings.append(
                _finding(
                    "consent-lifecycle",
                    f"TR-GRANT-CONSENT-{party}",
                    "same-session consent replacement must be forbidden",
                )
            )
        if (
            withdrawal.get("to_phase") != "ABORTED"
            or "CONSENT_WITHDRAWN" not in withdrawal.get("failure_code", [])
            or not {"terminal_failure_code", "party_terminal_category"}.issubset(
                _transition_writes(withdrawal)
            )
        ):
            findings.append(
                _finding(
                    "consent-lifecycle",
                    f"TR-WITHDRAW-CONSENT-{party}",
                    "withdrawal before completion must invalidate authorization and require a new session",
                )
            )
    consent_expiry = transition_index.get("TR-CONSENT-EXPIRED", {})
    if (
        consent_expiry.get("to_phase") != "ABORTED"
        or "CONSENT_EXPIRED" not in consent_expiry.get("failure_code", [])
        or "G-ACTIVE-CONSENT-EXPIRED" not in _transition_guard_ids(consent_expiry)
    ):
        findings.append(
            _finding(
                "consent-lifecycle",
                "TR-CONSENT-EXPIRED",
                "active consent expiry must atomically terminate same-session authorization",
            )
        )

    replay = model.get("replay_and_ordering", {})
    if replay.get("replay_domain") != ["session_id", "sender_participant_id"]:
        findings.append(
            _finding(
                "replay-domain",
                "replay_and_ordering.replay_domain",
                "must be (session_id,sender_participant_id)",
            )
        )
    if replay.get("message_identity") != [
        "sender_participant_id",
        "message_id",
        "nonce",
        "sequence",
        "issued_at",
        "canonical event digest",
    ]:
        findings.append(
            _finding(
                "idempotency",
                "replay_and_ordering.message_identity",
                "party message identity requires sender, message ID, nonce, sequence, issued_at, and canonical digest",
            )
        )
    if (
        replay.get("operation_domain") != ["actor_id"]
        or replay.get("operation_identity")
        != [
            "operation_id",
            "idempotency_key",
            "canonical operation digest",
            "current session binding",
        ]
        or replay.get("operation_independent_indexes")
        != [
            "operation_by_id",
            "operation_by_key",
        ]
    ):
        findings.append(
            _finding(
                "delivery-class",
                "replay_and_ordering.operation_domain",
                "coordinator operation deduplication must be actor scoped",
            )
        )
    if replay.get("profile_callback_identity") != [
        "callback_id",
        "idempotency_key",
        "canonical callback digest",
        "current profile/session/attempt binding",
    ] or replay.get("profile_callback_independent_indexes") != [
        "callback_by_id",
        "callback_by_key",
    ]:
        findings.append(
            _finding(
                "delivery-class",
                "replay_and_ordering.profile_callback_identity",
                "profile callback deduplication must bind callback ID, key, and digest",
            )
        )
    if "OUT_OF_ORDER" not in str(
        replay.get("future_sequence_gap", "")
    ) or "no buffering" not in str(replay.get("future_sequence_gap", "")):
        findings.append(
            _finding(
                "ordering-semantics",
                "replay_and_ordering.future_sequence_gap",
                "future gap must be OUT_OF_ORDER with no buffering",
            )
        )
    if "REPLAY" not in str(
        replay.get("stale_sequence", "")
    ) or "no state change" not in str(replay.get("stale_sequence", "")):
        findings.append(
            _finding(
                "ordering-semantics",
                "replay_and_ordering.stale_sequence",
                "stale sequence must reject without state change",
            )
        )
    if "REPLAY_CONFLICT" not in str(
        replay.get("conflicting_duplicate", "")
    ) or "no partial state change" not in str(replay.get("conflicting_duplicate", "")):
        findings.append(
            _finding(
                "idempotency",
                "replay_and_ordering.conflicting_duplicate",
                "conflicting duplicate must fail closed without partial state change",
            )
        )
    for party in ("A", "B"):
        retry_id = f"TR-RETRY-EXACT-DUPLICATE-{party}"
        retry = transition_index.get(retry_id, {})
        exact_guard = next(
            (
                item
                for item in retry.get("guards", [])
                if item.get("id") == f"G-EXACT-DUPLICATE-{party}"
            ),
            {},
        )
        prior_guard = next(
            (
                item
                for item in retry.get("guards", [])
                if item.get("id") == f"G-PRIOR-RESPONSE-{party}"
            ),
            {},
        )
        if (
            retry.get("mutating") is not False
            or _transition_writes(retry)
            or f"G-EXACT-DUPLICATE-{party}" not in _transition_guard_ids(retry)
            or "accepted_message_records" not in exact_guard.get("reads", [])
            or "normalized_message_responses" not in prior_guard.get("reads", [])
            or set(exact_guard.get("parameter_reads", []))
            != {
                "session_context.session_id",
                "replay_envelope.sender_participant_id",
                "replay_envelope.message_id",
                "replay_envelope.nonce",
                "replay_envelope.sequence",
                "replay_envelope.issued_at",
                "replay_envelope.canonical_event_digest",
            }
        ):
            findings.append(
                _finding(
                    "message-response-scope",
                    retry_id,
                    "exact replay must be a sender/session-scoped guarded no-op",
                )
            )
    for retry_id, guard_id in (
        ("TR-RETRY-EXACT-OPERATION", "G-EXACT-OPERATION-DUPLICATE"),
        (
            "TR-RETRY-EXACT-PROFILE-CALLBACK",
            "G-EXACT-PROFILE-CALLBACK-DUPLICATE",
        ),
    ):
        retry_transition = transition_index.get(retry_id, {})
        exact_guard = next(
            (
                item
                for item in retry_transition.get("guards", [])
                if item.get("id") == guard_id
            ),
            {},
        )
        expected_reads = (
            {"operation_by_id", "operation_by_key"}
            if retry_id == "TR-RETRY-EXACT-OPERATION"
            else {
                "callback_by_id",
                "callback_by_key",
                "selected_integration_profile_binding",
                "session_id",
                "evaluation_attempt_id",
            }
        )
        if (
            retry_transition.get("mutating") is not False
            or _transition_writes(retry_transition)
            or guard_id not in _transition_guard_ids(retry_transition)
            or not expected_reads.issubset(set(exact_guard.get("reads", [])))
        ):
            findings.append(
                _finding(
                    "idempotency",
                    retry_id,
                    "actor-scoped exact duplicate response must be a guarded no-op",
                )
            )

    for event_id in ("grant_consent_a", "grant_consent_b"):
        for transition in transitions:
            if transition.get("event") == event_id and not set(
                transition.get("from_phase", [])
            ).issubset({"RESULT_ACCEPTED", "CONSENT_PENDING"}):
                findings.append(
                    _finding(
                        "disclosure-guard",
                        transition.get("id", "transition"),
                        "consent is allowed only after result acceptance",
                    )
                )

    session_invariant = _index(invariants).get("INV-SESSION-BINDING", {})
    context_guard = next(
        (
            condition
            for condition in session_invariant.get("conditions", [])
            if condition.get("id") == "G-CONTEXT-BINDING"
        ),
        {},
    )
    expected_context = {
        "session_id",
        "protocol_profile",
        "policy_binding",
        "participant_binding",
        "intended_audience",
        "commitment_pair_id",
        "evaluation_attempt_id",
        "selected_integration_profile_binding",
    }
    if set(context_guard.get("reads", [])) != expected_context:
        findings.append(
            _finding(
                "session-binding",
                "INV-SESSION-BINDING",
                "context guard must bind session, version, policy, participants, audience, commitment pair, and attempt",
            )
        )

    timeout_transition = transition_index.get("TR-EVALUATION-TIMEOUT", {})
    if timeout_transition.get(
        "to_phase"
    ) != "ABORTED" or "EVALUATION_TIMEOUT" not in timeout_transition.get(
        "failure_code", []
    ):
        findings.append(
            _finding(
                "expiry",
                "TR-EVALUATION-TIMEOUT",
                "EVALUATION_TIMEOUT must terminate the current session as ABORTED",
            )
        )
    if "PARTIAL_PARTY_FAILURE" not in generic_abort.get("failure_code", []):
        findings.append(
            _finding(
                "expiry",
                "TR-ABORT",
                "generic abort must support declared PARTIAL_PARTY_FAILURE",
            )
        )

    audit = model.get("audit_policy", {})
    allowed_audit = set(audit.get("allowed_fields", []))
    if allowed_audit != REQUIRED_AUDIT_FIELDS:
        findings.append(
            _finding(
                "audit-policy",
                "audit_policy.allowed_fields",
                "allowed fields must equal the reviewed minimum set",
            )
        )
    if not PROHIBITED_AUDIT_FIELDS.issubset(set(audit.get("prohibited_fields", []))):
        findings.append(
            _finding(
                "audit-policy",
                "audit_policy.prohibited_fields",
                "required prohibited data classes are missing",
            )
        )
    for index, transition in enumerate(transitions):
        unexpected = (
            set(transition.get("audit_effect", {}).get("fields", [])) - allowed_audit
        )
        if unexpected:
            findings.append(
                _finding(
                    "audit-policy",
                    f"transitions.{index}.audit_effect.fields",
                    f"unapproved fields: {', '.join(sorted(unexpected))}",
                )
            )

    transcript = model.get("canonical_transcript_semantics", {})
    genesis_label = b"private-match-transcript-genesis/v0.1"
    expected_genesis = (
        "sha256:"
        + hashlib.sha256(
            len(genesis_label).to_bytes(2, "big") + genesis_label
        ).hexdigest()
    )
    expected_transcript_values = {
        "ordering_authority": "coordinator",
        "digest_algorithm": "SHA-256",
        "payload_domain": "private-match-payload/v0.1",
        "message_domain": "private-match-message/v0.1",
        "transcript_domain": "private-match-transcript/v0.1",
        "timer_event_domain": "private-match-timer-event/v0.1",
        "genesis_domain": "private-match-transcript-genesis/v0.1",
        "genesis_digest": expected_genesis,
        "timer_digest_source": "time_advance_parameter.canonical_event_digest",
    }
    for key, expected in expected_transcript_values.items():
        if transcript.get(key) != expected:
            findings.append(
                _finding(
                    "canonical-transcript",
                    f"canonical_transcript_semantics.{key}",
                    f"must equal {expected}",
                )
            )
    if transcript.get("external_message_digest_sources") != {
        "party_message": "replay_envelope.canonical_message_digest",
        "coordinator_command": "operation_envelope.canonical_message_digest",
        "profile_callback": "profile_callback_envelope.canonical_message_digest",
    }:
        findings.append(
            _finding(
                "canonical-transcript",
                "canonical_transcript_semantics.external_message_digest_sources",
                "delivery-class digest sources must match the envelope catalog",
            )
        )
    required_included = {"accepted", "mutating", "authoritative order"}
    required_excluded = {
        "rejected",
        "conflicting duplicates",
        "exact duplicates",
        "derived notices",
        "local guidance",
        "no-op",
    }
    included_text = str(transcript.get("included_relations", "")).lower()
    excluded_text = str(transcript.get("excluded_relations", "")).lower()
    if not all(token in included_text for token in required_included) or not all(
        token in excluded_text for token in required_excluded
    ):
        findings.append(
            _finding(
                "canonical-transcript",
                "canonical_transcript_semantics",
                "included and excluded accepted-event classes are incomplete",
            )
        )
    if (
        variable_index.get("canonical_transcript_head", {}).get("initial")
        != expected_genesis
        or variable_index.get("accepted_event_index", {}).get("initial") != "0"
    ):
        findings.append(
            _finding(
                "canonical-transcript",
                "state_variables",
                "transcript head/index initial values do not match the declared genesis",
            )
        )

    formal = model.get("formalization", {})
    if set(formal.get("state_variable_ids", [])) != variable_ids:
        findings.append(
            _finding(
                "formalization",
                "formalization.state_variable_ids",
                "must exactly map all state variables",
            )
        )
    if set(formal.get("invariant_ids", [])) != invariant_ids:
        findings.append(
            _finding(
                "formalization",
                "formalization.invariant_ids",
                "must exactly map all invariants",
            )
        )
    for clause in formal.get("initial_predicate", []):
        if clause.get("variable") not in variable_ids:
            findings.append(
                _finding(
                    "reference",
                    "formalization.initial_predicate",
                    f"undefined state variable {clause.get('variable')}",
                )
            )
    relation = {
        item.get("event"): set(item.get("transitions", []))
        for item in formal.get("event_relation", [])
    }
    if set(relation) != event_ids:
        findings.append(
            _finding(
                "formalization",
                "formalization.event_relation",
                "must map every event exactly once",
            )
        )
    for event_id in event_ids:
        expected = {
            item.get("id") for item in transitions if item.get("event") == event_id
        }
        if relation.get(event_id, set()) != expected:
            findings.append(
                _finding(
                    "formalization",
                    f"formalization.event_relation.{event_id}",
                    "transition mapping is incomplete or stale",
                )
            )
    if formal.get("tla_model_status") != "not created or model-checked in this issue":
        findings.append(
            _finding(
                "formalization",
                "formalization.tla_model_status",
                "must not claim a TLA+ result",
            )
        )
    fairness_text = " ".join(formal.get("fairness_candidates", [])).lower()
    environment_text = " ".join(formal.get("environment_assumptions", [])).lower()
    time_bound = next(
        (
            item
            for item in formal.get("bounded_model_parameters", [])
            if item.get("id") == "TimeDomain"
        ),
        {},
    )
    if (
        "timer" not in fairness_text
        or "clock" not in environment_text
        or "evaluation deadline" not in str(time_bound.get("constraint", ""))
        or "maximum-jump" not in str(time_bound.get("constraint", ""))
    ):
        findings.append(
            _finding(
                "formalization",
                "formalization.authoritative_time",
                "TLA+ readiness must include timer fairness, clock authority, deadline, and bounded jump semantics",
            )
        )

    clock = model.get("clock_and_expiry", {})
    if clock.get("timer_threshold_precedence") != [
        "SESSION_EXPIRY_THRESHOLD",
        "EVALUATION_DEADLINE",
        "CONSENT_EXPIRY_THRESHOLD",
        "COORDINATOR_CLOCK",
    ] or clock.get("timer_reason_effect_binding") != {
        "TR-ADVANCE-TIME-NOOP": "COORDINATOR_CLOCK",
        "TR-ADVANCE-TIME-LIVE": "COORDINATOR_CLOCK",
        "TR-ADVANCE-TIME-EXPIRE": "SESSION_EXPIRY_THRESHOLD",
        "TR-EVALUATION-TIMEOUT": "EVALUATION_DEADLINE",
        "TR-CONSENT-EXPIRED": "CONSENT_EXPIRY_THRESHOLD",
    }:
        findings.append(
            _finding(
                "authoritative-time",
                "clock_and_expiry.timer_threshold_precedence",
                "timer transition precedence and reason/effect binding must be complete and deterministic",
            )
        )
    clock_parameter = parameter_catalog.get("clock_policy", {})
    clock_fields = {item.get("id") for item in clock_parameter.get("fields", [])}
    if "maximum_jump" not in clock_fields or "maximum_time_jump" not in variable_ids:
        findings.append(
            _finding(
                "authoritative-time",
                "clock_policy.maximum_jump",
                "the reviewed maximum jump must be a catalog field and authoritative state variable",
            )
        )

    replay = model.get("replay_and_ordering", {})
    replay_order = replay.get("cached_response_validation_order", [])
    replay_exemptions = " ".join(
        replay.get("cached_response_dynamic_gate_exemptions", [])
    ).lower()
    wire = replay.get("canonical_wire_fingerprint", {})
    equality = " ".join(replay.get("accepted_record_equality", [])).lower()
    requester = replay.get("authenticated_requester_contract", {})
    requester_source = str(requester.get("source", "")).lower()
    requester_eligibility = str(requester.get("eligibility", "")).lower()
    requester_unauthorized = str(requester.get("unauthorized_behavior", "")).lower()
    if (
        len(replay_order) < 7
        or "transcript head" not in replay_exemptions
        or "material" not in replay_exemptions
        or "stateless" not in str(replay.get("stateless_validator_boundary", ""))
        or "recipient" not in str(replay.get("cached_response_effect", ""))
        or wire.get("domain") != "private-match-wire-message/v0.1"
        or "authentication.value" not in str(wire.get("canonicalization", ""))
        or "raw authentication.value is not retained"
        not in str(wire.get("stored_value", ""))
        or "canonical wire digest" not in equality
        or "original authenticated subject" not in equality
        or "never copied from replayed message" not in requester_source
        or "exact equality" not in requester_eligibility
        or "no cached response" not in requester_unauthorized
        or "no mutation" not in requester_unauthorized
    ):
        findings.append(
            _finding(
                "replay-ordering",
                "replay_and_ordering.cached_response_validation_order",
                "cached responses require full-wire equality, independent requester authorization, recipient scope, and a stateless boundary",
            )
        )

    required_reachable = {
        "CREATED",
        "PARTICIPANTS_BOUND",
        "COMMITMENTS_PENDING",
        "COMMITTED",
        "EVALUATING",
        "RESULT_ACCEPTED",
        "CLOSED",
        "ABORTED",
        "EXPIRED",
    }
    unreachable = required_reachable - reachable
    if unreachable:
        findings.append(
            _finding(
                "formalization",
                "transitions",
                f"core phase graph cannot reach: {', '.join(sorted(unreachable))}",
            )
        )

    # Issue #5 hardening: proposal acceptance is a distinct, immutable
    # prerequisite.  A binding transition must never provide an alternate
    # path around Party-specific exact-proposal acceptance.
    acceptance_semantics = model.get("session_acceptance_semantics", {})
    if set(acceptance_semantics) != {
        "proposal_binding",
        "party_acceptance",
        "binding_prerequisite",
        "downgrade_prevention",
        "trusted_subject_projection",
        "key_rotation_policy",
    }:
        findings.append(
            _finding(
                "session-acceptance",
                "session_acceptance_semantics",
                "complete proposal, Party acceptance, prerequisite, and downgrade semantics are required",
            )
        )
    create = transition_index.get("TR-CREATE", {})
    create_effect = next(
        (item for item in create.get("effects", []) if item.get("id") == "E-CREATE"),
        {},
    )
    if (
        "session_proposal_digest" not in create_effect.get("writes", [])
        or "selected_integration_profile_binding" not in create_effect.get("writes", [])
        or "session_proposal_parameter.proposal_digest"
        not in create_effect.get("parameter_reads", [])
        or "session_proposal_parameter.selected_integration_profile_binding"
        not in create_effect.get("parameter_reads", [])
    ):
        findings.append(
            _finding(
                "session-acceptance",
                "TR-CREATE.E-CREATE",
                "creation must bind the exact proposal digest and selected profile",
            )
        )
    for party in ("A", "B"):
        acceptance = transition_index.get(f"TR-ACCEPT-SESSION-{party}", {})
        if acceptance.get("event") != f"accept_session_{party.lower()}":
            findings.append(
                _finding(
                    "session-acceptance",
                    f"TR-ACCEPT-SESSION-{party}",
                    "Party acceptance must have its own event and transition",
                )
            )

        trusted_paths = {
            f"authenticated_subject_parameter.{field}"
            for field in (
                "actor",
                "participant_id",
                "key_id",
                "subject_binding_id",
                "verification_material_id",
            )
        }
        acceptance_effect = next(
            (
                item
                for item in acceptance.get("effects", [])
                if item.get("id") == f"E-ACCEPT-SESSION-{party}"
            ),
            {},
        )
        if not trusted_paths.issubset(
            set(acceptance_effect.get("parameter_reads", []))
        ):
            findings.append(
                _finding(
                    "session-acceptance",
                    f"TR-ACCEPT-SESSION-{party}",
                    "acceptance must atomically store the complete trusted subject projection",
                )
            )
        for suffix in ("FIRST", "COMPLETE"):
            binding = transition_index.get(f"TR-BIND-{party}-{suffix}", {})
            guard_ids = {item.get("id") for item in binding.get("guards", [])}
            if f"G-SESSION-ACCEPTED-{party}" not in guard_ids:
                findings.append(
                    _finding(
                        "session-acceptance",
                        f"TR-BIND-{party}-{suffix}",
                        "participant binding requires Party-specific exact-proposal acceptance",
                    )
                )
            subject_guard = next(
                (
                    item
                    for item in binding.get("guards", [])
                    if item.get("id") == f"G-SESSION-ACCEPTED-{party}"
                ),
                {},
            )
            required_binding = trusted_paths | {
                "participant_binding_parameter.participant_id",
                "participant_binding_parameter.key_id",
            }
            if not required_binding.issubset(
                set(subject_guard.get("parameter_reads", []))
            ):
                findings.append(
                    _finding(
                        "session-acceptance",
                        f"TR-BIND-{party}-{suffix}",
                        "binding must equal the accepted participant, key, subject, and material",
                    )
                )

    commitment_semantics = model.get("commitment_pair_derivation", {})
    if (
        commitment_semantics.get("domain") != "private-match-commitment-pair/v0.1"
        or commitment_semantics.get("canonicalization") != "RFC 8785 JCS"
        or commitment_semantics.get("slot_order") != ["party_a", "party_b"]
        or commitment_semantics.get("party_supplied_identifier") != "forbidden"
        or set(commitment_semantics.get("canonical_fields", []))
        != {
            "protocol_profile",
            "policy_binding",
            "session_id",
            "participant_binding.party_a",
            "participant_binding.party_b",
            "selected_integration_profile_binding",
            "commitment_a",
            "commitment_b",
        }
    ):
        findings.append(
            _finding(
                "commitment-pair-derivation",
                "commitment_pair_derivation",
                "v0.1 requires the complete deterministic coordinator-derived A/B binding",
            )
        )
    for transition_id in ("TR-COMMIT-A-COMPLETE", "TR-COMMIT-B-COMPLETE"):
        transition = transition_index.get(transition_id, {})
        guard = next(
            (
                item
                for item in transition.get("guards", [])
                if item.get("id") == "G-COMMITMENT-PAIR-CONTEXT"
            ),
            {},
        )
        if not {
            "protocol_profile",
            "policy_binding",
            "session_id",
            "participant_binding",
            "selected_integration_profile_binding",
            "commitment",
            "commitment_pair_id",
        }.issubset(set(guard.get("reads", []))):
            findings.append(
                _finding(
                    "commitment-pair-derivation",
                    transition_id,
                    "second commitment must read the complete immutable derivation context",
                )
            )

    cross_message = model.get("cross_message_binding_semantics", {})
    rules = {
        item.get("id"): item
        for item in cross_message.get("rules", [])
        if isinstance(item, dict)
    }
    required_rule_ids = {
        "XMSG-SESSION-ACCEPTANCE-SUBJECT",
        "XMSG-POLICY-ACCEPTANCE",
        "XMSG-COMMITMENT-PAIR",
        "XMSG-RECEIPT-ACCEPTANCE",
        "XMSG-CONSENT-BINDING",
    }
    if set(rules) != required_rule_ids or "no state" not in str(
        cross_message.get("atomic_failure_rule", "")
    ):
        findings.append(
            _finding(
                "cross-message-binding",
                "cross_message_binding_semantics",
                "all reviewed cross-message rules and atomic failure behavior are required",
            )
        )
    catalog_paths = {
        f"{parameter.get('id')}.{field.get('id')}"
        for parameter in model.get("event_parameter_catalog", [])
        for field in parameter.get("fields", [])
    }
    for rule_id, rule in rules.items():
        unknown_paths = set(rule.get("required_parameter_paths", [])) - catalog_paths
        if unknown_paths:
            findings.append(
                _finding(
                    "cross-message-binding",
                    rule_id,
                    "unknown required parameter paths: "
                    + ", ".join(sorted(unknown_paths)),
                )
            )

    return sorted(set(findings))


def validate(
    root: Path,
    artifact_path: Path | None = None,
    schema_path: Path | None = None,
) -> tuple[dict[str, Any] | None, list[Finding]]:
    artifact = artifact_path or root / ARTIFACT_PATH
    schema_file = schema_path or root / SCHEMA_PATH

    schema, findings = load_json(schema_file)
    if findings:
        return None, _relative_findings(findings, root)
    model, load_findings = load_yaml(artifact)
    if load_findings:
        return None, _relative_findings(load_findings, root)
    assert schema is not None and model is not None

    structural = schema_findings(model, schema)
    if structural:
        return model, structural
    return model, semantic_findings(model)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--artifact", type=Path)
    parser.add_argument("--schema", type=Path)
    parser.add_argument("--print-digest", action="store_true")
    args = parser.parse_args(argv)

    root = args.root.resolve()
    artifact = args.artifact.resolve() if args.artifact else None
    schema = args.schema.resolve() if args.schema else None
    model, findings = validate(root, artifact, schema)
    if findings:
        for finding in findings:
            print(finding.format())
        return 1

    assert model is not None
    suffix = f" sha256={canonical_digest(model)}" if args.print_digest else ""
    print(
        "session-state-machine: valid "
        f"phases={len(model['phases'])} "
        f"events={len(model['events'])} "
        f"transitions={len(model['transitions'])} "
        f"invariants={len(model['invariants'])}{suffix}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
