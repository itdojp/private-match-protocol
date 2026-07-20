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
}
REQUIRED_STATE_VARIABLES = {
    "phase",
    "session_id",
    "protocol_profile",
    "policy_binding",
    "intended_audience",
    "participant_binding",
    "commitment",
    "commitment_pair_id",
    "evaluation_started",
    "evaluation_attempt_id",
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
    "terminal_reason",
}
REQUIRED_INVARIANTS = {
    "INV-REVEAL-SAFETY",
    "INV-RESULT-SYMMETRY",
    "INV-COMMITMENT-IMMUTABILITY",
    "INV-SESSION-BINDING",
    "INV-NO-REPLAY",
    "INV-IDEMPOTENCY",
    "INV-ONE-EVALUATION",
    "INV-EXPIRY",
    "INV-MINIMUM-DISCLOSURE",
    "INV-OPAQUE-RECEIPT",
    "INV-QUERY-BUDGET",
    "INV-COORDINATOR-OUTCOME-CONFIDENTIALITY",
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
}
REQUIRED_SCOPE_EXCLUSIONS = {
    "PET selection or cryptographic implementation",
    "wire message fields or canonical encoding",
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
    for index, event in enumerate(events):
        if "prior normalized response" not in event.get("idempotency_behavior", ""):
            findings.append(
                _finding(
                    "idempotency",
                    f"events.{index}.idempotency_behavior",
                    "exact duplicate must return the prior normalized response",
                )
            )
        duplicate = event.get("duplicate_behavior", "")
        if (
            "REPLAY_CONFLICT" not in duplicate
            or "canonical event digest" not in duplicate
        ):
            findings.append(
                _finding(
                    "idempotency",
                    f"events.{index}.duplicate_behavior",
                    "conflicting ID or nonce must compare canonical digest and reject REPLAY_CONFLICT",
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
        "message_id",
        "nonce",
        "canonical event digest",
    ]:
        findings.append(
            _finding(
                "idempotency",
                "replay_and_ordering.message_identity",
                "exact duplicate identity requires message_id, nonce, and canonical digest",
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
        if (
            retry.get("mutating") is not False
            or _transition_writes(retry)
            or f"G-EXACT-DUPLICATE-{party}" not in _transition_guard_ids(retry)
        ):
            findings.append(
                _finding(
                    "idempotency", retry_id, "exact replay must be a guarded no-op"
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
    }
    if set(context_guard.get("reads", [])) != expected_context:
        findings.append(
            _finding(
                "session-binding",
                "INV-SESSION-BINDING",
                "context guard must bind session, version, policy, participants, audience, commitment pair, and attempt",
            )
        )

    for transition_id, code in (
        ("TR-EVALUATION-TIMEOUT", "EVALUATION_TIMEOUT"),
        ("TR-PARTIAL-PARTY-FAILURE", "PARTIAL_PARTY_FAILURE"),
    ):
        transition = transition_index.get(transition_id, {})
        if transition.get("to_phase") != "ABORTED" or code not in transition.get(
            "failure_code", []
        ):
            findings.append(
                _finding(
                    "expiry",
                    transition_id,
                    f"{code} must terminate the current session as ABORTED",
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
