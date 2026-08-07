#!/usr/bin/env python3
"""Closed experimental PET-profile authority, validation, and generation.

This module validates public contract artifacts only.  It never imports,
executes, or contacts SecretFlow, CIRCL, AWS, the Research repository, or the
private Product repository.
"""

from __future__ import annotations

import copy
import hashlib
import os
import stat
from pathlib import Path, PurePosixPath
from typing import Any

import yaml
from jsonschema import Draft202012Validator, FormatChecker

from canonicalize_message import canonicalize, strict_loads
from strict_yaml import strict_yaml_load
from validate_messages import validate_message_bytes


PROTOCOL_COMMIT = "9bb59d3b5e1435885fdea60280d6602f937305c9"
PROTOCOL_SOURCE_DIGEST = (
    "sha256:ed111a4bb8d6e662051940543bdf0c72503ff4b907018c1d76c7345b05ebf6a3"
)
STATE_MACHINE_DIGEST = (
    "sha256:32e514a61a83aeb1593623eb1144f323d1115dc8c812b5fd72af93a3ae06ba16"
)
MESSAGE_REGISTRY_DIGEST = (
    "sha256:df3eea26ad07b477912b124c96c9325676e9d1a89744e672f26c00538377a7ea"
)
MESSAGE_INPUT_TREE_DIGEST = (
    "sha256:4902a58e94110d4c1d3b5780daf5e9e059a7b39972911e0df23ee9cd993b5afa"
)
RESEARCH_COMMIT = "45607b57d61de5ff2d46a092dc24f6beb50dfe7c"
RESEARCH_FILES = {
    "decisions/ADR-0001-first-technology-bakeoff.md": "sha256:ccc3287ae979b95c62600cd8283b2389c05e44e076aa4836d4e034a01d4b2f9f",
    "benchmarks/experiment-matrix.yaml": "sha256:ff9a8b7bfb9353c0f38fad12aad120379c000859adeb07c913ba07452f7117ce",
    "benchmarks/result.schema.json": "sha256:b848e806353628c83d7e68a1c273e1da8b7541290a01952ae538a5696886603b",
    "records/technologies/secretflow-psi.yaml": "sha256:f570bcd8cde457e32bdc78c8202779146da7a40961bd44269df9347703d8b053",
    "records/technologies/rfc9497-circl-voprf.yaml": "sha256:b763711c3e648cd6c04f1d6e1c7936f0e2f5452a38b3606eb7e11fc83e8efe56",
    "records/technologies/aws-nitro-enclaves.yaml": "sha256:435d21640a369a211e8323e55ab51b2499aa771dbc840678a922efc18eeaeaab",
}
COMPLETE_PROFILE_IDS = {
    "private-match-experimental-secretflow-kkrt",
    "private-match-experimental-nitro-enclave",
}
COMPONENT_PROFILE_IDS = {"private-match-experimental-voprf-component"}
PROTOCOL_OUTPUTS = ["MATCH", "NO_MATCH", "INDETERMINATE"]
BARE_RESULT_RECEIPTS = {
    "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()
    for value in PROTOCOL_OUTPUTS
}
PROHIBITED_OUTPUTS = [
    "exact-intersection-count",
    "matching-elements",
    "non-matching-elements",
    "participant-identity",
    "private-input",
    "raw-identifier",
]
CALLBACK_BINDINGS = [
    "profile_id",
    "profile_version",
    "profile_digest",
    "profile_instance_id",
    "session_id",
    "policy_id",
    "policy_version",
    "participant_binding_digest",
    "commitment_pair_id",
    "evaluation_attempt_id",
    "opaque_receipt",
    "prior_transcript_head",
    "verification_material_reference",
    "verification_material_digest",
    "resource_policy_binding",
    "execution_authorization_digest",
]
RECEIPT_BINDINGS = [
    "session_id",
    "participant_binding_digest",
    "policy_id",
    "policy_version",
    "profile_id",
    "profile_version",
    "profile_digest",
    "profile_instance_id",
    "commitment_pair_id",
    "evaluation_attempt_id",
    "prior_transcript_head",
    "input_commitments",
    "verification_material_reference",
    "verification_material_digest",
    "resource_policy_binding",
    "execution_authorization_digest",
]
NITRO_RECEIPT_BINDINGS = [
    *RECEIPT_BINDINGS,
    "attestation_document_digest",
    "verifier_nonce",
    "pcr_policy_digest",
    "enclave_artifact_digest",
]
PROFILE_PATHS = {
    "private-match-experimental-secretflow-kkrt": Path(
        "profiles/pet-integration/secretflow-kkrt.v0.1.json"
    ),
    "private-match-experimental-nitro-enclave": Path(
        "profiles/pet-integration/nitro-enclave.v0.1.json"
    ),
    "private-match-experimental-voprf-component": Path(
        "profiles/pet-integration/voprf-component.v0.1.json"
    ),
}
AUTHORITY_PATH = Path("config/research-technology-authority.v0.1.json")
REGISTRY_PATH = Path("registry/pet-integration-profiles.v0.1.yaml")
HANDOFF_PATH = Path("handoff/product-decision-engine-port.v0.1.yaml")
BINDING_PATH = Path("specs/pet-integration/protocol-binding.v0.1.yaml")
CASE_CATALOG_PATH = Path("conformance/pet-profiles/case-catalog.v0.1.json")
CANONICAL_CALLBACK_PATH = Path(
    "conformance/pet-profiles/messages/result-acceptance-notice.v0.1.json"
)
STATE_MACHINE_PATH = Path("specs/state-machines/private-match-core-session-v0.1.yaml")
MESSAGE_REGISTRY_PATH = Path("registry/message-types.v0.1.yaml")
MESSAGE_SCHEMA_PATH = Path("schemas/messages/envelope.v0.1.schema.json")
MESSAGE_MATERIALS_PATH = Path("conformance/messages/verification-materials.v0.1.yaml")
GENERATED_ROOT = Path("generated/pet-integration")
SCHEMAS = {
    "authority": Path("schema/research-technology-authority.v0.1.schema.json"),
    "profile": Path("schema/pet-integration-profile.v0.1.schema.json"),
    "registry": Path("schema/pet-integration-profile-registry.v0.1.schema.json"),
    "handoff": Path("schema/product-decision-engine-handoff.v0.1.schema.json"),
    "binding": Path("schema/pet-protocol-binding.v0.1.schema.json"),
    "cases": Path("schema/pet-profile-conformance-cases.v0.1.schema.json"),
    "operation": Path("schema/pet-profile-operation-input.v0.1.schema.json"),
    "case_results": Path("schema/pet-profile-case-results.v0.1.schema.json"),
}
GENERATED_PATHS = {
    "index": GENERATED_ROOT / "profile-index.v0.1.json",
    "comparison": GENERATED_ROOT / "profile-comparison.v0.1.md",
    "handoff": GENERATED_ROOT / "product-handoff-projection.v0.1.json",
    "manifest": GENERATED_ROOT / "profile-digest-manifest.v0.1.json",
    "case_results": GENERATED_ROOT / "executable-case-results.v0.1.json",
}
MAX_FILE_BYTES = 2 * 1024 * 1024

DOMAINS = {
    "authority": b"private-match-research-technology-authority/v0.1\x00",
    "profile": b"private-match-pet-integration-profile/v0.1\x00",
    "registry": b"private-match-pet-profile-registry/v0.1\x00",
    "handoff": b"private-match-product-decision-engine-handoff/v0.1\x00",
    "binding": b"private-match-pet-protocol-binding/v0.1\x00",
    "cases": b"private-match-pet-profile-conformance-cases/v0.1\x00",
    "operation": b"private-match-pet-profile-operation-input/v0.1\x00",
    "case_results": b"private-match-pet-profile-executable-case-results/v0.1\x00",
    "execution_authorization": b"private-match-pet-execution-authorization/v0.1\x00",
    "index": b"private-match-pet-profile-index/v0.1\x00",
    "projection": b"private-match-product-handoff-projection/v0.1\x00",
    "manifest": b"private-match-pet-generated-manifest/v0.1\x00",
}


class PetProfileError(ValueError):
    """A bounded, value-free profile validation failure."""

    def __init__(self, code: str, logical_path: str = "artifact") -> None:
        super().__init__(f"{code}: {logical_path}")
        self.code = code
        self.logical_path = logical_path


def sha256_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def detached_digest(kind: str, value: dict[str, Any], field: str) -> str:
    material = copy.deepcopy(value)
    material.pop(field, None)
    return sha256_bytes(DOMAINS[kind] + canonicalize(material))


def _safe_relative(value: str) -> PurePosixPath:
    if not isinstance(value, str) or not value or "\\" in value:
        raise PetProfileError("PET-PATH-INVALID")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise PetProfileError("PET-PATH-INVALID")
    if len(path.parts) and path.parts[0].endswith(":"):
        raise PetProfileError("PET-PATH-INVALID")
    return path


def _regular_file(root: Path, relative: str | Path) -> Path:
    logical = str(relative)
    path = _safe_relative(logical)
    current = root.resolve()
    for part in path.parts:
        candidate = current / part
        try:
            mode = os.lstat(candidate).st_mode
        except OSError as error:
            raise PetProfileError("PET-FILE-MISSING", logical) from error
        if stat.S_ISLNK(mode):
            raise PetProfileError("PET-PATH-SYMLINK", logical)
        current = candidate
    try:
        mode = os.lstat(current).st_mode
        size = os.lstat(current).st_size
    except OSError as error:
        raise PetProfileError("PET-FILE-MISSING", logical) from error
    if not stat.S_ISREG(mode):
        raise PetProfileError("PET-PATH-NOT-FILE", logical)
    if size > MAX_FILE_BYTES:
        raise PetProfileError("PET-FILE-OVERSIZED", logical)
    return current


def load_json(root: Path, relative: str | Path) -> Any:
    path = _regular_file(root, relative)
    try:
        return strict_loads(path.read_bytes(), max_bytes=MAX_FILE_BYTES)
    except Exception as error:
        raise PetProfileError("PET-JSON-INVALID", str(relative)) from error


def load_yaml(root: Path, relative: str | Path) -> Any:
    path = _regular_file(root, relative)
    try:
        return strict_yaml_load(path.read_text(encoding="utf-8"))
    except (UnicodeError, yaml.YAMLError, ValueError) as error:
        raise PetProfileError("PET-YAML-INVALID", str(relative)) from error


def _schema_validate(value: Any, schema: dict[str, Any], logical: str) -> None:
    errors = sorted(
        Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(value),
        key=lambda item: list(item.absolute_path),
    )
    if errors:
        suffix = ".".join(map(str, errors[0].absolute_path))
        raise PetProfileError(
            "PET-SCHEMA-INVALID", f"{logical}{'.' + suffix if suffix else ''}"
        )


def load_repository(root: Path) -> dict[str, Any]:
    schemas = {key: load_json(root, path) for key, path in SCHEMAS.items()}
    for key, schema in schemas.items():
        try:
            Draft202012Validator.check_schema(schema)
        except Exception as error:
            raise PetProfileError("PET-SCHEMA-SELF-INVALID", key) from error
    values = {
        "root": root,
        "authority": load_json(root, AUTHORITY_PATH),
        "registry": load_yaml(root, REGISTRY_PATH),
        "handoff": load_yaml(root, HANDOFF_PATH),
        "binding": load_yaml(root, BINDING_PATH),
        "cases": load_json(root, CASE_CATALOG_PATH),
        "profiles": {key: load_json(root, path) for key, path in PROFILE_PATHS.items()},
        "state_machine": load_yaml(root, STATE_MACHINE_PATH),
        "message_registry": load_yaml(root, MESSAGE_REGISTRY_PATH),
        "message_schema": load_json(root, MESSAGE_SCHEMA_PATH),
        "message_materials": load_yaml(root, MESSAGE_MATERIALS_PATH),
    }
    for key in ("authority", "registry", "handoff", "binding", "cases"):
        _schema_validate(
            values[key],
            schemas[key],
            str(
                {
                    "authority": AUTHORITY_PATH,
                    "registry": REGISTRY_PATH,
                    "handoff": HANDOFF_PATH,
                    "binding": BINDING_PATH,
                    "cases": CASE_CATALOG_PATH,
                }[key]
            ),
        )
    for identifier, value in values["profiles"].items():
        _schema_validate(value, schemas["profile"], str(PROFILE_PATHS[identifier]))
    values["schemas"] = schemas
    return values


def _require(condition: bool, code: str, logical: str = "artifact") -> None:
    if not condition:
        raise PetProfileError(code, logical)


def validate_research_authority(authority: dict[str, Any]) -> None:
    _require(
        authority["repository"] == "itdojp/private-match-research",
        "PET-RESEARCH-REPOSITORY",
    )
    _require(authority["commit"] == RESEARCH_COMMIT, "PET-RESEARCH-COMMIT")
    _require(
        authority["issue"]["number"] == 4
        and authority["issue"]["state"] == "completed",
        "PET-RESEARCH-ISSUE",
    )
    observed = {item["path"]: item["digest"] for item in authority["artifacts"]}
    _require(observed == RESEARCH_FILES, "PET-RESEARCH-ARTIFACT-DIGEST")
    tracks = {item["track_id"]: item for item in authority["selected_tracks"]}
    _require(
        set(tracks) == {"secretflow-kkrt", "rfc9497-circl-voprf", "aws-nitro-enclave"},
        "PET-RESEARCH-TRACKS",
    )
    _require(
        tracks["secretflow-kkrt"]["source_revision"]
        == "d7682707035d6b3e04cc09b8bfef629140641432",
        "PET-RESEARCH-SECRET-FLOW-PIN",
    )
    _require(
        tracks["secretflow-kkrt"]["initial_protocol"] == "PROTOCOL_KKRT",
        "PET-RESEARCH-SECRET-FLOW-PROTOCOL",
    )
    _require(
        tracks["rfc9497-circl-voprf"]["source_revision"] == "v1.6.4",
        "PET-RESEARCH-CIRCL-PIN",
    )
    _require(
        tracks["rfc9497-circl-voprf"]["standard"] == "RFC 9497",
        "PET-RESEARCH-VOPRF-STANDARD",
    )
    _require(
        tracks["aws-nitro-enclave"]["source_revision"] == "v1.4.5"
        and tracks["aws-nitro-enclave"]["secondary_source_revision"] == "v0.5.2",
        "PET-RESEARCH-NITRO-PIN",
    )
    _require(
        tracks["secretflow-kkrt"]["source_repository"] == "secretflow/psi"
        and tracks["secretflow-kkrt"]["execution_authorization"] == "not-provided",
        "PET-RESEARCH-SECRET-FLOW-AUTHORITY",
    )
    _require(
        tracks["rfc9497-circl-voprf"]["source_repository"] == "cloudflare/circl"
        and tracks["rfc9497-circl-voprf"]["secondary_source_revision"] == "RFC 9497"
        and tracks["rfc9497-circl-voprf"]["execution_authorization"] == "not-provided",
        "PET-RESEARCH-VOPRF-AUTHORITY",
    )
    _require(
        tracks["aws-nitro-enclave"]["source_repository"] == "aws/aws-nitro-enclaves-cli"
        and tracks["aws-nitro-enclave"]["secondary_source_repository"]
        == "aws/aws-nitro-enclaves-nsm-api"
        and tracks["aws-nitro-enclave"]["execution_authorization"]
        == "human-required-not-provided",
        "PET-RESEARCH-NITRO-AUTHORITY",
    )
    _require(
        all(item["local_result_status"] == "not-run" for item in tracks.values()),
        "PET-LOCAL-RESULT-PROMOTION",
    )
    _require(
        authority["production_selection_status"] == "not-selected",
        "PET-PRODUCTION-PROMOTION",
    )
    _require(
        authority["authority_digest"]
        == detached_digest("authority", authority, "authority_digest"),
        "PET-RESEARCH-AUTHORITY-DIGEST",
    )


def _validate_profile(
    profile: dict[str, Any],
    authority_digest: str,
    expected_operations: dict[str, tuple[Any, ...]],
) -> None:
    identifier = profile["profile_id"]
    expected_tracks = {
        "private-match-experimental-secretflow-kkrt": "secretflow-kkrt",
        "private-match-experimental-nitro-enclave": "aws-nitro-enclave",
        "private-match-experimental-voprf-component": "rfc9497-circl-voprf",
    }
    _require(profile["profile_version"] == "0.1", "PET-PROFILE-VERSION", identifier)
    _require(
        profile["artifact_status"] == "experimental", "PET-PROFILE-STATUS", identifier
    )
    _require(
        profile["research_authority_binding"]["authority_digest"] == authority_digest,
        "PET-RESEARCH-AUTHORITY-STALE",
        identifier,
    )
    _require(
        profile["research_authority_binding"]["track_id"]
        == expected_tracks.get(identifier),
        "PET-RESEARCH-TRACK-BINDING",
        identifier,
    )
    _require(
        profile["production_eligible"] is False, "PET-PRODUCTION-ELIGIBLE", identifier
    )
    _require(
        profile["execution_authorization"]
        in {"not-provided", "human-required-not-provided"},
        "PET-EXECUTION-AUTHORIZATION",
        identifier,
    )
    execution = profile["execution_contract"]
    _require(
        execution
        == {
            "contract_registration_allowed": True,
            "synthetic_contract_fixture_allowed": True,
            "candidate_execution_authorized": False,
            "production_execution_authorized": False,
            "required_external_authority": {
                "private-match-experimental-secretflow-kkrt": "reviewed-local-experiment-execution-grant",
                "private-match-experimental-nitro-enclave": "reviewed-paid-aws-experiment-execution-grant",
                "private-match-experimental-voprf-component": "reviewed-local-component-experiment-execution-grant",
            }[identifier],
            "missing_authority_behavior": "unsupported",
            "authorization_binding_required": True,
        },
        "PET-EXECUTION-CONTRACT",
        identifier,
    )
    _require(
        profile["profile_digest"]
        == detached_digest("profile", profile, "profile_digest"),
        "PET-PROFILE-DIGEST",
        identifier,
    )
    _require(profile["security_model"]["model_id"], "PET-SECURITY-MODEL", identifier)
    _require(profile["trust_model"]["model_id"], "PET-TRUST-MODEL", identifier)
    privacy = profile["privacy_and_operations"]
    _require(privacy["metadata_leakage"], "PET-LEAKAGE-MODEL", identifier)
    _require(
        privacy["repeated_query_controls"], "PET-REPEATED-QUERY-CONTROL", identifier
    )
    _require(
        profile["protocol_contract"]["key_or_attestation_responsibilities"],
        "PET-VERIFICATION-RESPONSIBILITY",
        identifier,
    )
    pins = {
        (item["repository"], item["revision"], item["revision_kind"])
        for item in profile["implementation_source_pins"]
    }
    _require(
        privacy["cancellation"]["cleanup_required"] is True
        and privacy["cleanup"]["required"] is True,
        "PET-CANCELLATION-CLEANUP",
        identifier,
    )
    for hook in profile["protocol_contract"]["evidence_hooks"]:
        _require(
            not set(hook["allowed_fields"])
            & {
                "private_input",
                "raw_identifier",
                "matching_element",
                "secret_material",
            },
            "PET-EVIDENCE-SECRET",
            identifier,
        )
    if profile["profile_class"] == "complete-decision-profile":
        _require(
            identifier in COMPLETE_PROFILE_IDS,
            "PET-COMPLETE-PROFILE-UNKNOWN",
            identifier,
        )
        _require(
            profile["protocol_contract"]["supported_decision_outputs"]
            == PROTOCOL_OUTPUTS,
            "PET-DECISION-OUTPUTS",
            identifier,
        )
        _require(
            profile["decision_derivation"]
            == {
                "authority": "Protocol-policy-binding",
                "exact_policy_binding_required": True,
                "profile_may_select_default_policy": False,
                "profile_may_change_policy_after_evaluation_start": False,
                "unknown_policy_behavior": "fail-closed",
                "result_vocabulary": PROTOCOL_OUTPUTS,
                "derivation_evidence_required": True,
                "correctness_status": "not-established",
                "limitations": [
                    "Candidate execution has not been performed.",
                    "Policy correctness and input completeness are not established.",
                ],
            },
            "PET-DECISION-POLICY",
            identifier,
        )
        _require(
            profile["protocol_contract"]["result_symmetry"]["required"] is True,
            "PET-RESULT-SYMMETRY",
            identifier,
        )
        _require(
            profile["privacy_and_operations"]["prohibited_output_classes"]
            == PROHIBITED_OUTPUTS,
            "PET-PROHIBITED-OUTPUT",
            identifier,
        )
        _require(
            profile["protocol_contract"]["opaque_receipt"]["minimum_entropy_bits"]
            >= 128,
            "PET-LOW-ENTROPY-RECEIPT",
            identifier,
        )
        expected_receipt_bindings = (
            NITRO_RECEIPT_BINDINGS
            if identifier == "private-match-experimental-nitro-enclave"
            else RECEIPT_BINDINGS
        )
        _require(
            profile["protocol_contract"]["opaque_receipt"]["binding_fields"]
            == expected_receipt_bindings,
            "PET-RECEIPT-BINDING",
            identifier,
        )
        _require(
            profile["protocol_contract"]["callback"]["required_bindings"]
            == CALLBACK_BINDINGS,
            "PET-CALLBACK-BINDING",
            identifier,
        )
        expected_exchange = {
            operation: expected_operations[operation]
            for operation in (
                "reserve-query-budget",
                "start-evaluation",
                "submit-contribution",
                "acknowledge-receipt",
                "accept-profile-callback",
            )
        }
        observed_exchange = {
            item["operation"]: _operation_authority_projection(item)
            for item in profile["protocol_contract"]["exchange_steps"]
        }
        _require(
            observed_exchange == expected_exchange,
            "PET-PROTOCOL-EXCHANGE-BINDING",
            identifier,
        )
        _require(
            profile["protocol_contract"]["transcript_domain"]["state_machine_digest"]
            == STATE_MACHINE_DIGEST,
            "PET-STATE-MACHINE-DIGEST",
            identifier,
        )
        _require(
            profile["protocol_contract"]["transcript_domain"]["message_registry_digest"]
            == MESSAGE_REGISTRY_DIGEST,
            "PET-MESSAGE-REGISTRY-DIGEST",
            identifier,
        )
        _require(
            profile["complete_decision_contract"]["coordinator_plaintext_result"]
            == "prohibited",
            "PET-COORDINATOR-PLAINTEXT",
            identifier,
        )
        _require(
            profile["protocol_contract"]["opaque_receipt"]["prohibited_constructions"]
            == [
                "bare hash of MATCH",
                "bare hash of NO_MATCH",
                "bare hash of INDETERMINATE",
                "low-entropy enumerable receipt",
            ],
            "PET-LOW-ENTROPY-RECEIPT",
            identifier,
        )
        if identifier == "private-match-experimental-secretflow-kkrt":
            _require(
                pins
                == {
                    (
                        "secretflow/psi",
                        "d7682707035d6b3e04cc09b8bfef629140641432",
                        "git-commit",
                    )
                },
                "PET-SECRET-FLOW-SOURCE-PIN",
                identifier,
            )
            _require(
                profile["security_model"]["model_id"] == "semi-honest"
                and profile["security_model"]["malicious_party_security"]
                == "not-established",
                "PET-PSI-SECURITY-ESCALATION",
                identifier,
            )
        else:
            _require(
                pins
                == {
                    ("aws/aws-nitro-enclaves-cli", "v1.4.5", "release-tag"),
                    ("aws/aws-nitro-enclaves-nsm-api", "v0.5.2", "release-tag"),
                },
                "PET-NITRO-SOURCE-PIN",
                identifier,
            )
            _require(
                profile["execution_authorization"] == "human-required-not-provided",
                "PET-EXECUTION-AUTHORIZATION",
                identifier,
            )
    else:
        _require(
            identifier in COMPONENT_PROFILE_IDS,
            "PET-COMPONENT-PROFILE-UNKNOWN",
            identifier,
        )
        component = profile["component_contract"]
        _require(
            component["complete_engine"] is False
            and component["selectable_as_complete_profile"] is False,
            "PET-COMPONENT-AS-COMPLETE",
            identifier,
        )
        _require(
            component["set_semantics_defined"] is False
            and component["symmetric_decision_defined"] is False,
            "PET-VOPRF-COMPLETE-CLAIM",
            identifier,
        )
        _require(
            profile["protocol_contract"]["supported_decision_outputs"] == [],
            "PET-VOPRF-DECISION-OUTPUT",
            identifier,
        )
        _require(
            pins
            == {
                ("cloudflare/circl", "v1.6.4", "release-tag"),
                (
                    "https://www.rfc-editor.org/rfc/rfc9497",
                    "RFC 9497",
                    "rfc",
                ),
            },
            "PET-VOPRF-SOURCE-PIN",
            identifier,
        )


def _validate_handoff_semantics(handoff: dict[str, Any]) -> None:
    expected_fields = {
        "engine-profile-identifier",
        "security-trust-model",
        "supported-decision-types",
        "client-side-preparation",
        "protocol-exchange-steps",
        "result-and-verification-receipt",
        "verification-material-key-attestation",
        "metadata-leakage-descriptor",
        "resource-limits",
        "timeout",
        "deterministic-error-categories",
        "cancellation",
        "cleanup",
        "evidence-hooks",
        "decision-policy-binding",
        "execution-authorization",
    }
    _require(
        {item["field"] for item in handoff["port_fields"]} == expected_fields,
        "PET-HANDOFF-COVERAGE",
    )
    _require(
        handoff["selection_rule"]["complete_profile_required"] is True
        and handoff["selection_rule"]["component_only_rejected"] is True,
        "PET-HANDOFF-SELECTION",
    )
    handoff_fields = {item["field"]: item for item in handoff["port_fields"]}
    _require(
        "no use-case predicate or threshold is selected"
        in handoff_fields["decision-policy-binding"]["public_semantic_meaning"]
        and "reject missing, unknown, changed, defaulted, or substituted policy authority"
        == handoff_fields["decision-policy-binding"]["fail_closed_rule"],
        "PET-HANDOFF-POLICY-SEMANTICS",
    )
    execution_handoff = handoff_fields["execution-authorization"]
    _require(
        "do not authorize candidate or production execution"
        in execution_handoff["public_semantic_meaning"]
        and "return unsupported when reviewed candidate authority is missing; production execution is unsupported"
        == execution_handoff["fail_closed_rule"]
        and {"credential", "raw execution grant"}
        <= set(execution_handoff["prohibited_content"]),
        "PET-HANDOFF-EXECUTION-SEMANTICS",
    )


def validate_semantics(values: dict[str, Any]) -> None:
    authority = values["authority"]
    validate_research_authority(authority)
    profiles = values["profiles"]
    expected_operations = expected_protocol_operations(
        values["message_registry"], values["state_machine"]
    )
    _require(
        set(profiles) == COMPLETE_PROFILE_IDS | COMPONENT_PROFILE_IDS, "PET-PROFILE-SET"
    )
    for identifier, profile in profiles.items():
        _require(profile["profile_id"] == identifier, "PET-PROFILE-PATH-ID", identifier)
        _validate_profile(profile, authority["authority_digest"], expected_operations)
    complete_models = {
        (
            profiles[item]["security_model"]["model_id"],
            profiles[item]["trust_model"]["model_id"],
        )
        for item in COMPLETE_PROFILE_IDS
    }
    _require(len(complete_models) == 2, "PET-COMPLETE-PROFILES-NOT-MATERIAL-DIFFERENT")

    registry = values["registry"]
    _require(
        registry["research_authority_digest"] == authority["authority_digest"],
        "PET-REGISTRY-RESEARCH-DIGEST",
    )
    pins = registry["protocol_authority"]
    _require(
        pins
        == {
            "repository": "itdojp/private-match-protocol",
            "commit": PROTOCOL_COMMIT,
            "source_revision_digest": PROTOCOL_SOURCE_DIGEST,
            "profile": "private-match-core",
            "version": "0.1",
            "state_machine_digest": STATE_MACHINE_DIGEST,
            "message_registry_digest": MESSAGE_REGISTRY_DIGEST,
            "message_input_tree_digest": MESSAGE_INPUT_TREE_DIGEST,
        },
        "PET-PROTOCOL-AUTHORITY",
    )
    _require(
        [item["profile_id"] for item in registry["complete_profiles"]]
        == sorted(COMPLETE_PROFILE_IDS),
        "PET-REGISTRY-COMPLETE",
    )
    _require(
        [item["profile_id"] for item in registry["component_profiles"]]
        == sorted(COMPONENT_PROFILE_IDS),
        "PET-REGISTRY-COMPONENT",
    )
    for collection, expected_class in (
        (registry["complete_profiles"], "complete-decision-profile"),
        (registry["component_profiles"], "component-only"),
    ):
        for entry in collection:
            profile = profiles[entry["profile_id"]]
            _require(entry["profile_class"] == expected_class, "PET-REGISTRY-CLASS")
            _require(
                entry["path"] == PROFILE_PATHS[entry["profile_id"]].as_posix(),
                "PET-REGISTRY-PATH",
            )
            _require(
                entry["digest"] == profile["profile_digest"],
                "PET-REGISTRY-PROFILE-DIGEST",
            )
    _require(
        registry["registry_digest"]
        == detached_digest("registry", registry, "registry_digest"),
        "PET-REGISTRY-DIGEST",
    )

    binding = values["binding"]
    _require(
        binding["state_machine_digest"] == STATE_MACHINE_DIGEST
        and binding["message_registry_digest"] == MESSAGE_REGISTRY_DIGEST,
        "PET-BINDING-AUTHORITY",
    )
    operation_targets = [
        (tuple(item["events"]), item["message_type"], tuple(item["transition_ids"]))
        for item in binding["operations"]
    ]
    _require(
        len(operation_targets) == len(set(operation_targets)),
        "PET-BINDING-DUPLICATE-ALIAS",
    )
    required_operations = set(expected_operations)
    _require(
        {item["operation"] for item in binding["operations"]} == required_operations,
        "PET-BINDING-OPERATIONS",
    )
    observed_operations = {
        item["operation"]: _operation_authority_projection(item)
        for item in binding["operations"]
    }
    _require(
        observed_operations == expected_operations,
        "PET-BINDING-SEMANTICS",
    )
    _require(
        all(
            item["allowed_profile_classes"] == ["complete-decision-profile"]
            for item in binding["operations"]
        ),
        "PET-BINDING-PROFILE-CLASS",
    )
    _require(
        binding["callback_required_bindings"] == CALLBACK_BINDINGS,
        "PET-BINDING-CALLBACK",
    )
    _require(
        binding["binding_digest"]
        == detached_digest("binding", binding, "binding_digest"),
        "PET-BINDING-DIGEST",
    )

    handoff = values["handoff"]
    _validate_handoff_semantics(handoff)
    _require(
        handoff["handoff_digest"]
        == detached_digest("handoff", handoff, "handoff_digest"),
        "PET-HANDOFF-DIGEST",
    )
    validate_case_catalog(values, root=None)


INVALID_CASE_CODES = {
    # Original fail-closed coverage.
    "unknown-profile": "PET-PROFILE-UNKNOWN",
    "wrong-version": "PET-PROFILE-VERSION",
    "component-selected": "PET-COMPONENT-AS-COMPLETE",
    "cross-profile-callback": "PET-CROSS-PROFILE",
    "wrong-profile-instance": "PET-PROFILE-INSTANCE",
    "wrong-evaluation-attempt": "PET-EVALUATION-ATTEMPT",
    "wrong-receipt": "PET-RECEIPT-BINDING",
    "wrong-transcript-head": "PET-TRANSCRIPT-MISMATCH",
    "result-asymmetry": "PET-RESULT-SYMMETRY",
    "exact-count": "PET-PROHIBITED-OUTPUT",
    "matching-element": "PET-PROHIBITED-OUTPUT",
    "coordinator-plaintext-result": "PET-COORDINATOR-PLAINTEXT",
    "low-entropy-receipt": "PET-LOW-ENTROPY-RECEIPT",
    "missing-verification-material": "PET-VERIFICATION-MATERIAL",
    "psi-security-escalation": "PET-PSI-SECURITY-ESCALATION",
    "tee-debug-mode": "PET-TEE-DEBUG-MODE",
    "tee-stale-nonce": "PET-TEE-FRESH-NONCE",
    "tee-wrong-pcr-policy": "PET-TEE-PCR-POLICY",
    "tee-unapproved-execution": "PET-CANDIDATE-EXECUTION-UNAUTHORIZED",
    "voprf-complete-engine": "PET-VOPRF-COMPLETE-CLAIM",
    "secret-evidence-hook": "PET-EVIDENCE-SECRET",
    "query-budget-bypass": "PET-QUERY-BUDGET",
    "cancellation-without-cleanup": "PET-CANCELLATION-CLEANUP",
    "unknown-error-category": "PET-FAILURE-MAPPING",
    # Executable-authority and Product-handoff coverage.
    "unknown-symmetric-decision": "PET-DECISION-UNKNOWN",
    "callback-session-mismatch": "PET-SESSION-BINDING",
    "callback-policy-mismatch": "PET-POLICY-BINDING",
    "participant-binding-mismatch": "PET-PARTICIPANT-BINDING",
    "commitment-pair-mismatch": "PET-COMMITMENT-BINDING",
    "profile-digest-mismatch": "PET-PROFILE-DIGEST-BINDING",
    "verification-material-reference-mismatch": "PET-VERIFICATION-MATERIAL",
    "verification-material-digest-mismatch": "PET-VERIFICATION-MATERIAL",
    "resource-policy-mismatch": "PET-RESOURCE-POLICY",
    "missing-authoritative-context-field": "PET-AUTHORITATIVE-CONTEXT-MISSING",
    "secretflow-unapproved-candidate-execution": "PET-CANDIDATE-EXECUTION-UNAUTHORIZED",
    "nitro-unapproved-candidate-execution": "PET-CANDIDATE-EXECUTION-UNAUTHORIZED",
    "production-execution": "PET-PRODUCTION-EXECUTION-UNSUPPORTED",
    "fixture-with-candidate-flag": "PET-CANDIDATE-EXECUTION-UNAUTHORIZED",
    "unknown-execution-mode": "PET-EXECUTION-MODE",
    "message-delivery-class-mismatch": "PET-MESSAGE-DELIVERY-CLASS",
    "message-direction-mismatch": "PET-MESSAGE-DIRECTION",
    "wrong-callback-sender": "PET-MESSAGE-SENDER",
    "wrong-callback-verifier": "PET-MESSAGE-VERIFIER",
    "duplicate-callback-operation-alias": "PET-BINDING-DUPLICATE-ALIAS",
    "unexecuted-valid-case": "PET-CASE-NOT-EXECUTED",
    "decision-policy-default": "PET-DECISION-POLICY",
    "decision-policy-changed-after-start": "PET-DECISION-POLICY",
    "wrong-handoff-execution-semantics": "PET-HANDOFF-EXECUTION-SEMANTICS",
    "missing-policy-binding": "PET-POLICY-BINDING",
    "wrong-policy-id": "PET-POLICY-BINDING",
    "wrong-policy-version": "PET-POLICY-BINDING",
    "receipt-policy-substitution": "PET-RECEIPT-POLICY",
    "execution-authorization-digest-substitution": "PET-EXECUTION-AUTHORIZATION-BINDING",
}

OPERATION_MESSAGE_TYPES = {
    "select-profile": "session_proposal",
    "reserve-query-budget": "query_budget_reservation",
    "start-evaluation": "evaluation_start",
    "submit-contribution": "evaluation_contribution",
    "acknowledge-receipt": "opaque_receipt_ack",
    "accept-profile-callback": "result_acceptance_notice",
    "abort-and-cleanup": "abort_notice",
}

FIXTURE_PARTICIPANTS = {
    "party_a": {
        "participant_id": "urn:private-match:test:participant:a",
        "key_id": "urn:private-match:test:key:party-a:v0.1",
    },
    "party_b": {
        "participant_id": "urn:private-match:test:participant:b",
        "key_id": "urn:private-match:test:key:party-b:v0.1",
    },
}


def _operation_authority_projection(item: dict[str, Any]) -> tuple[Any, ...]:
    return (
        tuple(item["events"]),
        item["message_type"],
        item["message_version"],
        item["delivery_class"],
        item["direction"],
        tuple(item["allowed_senders"]),
        item["verifier"],
        tuple(item["intended_audience"]),
        tuple(item["transition_ids"]),
        item["transcript_participation"],
        item["replay_idempotency_domain"],
    )


def expected_protocol_operations(
    message_registry: dict[str, Any], state_machine: dict[str, Any]
) -> dict[str, tuple[Any, ...]]:
    """Project the reviewed Message Registry and State Machine exactly."""

    messages = {item["message_type"]: item for item in message_registry["messages"]}
    transitions = {item["id"]: item for item in state_machine["transitions"]}
    expected: dict[str, tuple[Any, ...]] = {}
    for operation, message_type in OPERATION_MESSAGE_TYPES.items():
        _require(message_type in messages, "PET-BINDING-MESSAGE-UNKNOWN")
        message = messages[message_type]
        ids = message["state_machine"]["transitions"]
        _require(
            all(
                item in transitions
                and transitions[item]["event"] in message["state_machine"]["events"]
                for item in ids
            ),
            "PET-BINDING-STATE-PARITY",
        )
        expected[operation] = (
            tuple(message["state_machine"]["events"]),
            message_type,
            message["message_version"],
            message["delivery_class"],
            message["direction"],
            tuple(message["allowed_senders"]),
            message["verifier"],
            tuple(message["intended_audience"]),
            tuple(ids),
            message["transcript_participation"],
            message["replay_or_idempotency_domain"],
        )
    timeout = transitions.get("TR-EVALUATION-TIMEOUT")
    _require(
        timeout is not None and timeout["event"] == "advance_authoritative_time",
        "PET-BINDING-STATE-PARITY",
    )
    expected["evaluation-timeout"] = (
        ("advance_authoritative_time",),
        None,
        None,
        "internal-event",
        "internal",
        ("protocol-timer",),
        "coordinator",
        ("coordinator",),
        ("TR-EVALUATION-TIMEOUT",),
        "accepted-mutating-event",
        "authoritative timer threshold",
    )
    return expected


def _fixture_digest(label: bytes, value: Any) -> str:
    return sha256_bytes(label + canonicalize(value))


def _execution_authorization(profile: dict[str, Any], instance: str) -> dict[str, Any]:
    material = {
        "state": (
            "registration-only"
            if profile["profile_class"] == "component-only"
            else "contract-fixture-only"
        ),
        "authority_reference": "urn:private-match:test:execution-authority:contract-fixture:v0.1",
        "source_revision_digest": _fixture_digest(
            b"private-match-pet-source-revisions/v0.1\x00",
            profile["implementation_source_pins"],
        ),
        "environment_id": "synthetic-local-offline",
        "expires_at": "2027-01-31T00:00:00Z",
        "candidate_execution_authorized": False,
        "production_execution_authorized": False,
        "profile_id": profile["profile_id"],
        "profile_version": profile["profile_version"],
        "profile_digest": profile["profile_digest"],
        "profile_instance_id": instance,
    }
    digest = _fixture_digest(DOMAINS["execution_authorization"], material)
    return {
        key: value
        for key, value in material.items()
        if key
        not in {
            "profile_id",
            "profile_version",
            "profile_digest",
            "profile_instance_id",
        }
    } | {"authority_digest": digest}


def _execution_authorization_digest(
    profile: dict[str, Any], instance: str, authorization: dict[str, Any]
) -> str:
    material = {
        key: value for key, value in authorization.items() if key != "authority_digest"
    } | {
        "profile_id": profile["profile_id"],
        "profile_version": profile["profile_version"],
        "profile_digest": profile["profile_digest"],
        "profile_instance_id": instance,
    }
    return _fixture_digest(DOMAINS["execution_authorization"], material)


def operation_input_for_case(
    values: dict[str, Any], item: dict[str, Any]
) -> dict[str, Any]:
    """Derive one complete operation input from a catalogued synthetic case."""

    profile = values["profiles"][item["profile_id"]]
    operation = item["operation"]
    instance = (
        f"urn:private-match:test:profile-instance:{profile['technology_family']}:0001"
    )
    session = "urn:private-match:test:session:pet-profile:0001"
    policy_id = "urn:private-match:test:policy:public-binding"
    policy_version = "0.1"
    participants = copy.deepcopy(FIXTURE_PARTICIPANTS)
    participant_digest = _fixture_digest(
        b"private-match-pet-participant-binding/v0.1\x00", participants
    )
    commitment = "sha256:" + "31" * 32
    prior = "sha256:" + "42" * 32
    current = "sha256:" + "43" * 32
    verification_ref = "urn:private-match:test:material:profile:v0.1"
    verification_digest = "sha256:" + "54" * 32
    resource_policy = "sha256:" + "65" * 32
    opaque_receipt = "sha256:" + "76" * 32
    authorization = _execution_authorization(profile, instance)
    execution_mode = (
        "registration"
        if profile["profile_class"] == "component-only"
        else "contract-fixture"
    )
    if operation in {"select-profile", "reserve-query-budget"}:
        query = {"reserved": False, "consumption_count": 0}
    elif operation == "start-evaluation":
        query = {"reserved": True, "consumption_count": 0}
    else:
        query = {"reserved": True, "consumption_count": 1}
    context = {
        "protocol_profile": "private-match-core",
        "protocol_version": "0.1",
        "state_machine_digest": STATE_MACHINE_DIGEST,
        "message_registry_digest": MESSAGE_REGISTRY_DIGEST,
        "pet_registry_digest": values["registry"]["registry_digest"],
        "profile_id": profile["profile_id"],
        "profile_version": profile["profile_version"],
        "profile_digest": profile["profile_digest"],
        "profile_class": profile["profile_class"],
        "profile_instance_id": instance,
        "session_id": session,
        "policy_id": policy_id,
        "policy_version": policy_version,
        "participant_binding": participants,
        "participant_binding_digest": participant_digest,
        "commitment_pair_id": commitment,
        "evaluation_attempt_id": "urn:private-match:test:evaluation:pet-profile:0001",
        "prior_transcript_head": prior,
        "current_transcript_head": current,
        "verification_material_reference": verification_ref,
        "verification_material_digest": verification_digest,
        "query_budget_state": query,
        "resource_policy_binding": resource_policy,
        "execution_mode": execution_mode,
        "execution_authorization": authorization,
    }
    if operation == "register-component":
        message = {
            "message_type": None,
            "message_version": None,
            "delivery_class": "registry",
            "direction": "local-validation",
            "allowed_senders": ["registry-authority"],
            "verifier": "product-profile-loader",
            "intended_audience": ["product-profile-loader"],
            "failure_category": "UNKNOWN_STATE",
        }
    else:
        binding = next(
            entry
            for entry in values["binding"]["operations"]
            if entry["operation"] == operation
        )
        message = binding
    receipt = {
        "session_id": session,
        "policy_id": policy_id,
        "policy_version": policy_version,
        "profile_id": profile["profile_id"],
        "profile_version": profile["profile_version"],
        "profile_digest": profile["profile_digest"],
        "profile_instance_id": instance,
        "participant_binding_digest": participant_digest,
        "commitment_pair_id": commitment,
        "evaluation_attempt_id": context["evaluation_attempt_id"],
        "opaque_receipt": opaque_receipt,
        "prior_transcript_head": prior,
        "verification_material_reference": verification_ref,
        "verification_material_digest": verification_digest,
        "resource_policy_binding": resource_policy,
        "execution_authorization_digest": authorization["authority_digest"],
    }
    sender = item.get("party_slot")
    sender_role = (
        f"party_{sender}_client"
        if sender in {"a", "b"}
        else message["allowed_senders"][0]
    )
    presented = {
        "operation": operation,
        "message_type": message["message_type"],
        "message_version": message["message_version"],
        "delivery_class": message["delivery_class"],
        "direction": message["direction"],
        "sender_role": sender_role,
        "verifier_role": message["verifier"],
        "intended_audience": message["intended_audience"],
        "profile_id": profile["profile_id"],
        "profile_version": profile["profile_version"],
        "profile_digest": profile["profile_digest"],
        "profile_class": profile["profile_class"],
        "profile_instance_id": instance,
        "session_id": session,
        "policy_id": policy_id,
        "policy_version": policy_version,
        "participant_binding_digest": participant_digest,
        "commitment_pair_id": commitment,
        "evaluation_attempt_id": context["evaluation_attempt_id"],
        "prior_transcript_head": prior,
        "opaque_receipt": opaque_receipt,
        "receipt_bindings": receipt,
        "verification_material_reference": verification_ref,
        "verification_material_digest": verification_digest,
        "party_results": {"party_a": "MATCH", "party_b": "MATCH"},
        "output_classes": [],
        "normalized_failure_category": message["failure_category"],
        "query_budget_reserved": query["reserved"],
        "query_budget_consumption_count": query["consumption_count"],
        "resource_policy_binding": resource_policy,
        "profile_supplied_default_policy": False,
        "policy_changed_after_evaluation_start": False,
        "execution_mode": execution_mode,
        "synthetic": True,
        "network_execution": "prohibited",
        "candidate_execution": False,
        "production_execution": False,
        "paid_resource_use": False,
        "execution_authorization_digest": authorization["authority_digest"],
        "cancellation_requested": operation == "abort-and-cleanup",
        "cleanup_completed": True,
        "canonical_message_path": item.get("canonical_message_path"),
        "coordinator_plaintext_result": False,
        "receipt_entropy_bits": 256,
        "security_claim": "reviewed-profile-only",
        "tee": {"debug_mode": False, "fresh_nonce": True, "pcr_policy_matches": True},
        "component_complete_engine_claim": False,
        "evidence_fields": ["profile_id", "profile_version", "profile_digest"],
    }
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "schema_version": "0.1",
        "record_type": "pet-profile-operation-input",
        "artifact_status": "experimental",
        "synthetic": True,
        "authoritative_context": context,
        "presented_operation": presented,
    }


def _validate_canonical_callback(
    values: dict[str, Any], record: dict[str, Any], raw: bytes
) -> None:
    context = record["authoritative_context"]
    operation = record["presented_operation"]
    materials = copy.deepcopy(values["message_materials"])
    material = next(
        item
        for item in materials["materials"]
        if item["verification_material_id"]
        == context["verification_material_reference"]
    )
    material["subject"].update(
        {
            "profile_id": context["profile_id"],
            "profile_version": context["profile_version"],
            "profile_instance_id": context["profile_instance_id"],
        }
    )
    message_context = {
        "authoritative_time": "2026-07-21T00:00:30Z",
        "allowed_clock_skew_seconds": 60,
        "message_stale_threshold_seconds": 300,
        "prior_transcript_digest": context["prior_transcript_head"],
        "session_context": {
            "session_id": context["session_id"],
            "policy": {
                "policy_id": context["policy_id"],
                "policy_version": context["policy_version"],
            },
            "participants": context["participant_binding"],
            "intended_audience": ["party_a_client", "party_b_client"],
            "commitment_pair_id": context["commitment_pair_id"],
            "evaluation_attempt_id": context["evaluation_attempt_id"],
            "selected_integration_profile": {
                "profile_id": context["profile_id"],
                "profile_version": context["profile_version"],
                "profile_instance_id": context["profile_instance_id"],
            },
        },
    }
    message, findings = validate_message_bytes(
        raw,
        values["message_schema"],
        values["message_registry"],
        materials,
        message_context,
        path="pet-profile-callback",
    )
    _require(not findings and message is not None, "PET-CANONICAL-MESSAGE-INVALID")
    assert message is not None
    _require(message["message_type"] == operation["message_type"], "PET-MESSAGE-TYPE")
    _require(
        message["message_version"] == operation["message_version"],
        "PET-MESSAGE-VERSION",
    )
    _require(
        message["delivery_class"] == operation["delivery_class"],
        "PET-MESSAGE-DELIVERY-CLASS",
    )
    _require(
        message["sender"]["actor"] == operation["sender_role"], "PET-MESSAGE-SENDER"
    )
    _require(
        message["audience"] == operation["intended_audience"], "PET-MESSAGE-AUDIENCE"
    )
    identity = message["identity"]
    for key in (
        "profile_id",
        "profile_version",
        "profile_instance_id",
        "session_id",
        "evaluation_attempt_id",
    ):
        _require(identity[key] == context[key], "PET-CANONICAL-CALLBACK-BINDING")
    _require(
        message["payload"]["opaque_receipt_ref"] == operation["opaque_receipt"],
        "PET-RECEIPT-BINDING",
    )
    _require(
        message["prior_transcript_digest"] == context["prior_transcript_head"],
        "PET-TRANSCRIPT-MISMATCH",
    )
    _require(
        message["authentication"]["verification_material_id"]
        == context["verification_material_reference"],
        "PET-VERIFICATION-MATERIAL",
    )


def validate_operation_input(
    values: dict[str, Any],
    record: dict[str, Any],
    *,
    canonical_message_bytes: bytes | None = None,
) -> dict[str, Any]:
    """Validate one complete operation against its supplied authority context."""

    required_context = set(
        values["schemas"]["operation"]["properties"]["authoritative_context"][
            "required"
        ]
    )
    observed_context = record.get("authoritative_context")
    _require(isinstance(observed_context, dict), "PET-AUTHORITATIVE-CONTEXT-MISSING")
    _require(
        required_context <= set(observed_context), "PET-AUTHORITATIVE-CONTEXT-MISSING"
    )
    presented = record.get("presented_operation")
    _require(isinstance(presented, dict), "PET-OPERATION-MISSING")
    raw_results = presented.get("party_results")
    _require(
        isinstance(raw_results, dict) and set(raw_results) == {"party_a", "party_b"},
        "PET-PARTY-SLOT-SET",
    )
    _require(
        all(
            isinstance(value, str) and value in PROTOCOL_OUTPUTS
            for value in raw_results.values()
        ),
        "PET-DECISION-UNKNOWN",
    )
    _schema_validate(record, values["schemas"]["operation"], "operation-input")
    context = record["authoritative_context"]
    operation = presented
    profiles = values["profiles"]
    identifier = context["profile_id"]
    _require(identifier in profiles, "PET-PROFILE-UNKNOWN")
    profile = profiles[identifier]
    _require(
        context["profile_version"] == profile["profile_version"], "PET-PROFILE-VERSION"
    )
    _require(
        context["profile_digest"] == profile["profile_digest"],
        "PET-PROFILE-DIGEST-BINDING",
    )
    _require(context["profile_class"] == profile["profile_class"], "PET-PROFILE-CLASS")
    _require(
        context["protocol_profile"] == "private-match-core"
        and context["protocol_version"] == "0.1",
        "PET-PROTOCOL-AUTHORITY",
    )
    _require(
        context["state_machine_digest"] == STATE_MACHINE_DIGEST,
        "PET-STATE-MACHINE-DIGEST",
    )
    _require(
        context["message_registry_digest"] == MESSAGE_REGISTRY_DIGEST,
        "PET-MESSAGE-REGISTRY-DIGEST",
    )
    _require(
        context["pet_registry_digest"] == values["registry"]["registry_digest"],
        "PET-REGISTRY-DIGEST",
    )
    _require(
        context["participant_binding_digest"]
        == _fixture_digest(
            b"private-match-pet-participant-binding/v0.1\x00",
            context["participant_binding"],
        ),
        "PET-PARTICIPANT-BINDING",
    )
    authorization = context["execution_authorization"]
    expected_authorization_state = (
        "registration-only"
        if profile["profile_class"] == "component-only"
        else "contract-fixture-only"
    )
    _require(
        authorization["state"] == expected_authorization_state
        and authorization["authority_reference"]
        == "urn:private-match:test:execution-authority:contract-fixture:v0.1"
        and authorization["source_revision_digest"]
        == _fixture_digest(
            b"private-match-pet-source-revisions/v0.1\x00",
            profile["implementation_source_pins"],
        )
        and authorization["environment_id"] == "synthetic-local-offline"
        and authorization["expires_at"] == "2027-01-31T00:00:00Z"
        and authorization["candidate_execution_authorized"] is False
        and authorization["production_execution_authorized"] is False,
        "PET-EXECUTION-AUTHORIZATION-BINDING",
    )
    _require(
        authorization["authority_digest"]
        == _execution_authorization_digest(
            profile, context["profile_instance_id"], authorization
        ),
        "PET-EXECUTION-AUTHORIZATION-BINDING",
    )
    exact_fields = {
        "profile_id": "PET-CROSS-PROFILE",
        "profile_version": "PET-PROFILE-VERSION",
        "profile_digest": "PET-PROFILE-DIGEST-BINDING",
        "profile_class": "PET-PROFILE-CLASS",
        "profile_instance_id": "PET-PROFILE-INSTANCE",
        "session_id": "PET-SESSION-BINDING",
        "policy_id": "PET-POLICY-BINDING",
        "policy_version": "PET-POLICY-BINDING",
        "participant_binding_digest": "PET-PARTICIPANT-BINDING",
        "commitment_pair_id": "PET-COMMITMENT-BINDING",
        "evaluation_attempt_id": "PET-EVALUATION-ATTEMPT",
        "prior_transcript_head": "PET-TRANSCRIPT-MISMATCH",
        "verification_material_reference": "PET-VERIFICATION-MATERIAL",
        "verification_material_digest": "PET-VERIFICATION-MATERIAL",
        "resource_policy_binding": "PET-RESOURCE-POLICY",
    }
    for field, code in exact_fields.items():
        _require(operation[field] == context[field], code)
    _require(
        operation["execution_authorization_digest"]
        == context["execution_authorization"]["authority_digest"],
        "PET-EXECUTION-AUTHORIZATION-BINDING",
    )
    receipt_codes = {
        "policy_id": "PET-RECEIPT-POLICY",
        "policy_version": "PET-RECEIPT-POLICY",
    }
    for field in operation["receipt_bindings"]:
        if field == "execution_authorization_digest":
            expected = operation["execution_authorization_digest"]
        elif field == "opaque_receipt":
            expected = operation["opaque_receipt"]
        else:
            expected = context[field]
        _require(
            operation["receipt_bindings"][field] == expected,
            receipt_codes.get(field, "PET-RECEIPT-BINDING"),
        )

    op_name = operation["operation"]
    if op_name == "register-component":
        _require(
            profile["profile_class"] == "component-only", "PET-COMPONENT-AS-COMPLETE"
        )
        _require(operation["message_type"] is None, "PET-MESSAGE-TYPE")
        _require(
            operation["delivery_class"] == "registry", "PET-MESSAGE-DELIVERY-CLASS"
        )
        _require(operation["direction"] == "local-validation", "PET-MESSAGE-DIRECTION")
        _require(operation["sender_role"] == "registry-authority", "PET-MESSAGE-SENDER")
        _require(
            operation["verifier_role"] == "product-profile-loader",
            "PET-MESSAGE-VERIFIER",
        )
        _require(
            operation["normalized_failure_category"] == "UNKNOWN_STATE",
            "PET-FAILURE-MAPPING",
        )
    else:
        _require(
            profile["profile_class"] == "complete-decision-profile",
            "PET-COMPONENT-AS-COMPLETE",
        )
        mapping = {item["operation"]: item for item in values["binding"]["operations"]}
        _require(op_name in mapping, "PET-OPERATION-UNKNOWN")
        binding = mapping[op_name]
        _require(
            operation["message_type"] == binding["message_type"], "PET-MESSAGE-TYPE"
        )
        _require(
            operation["message_version"] == binding["message_version"],
            "PET-MESSAGE-VERSION",
        )
        _require(
            operation["delivery_class"] == binding["delivery_class"],
            "PET-MESSAGE-DELIVERY-CLASS",
        )
        _require(
            operation["direction"] == binding["direction"], "PET-MESSAGE-DIRECTION"
        )
        _require(
            operation["sender_role"] in binding["allowed_senders"], "PET-MESSAGE-SENDER"
        )
        _require(
            operation["verifier_role"] == binding["verifier"], "PET-MESSAGE-VERIFIER"
        )
        _require(
            operation["intended_audience"] == binding["intended_audience"],
            "PET-MESSAGE-AUDIENCE",
        )
        _require(
            operation["normalized_failure_category"] == binding["failure_category"],
            "PET-FAILURE-MAPPING",
        )

    results = operation["party_results"]
    _require(set(results) == {"party_a", "party_b"}, "PET-PARTY-SLOT-SET")
    _require(
        all(value in PROTOCOL_OUTPUTS for value in results.values()),
        "PET-DECISION-UNKNOWN",
    )
    _require(results["party_a"] == results["party_b"], "PET-RESULT-SYMMETRY")
    _require(
        not operation["profile_supplied_default_policy"]
        and not operation["policy_changed_after_evaluation_start"],
        "PET-DECISION-POLICY",
    )
    _require(
        not set(operation["output_classes"]) & set(PROHIBITED_OUTPUTS),
        "PET-PROHIBITED-OUTPUT",
    )
    _require(
        operation["coordinator_plaintext_result"] is False, "PET-COORDINATOR-PLAINTEXT"
    )
    _require(
        operation["opaque_receipt"] not in BARE_RESULT_RECEIPTS
        and operation["receipt_entropy_bits"] >= 128,
        "PET-LOW-ENTROPY-RECEIPT",
    )
    _require(
        operation["verification_material_reference"]
        and operation["verification_material_digest"],
        "PET-VERIFICATION-MATERIAL",
    )
    if identifier == "private-match-experimental-secretflow-kkrt":
        _require(
            operation["security_claim"] != "malicious-party-secure",
            "PET-PSI-SECURITY-ESCALATION",
        )
    if identifier == "private-match-experimental-nitro-enclave":
        _require(operation["tee"]["debug_mode"] is False, "PET-TEE-DEBUG-MODE")
        _require(operation["tee"]["fresh_nonce"], "PET-TEE-FRESH-NONCE")
        _require(operation["tee"]["pcr_policy_matches"], "PET-TEE-PCR-POLICY")
    _require(
        not operation["component_complete_engine_claim"], "PET-VOPRF-COMPLETE-CLAIM"
    )
    _require(
        not set(operation["evidence_fields"])
        & {"private_input", "raw_identifier", "matching_element", "secret_material"},
        "PET-EVIDENCE-SECRET",
    )
    _require(
        operation["query_budget_reserved"] == context["query_budget_state"]["reserved"]
        and operation["query_budget_consumption_count"]
        == context["query_budget_state"]["consumption_count"],
        "PET-QUERY-BUDGET",
    )
    if op_name not in {"register-component", "select-profile", "reserve-query-budget"}:
        _require(operation["query_budget_reserved"], "PET-QUERY-BUDGET")
    if operation["cancellation_requested"]:
        _require(operation["cleanup_completed"], "PET-CANCELLATION-CLEANUP")
    expected_mode = (
        "registration"
        if profile["profile_class"] == "component-only"
        else "contract-fixture"
    )
    _require(
        context["execution_mode"] == expected_mode
        and operation["execution_mode"] == expected_mode,
        "PET-EXECUTION-MODE",
    )
    _require(
        operation["synthetic"] is True
        and operation["network_execution"] == "prohibited"
        and operation["paid_resource_use"] is False,
        "PET-EXECUTION-BOUNDARY",
    )
    _require(
        operation["candidate_execution"] is False
        and context["execution_authorization"]["candidate_execution_authorized"]
        is False,
        "PET-CANDIDATE-EXECUTION-UNAUTHORIZED",
    )
    _require(
        operation["production_execution"] is False
        and context["execution_authorization"]["production_execution_authorized"]
        is False,
        "PET-PRODUCTION-EXECUTION-UNSUPPORTED",
    )
    _require(
        profile["execution_contract"]["candidate_execution_authorized"] is False
        and profile["execution_contract"]["production_execution_authorized"] is False,
        "PET-EXECUTION-CONTRACT",
    )

    if operation["canonical_message_path"] is not None:
        _require(
            op_name == "accept-profile-callback", "PET-CANONICAL-MESSAGE-OPERATION"
        )
        raw = canonical_message_bytes
        if raw is None:
            root = values["root"]
            raw = _regular_file(root, operation["canonical_message_path"]).read_bytes()
        _validate_canonical_callback(values, record, raw)
    result = {
        "status": "accepted",
        "operation": op_name,
        "profile_id": identifier,
        "result_digest": "",
    }
    result["result_digest"] = _fixture_digest(
        DOMAINS["operation"], {k: v for k, v in result.items() if k != "result_digest"}
    )
    return result


def _mutate_operation_input(values: dict[str, Any], mutation: str) -> dict[str, Any]:
    profile_id = "private-match-experimental-secretflow-kkrt"
    if mutation.startswith("tee-") or mutation.startswith("nitro-"):
        profile_id = "private-match-experimental-nitro-enclave"
    if mutation in {"component-selected", "voprf-complete-engine"}:
        profile_id = "private-match-experimental-voprf-component"
    operation = (
        "register-component"
        if mutation == "voprf-complete-engine"
        else "accept-profile-callback"
    )
    item = {
        "profile_id": profile_id,
        "operation": operation,
        "party_slot": None,
        "canonical_message_path": None,
    }
    record = operation_input_for_case(values, item)
    c, p = record["authoritative_context"], record["presented_operation"]
    if mutation == "unknown-profile":
        c["profile_id"] = p["profile_id"] = "private-match-experimental-unknown"
    elif mutation == "wrong-version":
        c["profile_version"] = p["profile_version"] = "9.9"
    elif mutation == "component-selected":
        p["operation"] = "select-profile"
    elif mutation in {"cross-profile-callback"}:
        p["profile_id"] = "private-match-experimental-nitro-enclave"
    elif mutation == "wrong-profile-instance":
        p["profile_instance_id"] = "fixture-other-instance"
    elif mutation == "wrong-evaluation-attempt":
        p["evaluation_attempt_id"] = "fixture-other-attempt"
    elif mutation == "wrong-receipt":
        p["opaque_receipt"] = "sha256:" + "c3" * 32
    elif mutation == "wrong-transcript-head":
        p["prior_transcript_head"] = "sha256:" + "d4" * 32
    elif mutation == "result-asymmetry":
        p["party_results"]["party_b"] = "NO_MATCH"
    elif mutation == "unknown-symmetric-decision":
        p["party_results"] = {
            "party_a": "UNREVIEWED_DECISION",
            "party_b": "UNREVIEWED_DECISION",
        }
    elif mutation == "exact-count":
        p["output_classes"] = ["exact-intersection-count"]
    elif mutation == "matching-element":
        p["output_classes"] = ["matching-elements"]
    elif mutation == "coordinator-plaintext-result":
        p["coordinator_plaintext_result"] = True
    elif mutation == "low-entropy-receipt":
        bare = "sha256:" + hashlib.sha256(b"MATCH").hexdigest()
        p["opaque_receipt"] = bare
        p["receipt_bindings"]["opaque_receipt"] = bare
    elif mutation == "missing-verification-material":
        p["verification_material_reference"] = "urn:private-match:test:material:missing"
    elif mutation == "psi-security-escalation":
        p["security_claim"] = "malicious-party-secure"
    elif mutation == "tee-debug-mode":
        p["tee"]["debug_mode"] = True
    elif mutation == "tee-stale-nonce":
        p["tee"]["fresh_nonce"] = False
    elif mutation == "tee-wrong-pcr-policy":
        p["tee"]["pcr_policy_matches"] = False
    elif mutation in {
        "tee-unapproved-execution",
        "secretflow-unapproved-candidate-execution",
        "nitro-unapproved-candidate-execution",
        "fixture-with-candidate-flag",
    }:
        p["candidate_execution"] = True
    elif mutation == "voprf-complete-engine":
        p["component_complete_engine_claim"] = True
    elif mutation == "secret-evidence-hook":
        p["evidence_fields"] = ["private_input"]
    elif mutation == "query-budget-bypass":
        p["query_budget_reserved"] = False
    elif mutation == "cancellation-without-cleanup":
        p["cancellation_requested"] = True
        p["cleanup_completed"] = False
    elif mutation == "unknown-error-category":
        p["normalized_failure_category"] = "VENDOR_RAW_FAILURE"
    elif mutation == "callback-session-mismatch":
        p["session_id"] = "urn:private-match:test:session:other"
    elif mutation in {"callback-policy-mismatch", "wrong-policy-id"}:
        p["policy_id"] = "urn:private-match:test:policy:other"
    elif mutation == "wrong-policy-version":
        p["policy_version"] = "9.9"
    elif mutation == "missing-policy-binding":
        p["policy_id"] = "urn:private-match:test:policy:missing"
    elif mutation == "receipt-policy-substitution":
        p["receipt_bindings"]["policy_id"] = "urn:private-match:test:policy:other"
    elif mutation == "participant-binding-mismatch":
        p["participant_binding_digest"] = "sha256:" + "81" * 32
    elif mutation == "commitment-pair-mismatch":
        p["commitment_pair_id"] = "sha256:" + "82" * 32
    elif mutation == "profile-digest-mismatch":
        p["profile_digest"] = "sha256:" + "83" * 32
    elif mutation == "verification-material-reference-mismatch":
        p["verification_material_reference"] = "urn:private-match:test:material:other"
    elif mutation == "verification-material-digest-mismatch":
        p["verification_material_digest"] = "sha256:" + "84" * 32
    elif mutation == "resource-policy-mismatch":
        p["resource_policy_binding"] = "sha256:" + "85" * 32
    elif mutation == "missing-authoritative-context-field":
        del c["session_id"]
    elif mutation == "production-execution":
        p["production_execution"] = True
    elif mutation == "unknown-execution-mode":
        p["execution_mode"] = "vendor-live"
    elif mutation == "message-delivery-class-mismatch":
        p["delivery_class"] = "party_message"
    elif mutation == "message-direction-mismatch":
        p["direction"] = "outbound"
    elif mutation == "wrong-callback-sender":
        p["sender_role"] = "coordinator"
    elif mutation == "wrong-callback-verifier":
        p["verifier_role"] = "party_a_client"
    elif mutation == "decision-policy-default":
        p["profile_supplied_default_policy"] = True
    elif mutation == "decision-policy-changed-after-start":
        p["policy_changed_after_evaluation_start"] = True
    elif mutation == "execution-authorization-digest-substitution":
        p["execution_authorization_digest"] = "sha256:" + "86" * 32
    return record


def _execute_invalid_case(values: dict[str, Any], mutation: str) -> None:
    if mutation == "duplicate-callback-operation-alias":
        targets = [
            (tuple(x["events"]), x["message_type"], tuple(x["transition_ids"]))
            for x in values["binding"]["operations"]
        ]
        targets.append(next(x for x in targets if x[1] == "result_acceptance_notice"))
        _require(len(targets) == len(set(targets)), "PET-BINDING-DUPLICATE-ALIAS")
        return
    if mutation == "unexecuted-valid-case":
        raise PetProfileError("PET-CASE-NOT-EXECUTED")
    if mutation == "wrong-handoff-execution-semantics":
        handoff = copy.deepcopy(values["handoff"])
        execution = next(
            item
            for item in handoff["port_fields"]
            if item["field"] == "execution-authorization"
        )
        execution["fail_closed_rule"] = "accept an unreviewed execution grant"
        _validate_handoff_semantics(handoff)
        return
    validate_operation_input(values, _mutate_operation_input(values, mutation))


def validate_case_catalog(
    values: dict[str, Any], root: Path | None = None
) -> list[dict[str, Any]]:
    catalog = values["cases"]
    _require(
        catalog["catalog_digest"]
        == detached_digest("cases", catalog, "catalog_digest"),
        "PET-CASE-CATALOG-DIGEST",
    )
    valid_ids = [item["case_id"] for item in catalog["valid_cases"]]
    _require(
        len(valid_ids) == len(set(valid_ids)) and len(valid_ids) >= 12,
        "PET-VALID-CASE-SET",
    )
    results = []
    for item in catalog["valid_cases"]:
        record = operation_input_for_case(values, item)
        _schema_validate(record, values["schemas"]["operation"], item["case_id"])
        input_bytes = _canonical_json(record)
        _require(
            sha256_bytes(input_bytes) == item["input_digest"],
            "PET-CASE-INPUT-DIGEST",
            item["case_id"],
        )
        result = validate_operation_input(values, record)
        _require(
            result["status"] == item["expected"],
            "PET-VALID-CASE-EXPECTATION",
            item["case_id"],
        )
        _require(
            result["result_digest"] == item["result_digest"],
            "PET-CASE-RESULT-DIGEST",
            item["case_id"],
        )
        results.append(
            {
                "case_id": item["case_id"],
                "input_path": item["input_path"],
                "input_digest": item["input_digest"],
                **result,
            }
        )
    invalid = {
        item["mutation"]: item["expected_error"] for item in catalog["invalid_cases"]
    }
    _require(invalid == INVALID_CASE_CODES, "PET-INVALID-CASE-SET")
    for item in catalog["invalid_cases"]:
        try:
            _execute_invalid_case(values, item["mutation"])
        except PetProfileError as error:
            _require(
                error.code == item["expected_error"],
                "PET-INVALID-CASE-EXPECTATION",
                item["case_id"],
            )
        else:
            raise PetProfileError("PET-INVALID-CASE-ACCEPTED", item["case_id"])
    return results


# Compatibility name retained for Draft callers; semantics are now authority-driven.
def validate_conformance_input(values: dict[str, Any], record: dict[str, Any]) -> None:
    validate_operation_input(values, record)


def conformance_input_for_mutation(
    values: dict[str, Any], mutation: str
) -> dict[str, Any]:
    _require(mutation in INVALID_CASE_CODES, "PET-CASE-MUTATION-UNKNOWN")
    return _mutate_operation_input(values, mutation)


def _canonical_json(value: Any) -> bytes:
    return canonicalize(value) + b"\n"


def _profile_summary(profile: dict[str, Any]) -> dict[str, Any]:
    return {
        "profile_id": profile["profile_id"],
        "profile_version": profile["profile_version"],
        "profile_class": profile["profile_class"],
        "technology_family": profile["technology_family"],
        "security_model": profile["security_model"]["model_id"],
        "trust_model": profile["trust_model"]["model_id"],
        "supported_decision_outputs": profile["protocol_contract"][
            "supported_decision_outputs"
        ],
        "execution_authorization": profile["execution_authorization"],
        "candidate_execution_authorized": profile["execution_contract"][
            "candidate_execution_authorized"
        ],
        "production_execution_authorized": profile["execution_contract"][
            "production_execution_authorized"
        ],
        "required_external_authority": profile["execution_contract"][
            "required_external_authority"
        ],
        "decision_policy_authority": (
            profile["decision_derivation"]["authority"]
            if profile["profile_class"] == "complete-decision-profile"
            else None
        ),
        "production_eligible": profile["production_eligible"],
        "profile_digest": profile["profile_digest"],
    }


def generated_files(root: Path) -> dict[Path, bytes]:
    values = load_repository(root)
    validate_semantics(values)
    profiles = values["profiles"]
    summaries = [_profile_summary(profiles[key]) for key in sorted(profiles)]
    index = {
        "schema_version": "0.1",
        "record_type": "pet-integration-profile-index",
        "artifact_status": "experimental",
        "research_authority_digest": values["authority"]["authority_digest"],
        "protocol_source_revision_digest": PROTOCOL_SOURCE_DIGEST,
        "registry_digest": values["registry"]["registry_digest"],
        "complete_profile_count": len(COMPLETE_PROFILE_IDS),
        "component_profile_count": len(COMPONENT_PROFILE_IDS),
        "profiles": summaries,
        "index_digest": "",
    }
    index["index_digest"] = detached_digest("index", index, "index_digest")
    projection = {
        "schema_version": "0.1",
        "record_type": "product-decision-engine-handoff-projection",
        "artifact_status": "experimental",
        "handoff_digest": values["handoff"]["handoff_digest"],
        "registry_digest": values["registry"]["registry_digest"],
        "selection_rule": values["handoff"]["selection_rule"],
        "port_fields": values["handoff"]["port_fields"],
        "complete_profiles": [
            item
            for item in summaries
            if item["profile_class"] == "complete-decision-profile"
        ],
        "component_profiles": [
            item for item in summaries if item["profile_class"] == "component-only"
        ],
        "prohibited_content": values["handoff"]["global_prohibited_content"],
        "projection_digest": "",
    }
    projection["projection_digest"] = detached_digest(
        "projection", projection, "projection_digest"
    )
    lines = [
        "# Experimental PET integration profile comparison",
        "",
        "> Generated deterministically from validated public contract artifacts. Do not edit.",
        "",
        "| Profile | Class | Technology | Security model | Trust model | Fixture | Candidate | Production |",
        "| --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for item in summaries:
        lines.append(
            f"| `{item['profile_id']}/0.1` | {item['profile_class']} | {item['technology_family']} | {item['security_model']} | {item['trust_model']} | contract-only | no | no |"
        )
    lines += [
        "",
        "SecretFlow KKRT and Nitro Enclaves are materially different experimental complete-decision contracts.",
        "RFC 9497/CIRCL VOPRF is component-only and cannot be selected as the complete matching engine.",
        "No candidate was executed and no production PET architecture was selected.",
        "Profile registration and contract-fixture validation are not candidate execution permission.",
        "",
    ]
    files = {
        GENERATED_PATHS["index"]: _canonical_json(index),
        GENERATED_PATHS["comparison"]: "\n".join(lines).encode("utf-8"),
        GENERATED_PATHS["handoff"]: _canonical_json(projection),
    }
    executed_results = []
    for item in values["cases"]["valid_cases"]:
        operation_input = operation_input_for_case(values, item)
        input_bytes = _canonical_json(operation_input)
        _require(
            sha256_bytes(input_bytes) == item["input_digest"],
            "PET-CASE-INPUT-DIGEST",
            item["case_id"],
        )
        result = validate_operation_input(values, operation_input)
        _require(
            result["result_digest"] == item["result_digest"],
            "PET-CASE-RESULT-DIGEST",
            item["case_id"],
        )
        input_path = Path(item["input_path"])
        _require(
            input_path.as_posix()
            == (
                "generated/pet-integration/cases/"
                + item["case_id"].lower()
                + ".v0.1.json"
            ),
            "PET-CASE-INPUT-PATH",
            item["case_id"],
        )
        files[input_path] = input_bytes
        executed_results.append(
            {
                "case_id": item["case_id"],
                "input_path": item["input_path"],
                "input_digest": item["input_digest"],
                **result,
            }
        )
    case_results = {
        "schema_version": "0.1",
        "record_type": "pet-profile-executable-case-results",
        "artifact_status": "experimental",
        "catalog_digest": values["cases"]["catalog_digest"],
        "results": executed_results,
        "status_counts": {"accepted": len(executed_results), "rejected": 0},
        "result_set_digest": "",
    }
    case_results["result_set_digest"] = detached_digest(
        "case_results", case_results, "result_set_digest"
    )
    _schema_validate(
        case_results,
        values["schemas"]["case_results"],
        GENERATED_PATHS["case_results"].as_posix(),
    )
    files[GENERATED_PATHS["case_results"]] = _canonical_json(case_results)
    behavior_paths = [
        AUTHORITY_PATH,
        REGISTRY_PATH,
        HANDOFF_PATH,
        BINDING_PATH,
        CASE_CATALOG_PATH,
        CANONICAL_CALLBACK_PATH,
        *SCHEMAS.values(),
        *PROFILE_PATHS.values(),
        Path("scripts/pet_profiles.py"),
        Path("scripts/generate_pet_profiles.py"),
        Path("scripts/validate_pet_profiles.py"),
        Path("scripts/canonicalize_message.py"),
        Path("scripts/strict_yaml.py"),
        Path("tests/test_pet_profiles.py"),
        Path("requirements-build.txt"),
        Path("requirements-dev.txt"),
        Path("specs/state-machines/private-match-core-session-v0.1.yaml"),
        Path("registry/message-types.v0.1.yaml"),
        Path(".github/workflows/protocol-spec.yml"),
        Path("REUSE.toml"),
        Path("README.md"),
        Path("ROADMAP.md"),
        Path("GOVERNANCE.md"),
        Path("docs/decisions/ADR-0006-EXPERIMENTAL-PET-INTEGRATION-PROFILES.md"),
        Path("specs/pet-integration/README.md"),
        Path("specs/pet-integration/secretflow-kkrt-v0.1.md"),
        Path("specs/pet-integration/nitro-enclave-v0.1.md"),
        Path("specs/pet-integration/voprf-component-v0.1.md"),
    ]
    entries = []
    for relative in sorted(behavior_paths, key=lambda item: item.as_posix()):
        path = _regular_file(root, relative)
        entries.append(
            {
                "path": relative.as_posix(),
                "digest": sha256_bytes(path.read_bytes()),
                "size": path.stat().st_size,
            }
        )
    output_entries = [
        {"path": path.as_posix(), "digest": sha256_bytes(content), "size": len(content)}
        for path, content in sorted(files.items(), key=lambda item: item[0].as_posix())
    ]
    manifest = {
        "schema_version": "0.1",
        "record_type": "pet-integration-generated-manifest",
        "artifact_status": "experimental",
        "research_authority_digest": values["authority"]["authority_digest"],
        "registry_digest": values["registry"]["registry_digest"],
        "handoff_digest": values["handoff"]["handoff_digest"],
        "binding_digest": values["binding"]["binding_digest"],
        "case_catalog_digest": values["cases"]["catalog_digest"],
        "behavior_inputs": entries,
        "generated_outputs": output_entries,
        "implementation_digest": "",
    }
    manifest["implementation_digest"] = detached_digest(
        "manifest", manifest, "implementation_digest"
    )
    files[GENERATED_PATHS["manifest"]] = _canonical_json(manifest)
    return files


def validate_repository(root: Path) -> None:
    values = load_repository(root)
    validate_semantics(values)
    expected = generated_files(root)
    _require(
        _generated_path_set(root) == set(expected),
        "PET-GENERATED-PATH-SET",
    )
    for relative, content in expected.items():
        observed = _regular_file(root, relative).read_bytes()
        _require(observed == content, "PET-GENERATED-STALE", relative.as_posix())


def write_generated(root: Path) -> dict[Path, bytes]:
    files = generated_files(root)
    for relative, content in files.items():
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        temporary = target.with_name(target.name + ".tmp")
        temporary.write_bytes(content)
        os.replace(temporary, target)
    _require(
        _generated_path_set(root) == set(files),
        "PET-GENERATED-PATH-SET",
    )
    return files


def compare_generated(root: Path) -> None:
    files = generated_files(root)
    _require(
        _generated_path_set(root) == set(files),
        "PET-GENERATED-PATH-SET",
    )
    for relative, content in files.items():
        _require(
            _regular_file(root, relative).read_bytes() == content,
            "PET-GENERATED-STALE",
            relative.as_posix(),
        )


def _generated_path_set(root: Path) -> set[Path]:
    generated_root = root / GENERATED_ROOT
    observed: set[Path] = set()
    for path in generated_root.rglob("*"):
        relative = path.relative_to(root)
        mode = os.lstat(path).st_mode
        if stat.S_ISLNK(mode):
            raise PetProfileError("PET-PATH-SYMLINK", relative.as_posix())
        if stat.S_ISDIR(mode):
            continue
        if not stat.S_ISREG(mode):
            raise PetProfileError("PET-PATH-NOT-FILE", relative.as_posix())
        observed.add(relative)
    return observed


def bounded_main(action: Any) -> int:
    try:
        action()
        return 0
    except PetProfileError as error:
        print(str(error), file=os.sys.stderr)
        return 1
