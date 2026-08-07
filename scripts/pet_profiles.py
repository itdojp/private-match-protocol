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
    "profile_instance_id",
    "session_id",
    "evaluation_attempt_id",
    "opaque_receipt",
    "transcript_head",
]
RECEIPT_BINDINGS = [
    "session_id",
    "participant_binding",
    "policy_binding",
    "profile_id",
    "profile_version",
    "profile_instance_id",
    "commitment_pair_id",
    "evaluation_attempt_id",
    "transcript_head",
    "input_commitments",
    "resource_policy",
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
GENERATED_ROOT = Path("generated/pet-integration")
SCHEMAS = {
    "authority": Path("schema/research-technology-authority.v0.1.schema.json"),
    "profile": Path("schema/pet-integration-profile.v0.1.schema.json"),
    "registry": Path("schema/pet-integration-profile-registry.v0.1.schema.json"),
    "handoff": Path("schema/product-decision-engine-handoff.v0.1.schema.json"),
    "binding": Path("schema/pet-protocol-binding.v0.1.schema.json"),
    "cases": Path("schema/pet-profile-conformance-cases.v0.1.schema.json"),
}
GENERATED_PATHS = {
    "index": GENERATED_ROOT / "profile-index.v0.1.json",
    "comparison": GENERATED_ROOT / "profile-comparison.v0.1.md",
    "handoff": GENERATED_ROOT / "product-handoff-projection.v0.1.json",
    "manifest": GENERATED_ROOT / "profile-digest-manifest.v0.1.json",
}
MAX_FILE_BYTES = 2 * 1024 * 1024

DOMAINS = {
    "authority": b"private-match-research-technology-authority/v0.1\x00",
    "profile": b"private-match-pet-integration-profile/v0.1\x00",
    "registry": b"private-match-pet-profile-registry/v0.1\x00",
    "handoff": b"private-match-product-decision-engine-handoff/v0.1\x00",
    "binding": b"private-match-pet-protocol-binding/v0.1\x00",
    "cases": b"private-match-pet-profile-conformance-cases/v0.1\x00",
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
        "authority": load_json(root, AUTHORITY_PATH),
        "registry": load_yaml(root, REGISTRY_PATH),
        "handoff": load_yaml(root, HANDOFF_PATH),
        "binding": load_yaml(root, BINDING_PATH),
        "cases": load_json(root, CASE_CATALOG_PATH),
        "profiles": {key: load_json(root, path) for key, path in PROFILE_PATHS.items()},
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


def _validate_profile(profile: dict[str, Any], authority_digest: str) -> None:
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
            operation: EXPECTED_PROTOCOL_OPERATIONS[operation]
            for operation in (
                "reserve-query-budget",
                "start-evaluation",
                "submit-contribution",
                "acknowledge-receipt",
                "accept-symmetric-result",
            )
        }
        observed_exchange = {
            item["operation"]: (
                item["event"],
                item["message_type"],
                item["transition_ids"],
            )
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


def validate_semantics(values: dict[str, Any]) -> None:
    authority = values["authority"]
    validate_research_authority(authority)
    profiles = values["profiles"]
    _require(
        set(profiles) == COMPLETE_PROFILE_IDS | COMPONENT_PROFILE_IDS, "PET-PROFILE-SET"
    )
    for identifier, profile in profiles.items():
        _require(profile["profile_id"] == identifier, "PET-PROFILE-PATH-ID", identifier)
        _validate_profile(profile, authority["authority_digest"])
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
    required_operations = set(EXPECTED_PROTOCOL_OPERATIONS)
    _require(
        {item["operation"] for item in binding["operations"]} == required_operations,
        "PET-BINDING-OPERATIONS",
    )
    observed_operations = {
        item["operation"]: (
            item["event"],
            item["message_type"],
            item["transition_ids"],
        )
        for item in binding["operations"]
    }
    _require(
        observed_operations == EXPECTED_PROTOCOL_OPERATIONS,
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
    _require(
        handoff["handoff_digest"]
        == detached_digest("handoff", handoff, "handoff_digest"),
        "PET-HANDOFF-DIGEST",
    )
    validate_case_catalog(values["cases"], profiles)


INVALID_CASE_CODES = {
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
    "tee-unapproved-execution": "PET-EXECUTION-AUTHORIZATION",
    "voprf-complete-engine": "PET-VOPRF-COMPLETE-CLAIM",
    "secret-evidence-hook": "PET-EVIDENCE-SECRET",
    "query-budget-bypass": "PET-QUERY-BUDGET",
    "cancellation-without-cleanup": "PET-CANCELLATION-CLEANUP",
    "unknown-error-category": "PET-FAILURE-MAPPING",
}

EXPECTED_PROTOCOL_OPERATIONS = {
    "select-profile": (
        "create_session",
        "session_proposal",
        ["TR-CREATE"],
    ),
    "reserve-query-budget": (
        "reserve_query_budget",
        "query_budget_reservation",
        ["TR-RESERVE-BUDGET"],
    ),
    "start-evaluation": (
        "start_evaluation",
        "evaluation_start",
        ["TR-START-EVALUATION"],
    ),
    "submit-contribution": (
        "submit_evaluation_contribution",
        "evaluation_contribution",
        ["TR-SUBMIT-CONTRIBUTION-A", "TR-SUBMIT-CONTRIBUTION-B"],
    ),
    "accept-profile-callback": (
        "accept_symmetric_result",
        "result_acceptance_notice",
        ["TR-ACCEPT-SYMMETRIC-RESULT", "TR-RESULT-CONFLICT"],
    ),
    "acknowledge-receipt": (
        "acknowledge_opaque_receipt_a",
        "opaque_receipt_ack",
        ["TR-ACK-RECEIPT-A", "TR-ACK-RECEIPT-B"],
    ),
    "accept-symmetric-result": (
        "accept_symmetric_result",
        "result_acceptance_notice",
        ["TR-ACCEPT-SYMMETRIC-RESULT", "TR-RESULT-CONFLICT"],
    ),
    "evaluation-timeout": (
        "advance_authoritative_time",
        None,
        ["TR-EVALUATION-TIMEOUT"],
    ),
    "abort-and-cleanup": (
        "abort_session",
        "abort_notice",
        ["TR-ABORT"],
    ),
}


def validate_case_catalog(catalog: dict[str, Any], profiles: dict[str, Any]) -> None:
    _require(
        catalog["catalog_digest"]
        == detached_digest("cases", catalog, "catalog_digest"),
        "PET-CASE-CATALOG-DIGEST",
    )
    valid_ids = [item["case_id"] for item in catalog["valid_cases"]]
    _require(
        len(valid_ids) == len(set(valid_ids)) and len(valid_ids) >= 8,
        "PET-VALID-CASE-SET",
    )
    for item in catalog["valid_cases"]:
        identifier = item["profile_id"]
        _require(identifier in profiles, "PET-PROFILE-UNKNOWN", item["case_id"])
        _require(
            item["profile_version"] == profiles[identifier]["profile_version"],
            "PET-PROFILE-VERSION",
            item["case_id"],
        )
        if item["operation"] == "select-for-evaluation":
            _require(
                profiles[identifier]["profile_class"] == "complete-decision-profile",
                "PET-COMPONENT-AS-COMPLETE",
                item["case_id"],
            )
    invalid = {
        item["mutation"]: item["expected_error"] for item in catalog["invalid_cases"]
    }
    _require(invalid == INVALID_CASE_CODES, "PET-INVALID-CASE-SET")
    for item in catalog["invalid_cases"]:
        record = conformance_input_for_mutation(profiles, item["mutation"])
        try:
            validate_conformance_input(profiles, record)
        except PetProfileError as error:
            _require(
                error.code == item["expected_error"],
                "PET-INVALID-CASE-EXPECTATION",
                item["case_id"],
            )
        else:
            raise PetProfileError("PET-INVALID-CASE-ACCEPTED", item["case_id"])


def _base_conformance_input(profile_id: str) -> dict[str, Any]:
    """Return one value-only synthetic callback/selection contract input."""

    return {
        "profile_id": profile_id,
        "profile_version": "0.1",
        "profile_instance_id": "fixture-profile-instance-001",
        "operation": "select-for-evaluation",
        "callback": {
            "profile_id": profile_id,
            "profile_version": "0.1",
            "profile_instance_id": "fixture-profile-instance-001",
            "session_id": "fixture-session-001",
            "evaluation_attempt_id": "fixture-attempt-001",
            "opaque_receipt": "sha256:" + "a1" * 32,
            "expected_opaque_receipt": "sha256:" + "a1" * 32,
            "transcript_head": "sha256:" + "b2" * 32,
            "expected_transcript_head": "sha256:" + "b2" * 32,
        },
        "party_results": ["MATCH", "MATCH"],
        "output_classes": [],
        "coordinator_plaintext_result": False,
        "receipt_entropy_bits": 256,
        "verification_material_present": True,
        "security_claim": "reviewed-profile-only",
        "tee": {
            "debug_mode": False,
            "fresh_nonce": True,
            "pcr_policy_matches": True,
            "execute_candidate": False,
        },
        "component_complete_engine_claim": False,
        "evidence_fields": ["profile_id", "profile_version", "profile_digest"],
        "query_budget_reserved": True,
        "query_budget_consumption_count": 1,
        "cancellation_requested": False,
        "cleanup_completed": True,
        "failure_category": "RESULT_CONFLICT",
    }


def conformance_input_for_mutation(
    profiles: dict[str, Any], mutation: str
) -> dict[str, Any]:
    """Build one deterministic invalid input named by the reviewed catalog."""

    _require(mutation in INVALID_CASE_CODES, "PET-CASE-MUTATION-UNKNOWN")
    profile_id = "private-match-experimental-secretflow-kkrt"
    if mutation.startswith("tee-"):
        profile_id = "private-match-experimental-nitro-enclave"
    elif mutation in {"component-selected", "voprf-complete-engine"}:
        profile_id = "private-match-experimental-voprf-component"
    record = _base_conformance_input(profile_id)
    if mutation == "unknown-profile":
        record["profile_id"] = "private-match-experimental-unknown"
    elif mutation == "wrong-version":
        record["profile_version"] = "9.9"
    elif mutation == "component-selected":
        pass
    elif mutation == "cross-profile-callback":
        record["callback"]["profile_id"] = "private-match-experimental-nitro-enclave"
    elif mutation == "wrong-profile-instance":
        record["callback"]["profile_instance_id"] = "fixture-other-instance"
    elif mutation == "wrong-evaluation-attempt":
        record["callback"]["evaluation_attempt_id"] = "fixture-other-attempt"
    elif mutation == "wrong-receipt":
        record["callback"]["opaque_receipt"] = "sha256:" + "c3" * 32
    elif mutation == "wrong-transcript-head":
        record["callback"]["transcript_head"] = "sha256:" + "d4" * 32
    elif mutation == "result-asymmetry":
        record["party_results"] = ["MATCH", "NO_MATCH"]
    elif mutation == "exact-count":
        record["output_classes"] = ["exact-intersection-count"]
    elif mutation == "matching-element":
        record["output_classes"] = ["matching-elements"]
    elif mutation == "coordinator-plaintext-result":
        record["coordinator_plaintext_result"] = True
    elif mutation == "low-entropy-receipt":
        bare = "sha256:" + hashlib.sha256(b"MATCH").hexdigest()
        record["callback"]["opaque_receipt"] = bare
        record["callback"]["expected_opaque_receipt"] = bare
    elif mutation == "missing-verification-material":
        record["verification_material_present"] = False
    elif mutation == "psi-security-escalation":
        record["security_claim"] = "malicious-party-secure"
    elif mutation == "tee-debug-mode":
        record["tee"]["debug_mode"] = True
    elif mutation == "tee-stale-nonce":
        record["tee"]["fresh_nonce"] = False
    elif mutation == "tee-wrong-pcr-policy":
        record["tee"]["pcr_policy_matches"] = False
    elif mutation == "tee-unapproved-execution":
        record["tee"]["execute_candidate"] = True
    elif mutation == "voprf-complete-engine":
        record["component_complete_engine_claim"] = True
        record["operation"] = "register-component"
    elif mutation == "secret-evidence-hook":
        record["evidence_fields"] = ["private_input"]
    elif mutation == "query-budget-bypass":
        record["query_budget_reserved"] = False
    elif mutation == "cancellation-without-cleanup":
        record["cancellation_requested"] = True
        record["cleanup_completed"] = False
    elif mutation == "unknown-error-category":
        record["failure_category"] = "VENDOR_RAW_FAILURE"
    return record


def validate_conformance_input(
    profiles: dict[str, Any], record: dict[str, Any]
) -> None:
    """Validate one value-only profile binding without invoking a candidate."""

    identifier = record["profile_id"]
    _require(identifier in profiles, "PET-PROFILE-UNKNOWN")
    profile = profiles[identifier]
    _require(
        record["profile_version"] == profile["profile_version"], "PET-PROFILE-VERSION"
    )
    if record["operation"] == "select-for-evaluation":
        _require(
            profile["profile_class"] == "complete-decision-profile",
            "PET-COMPONENT-AS-COMPLETE",
        )
    callback = record["callback"]
    _require(callback["profile_id"] == identifier, "PET-CROSS-PROFILE")
    _require(
        callback["profile_version"] == record["profile_version"], "PET-PROFILE-VERSION"
    )
    _require(
        callback["profile_instance_id"] == record["profile_instance_id"],
        "PET-PROFILE-INSTANCE",
    )
    _require(
        callback["evaluation_attempt_id"] == "fixture-attempt-001",
        "PET-EVALUATION-ATTEMPT",
    )
    _require(
        callback["opaque_receipt"] == callback["expected_opaque_receipt"],
        "PET-RECEIPT-BINDING",
    )
    _require(
        callback["transcript_head"] == callback["expected_transcript_head"],
        "PET-TRANSCRIPT-MISMATCH",
    )
    _require(len(set(record["party_results"])) == 1, "PET-RESULT-SYMMETRY")
    _require(
        not set(record["output_classes"]) & set(PROHIBITED_OUTPUTS),
        "PET-PROHIBITED-OUTPUT",
    )
    _require(
        record["coordinator_plaintext_result"] is False,
        "PET-COORDINATOR-PLAINTEXT",
    )
    _require(
        callback["opaque_receipt"] not in BARE_RESULT_RECEIPTS,
        "PET-LOW-ENTROPY-RECEIPT",
    )
    _require(record["receipt_entropy_bits"] >= 128, "PET-LOW-ENTROPY-RECEIPT")
    _require(record["verification_material_present"], "PET-VERIFICATION-MATERIAL")
    if identifier == "private-match-experimental-secretflow-kkrt":
        _require(
            record["security_claim"] != "malicious-party-secure",
            "PET-PSI-SECURITY-ESCALATION",
        )
    if identifier == "private-match-experimental-nitro-enclave":
        _require(record["tee"]["debug_mode"] is False, "PET-TEE-DEBUG-MODE")
        _require(record["tee"]["fresh_nonce"], "PET-TEE-FRESH-NONCE")
        _require(record["tee"]["pcr_policy_matches"], "PET-TEE-PCR-POLICY")
        _require(
            record["tee"]["execute_candidate"] is False,
            "PET-EXECUTION-AUTHORIZATION",
        )
    _require(
        not record["component_complete_engine_claim"],
        "PET-VOPRF-COMPLETE-CLAIM",
    )
    _require(
        not set(record["evidence_fields"])
        & {"private_input", "raw_identifier", "matching_element", "secret_material"},
        "PET-EVIDENCE-SECRET",
    )
    _require(record["query_budget_reserved"], "PET-QUERY-BUDGET")
    _require(record["query_budget_consumption_count"] == 1, "PET-QUERY-BUDGET")
    if record["cancellation_requested"]:
        _require(record["cleanup_completed"], "PET-CANCELLATION-CLEANUP")
    permitted_failures = {
        item["category"]
        for complete_id in COMPLETE_PROFILE_IDS
        for item in profiles[complete_id]["protocol_contract"]["failure_mappings"]
    }
    _require(record["failure_category"] in permitted_failures, "PET-FAILURE-MAPPING")


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
        "| Profile | Class | Technology | Security model | Trust model | Execution | Production |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for item in summaries:
        lines.append(
            f"| `{item['profile_id']}/0.1` | {item['profile_class']} | {item['technology_family']} | {item['security_model']} | {item['trust_model']} | {item['execution_authorization']} | no |"
        )
    lines += [
        "",
        "SecretFlow KKRT and Nitro Enclaves are materially different experimental complete-decision contracts.",
        "RFC 9497/CIRCL VOPRF is component-only and cannot be selected as the complete matching engine.",
        "No candidate was executed and no production PET architecture was selected.",
        "",
    ]
    files = {
        GENERATED_PATHS["index"]: _canonical_json(index),
        GENERATED_PATHS["comparison"]: "\n".join(lines).encode("utf-8"),
        GENERATED_PATHS["handoff"]: _canonical_json(projection),
    }
    behavior_paths = [
        AUTHORITY_PATH,
        REGISTRY_PATH,
        HANDOFF_PATH,
        BINDING_PATH,
        CASE_CATALOG_PATH,
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
    return files


def compare_generated(root: Path) -> None:
    files = generated_files(root)
    for relative, content in files.items():
        _require(
            _regular_file(root, relative).read_bytes() == content,
            "PET-GENERATED-STALE",
            relative.as_posix(),
        )


def bounded_main(action: Any) -> int:
    try:
        action()
        return 0
    except PetProfileError as error:
        print(str(error), file=os.sys.stderr)
        return 1
