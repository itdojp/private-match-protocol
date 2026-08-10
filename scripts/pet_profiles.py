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
import re
import stat
from pathlib import Path, PurePosixPath
from typing import Any

import yaml
from jsonschema import Draft202012Validator, FormatChecker

from canonicalize_message import (
    canonicalize,
    payload_digest,
    populate_digests,
    strict_loads,
)
from protocol_time import ProtocolTimeError, parse_canonical_utc_timestamp
from pet_v02_digests import PUBLISHED_V02_DIGESTS
from strict_yaml import strict_yaml_load
from validate_messages import validate_message_bytes


PROTOCOL_COMMIT = "9bb59d3b5e1435885fdea60280d6602f937305c9"
PROTOCOL_SOURCE_DIGEST = (
    "sha256:ed111a4bb8d6e662051940543bdf0c72503ff4b907018c1d76c7345b05ebf6a3"
)
STATE_MACHINE_DIGEST = (
    "sha256:7d710270b4fae68dfb2596fe2dd8158b7d5b02f3235be43d0ed8e21f232c8b94"
)
MESSAGE_REGISTRY_DIGEST = (
    "sha256:cd41e5fe0b932f720b005ded2c535e4e5264dd9ff2893e77add00d64da9bf950"
)
MESSAGE_INPUT_TREE_DIGEST = (
    "sha256:5ea8e3de7e6d2174f238548b879b0c30a7ec5165fd69b86f572eafa515a21909"
)
V02_OPERATION_STAGE_DIGEST = (
    "sha256:e4af007a87443afb3a4a93cf477e3f968c151b66b7498e73e9b2c84b33593498"
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
LEGACY_PROFILE_PATHS = {
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
V02_PROFILE_PATHS = {
    "private-match-experimental-secretflow-kkrt": Path(
        "profiles/pet-integration/secretflow-kkrt.v0.2.json"
    ),
    "private-match-experimental-nitro-enclave": Path(
        "profiles/pet-integration/nitro-enclave.v0.2.json"
    ),
    "private-match-experimental-voprf-component": Path(
        "profiles/pet-integration/voprf-component.v0.2.json"
    ),
}
PROFILE_PATHS = {
    "private-match-experimental-secretflow-kkrt": Path(
        "profiles/pet-integration/secretflow-kkrt.v0.2.json"
    ),
    "private-match-experimental-nitro-enclave": Path(
        "profiles/pet-integration/nitro-enclave.v0.2.json"
    ),
    "private-match-experimental-voprf-component": Path(
        "profiles/pet-integration/voprf-component.v0.2.json"
    ),
}
AUTHORITY_PATH = Path("config/research-technology-authority.v0.1.json")
LEGACY_REGISTRY_PATH = Path("registry/pet-integration-profiles.v0.1.yaml")
LEGACY_HANDOFF_PATH = Path("handoff/product-decision-engine-port.v0.1.yaml")
LEGACY_BINDING_PATH = Path("specs/pet-integration/protocol-binding.v0.1.yaml")
V02_REGISTRY_PATH = Path("registry/pet-integration-profiles.v0.2.yaml")
V02_HANDOFF_PATH = Path("handoff/product-decision-engine-port.v0.2.yaml")
V02_BINDING_PATH = Path("specs/pet-integration/protocol-binding.v0.2.yaml")
V02_STAGE_CONTRACT_PATH = Path(
    "specs/pet-integration/operation-stage-contract.v0.2.yaml"
)
V02_CASE_CATALOG_PATH = Path("conformance/pet-profiles/case-catalog.v0.2.json")
REGISTRY_PATH = Path("registry/pet-integration-profiles.v0.3.yaml")
HANDOFF_PATH = Path("handoff/product-decision-engine-port.v0.3.yaml")
BINDING_PATH = Path("specs/pet-integration/protocol-binding.v0.3.yaml")
STAGE_CONTRACT_PATH = Path("specs/pet-integration/operation-stage-contract.v0.3.yaml")
CASE_CATALOG_PATH = Path("conformance/pet-profiles/case-catalog.v0.3.json")
LEGACY_ERROR_CODE_CATALOG_PATH = Path("config/pet-profile-error-codes.v0.1.json")
V02_ERROR_CODE_CATALOG_PATH = Path("config/pet-profile-error-codes.v0.2.json")
ERROR_CODE_CATALOG_PATH = Path("config/pet-profile-error-codes.v0.3.json")
V02_COMPATIBILITY_PATH = Path("config/pet-contract-compatibility.v0.2.json")
COMPATIBILITY_PATH = Path("config/pet-contract-compatibility.v0.3.json")
RESULT_FIELD_POLICY_PATH = Path("config/pet-public-result-field-policy.v0.3.json")
CANONICAL_CALLBACK_PATH = Path(
    "conformance/pet-profiles/messages/result-acceptance-notice.v0.2.json"
)
STATE_MACHINE_PATH = Path("specs/state-machines/private-match-core-session-v0.1.yaml")
MESSAGE_REGISTRY_PATH = Path("registry/message-types.v0.1.yaml")
MESSAGE_SCHEMA_PATH = Path("schemas/messages/envelope.v0.1.schema.json")
PET_MESSAGE_SCHEMA_PATH = Path("schemas/messages/envelope.v0.2.schema.json")
MESSAGE_MATERIALS_PATH = Path("conformance/messages/verification-materials.v0.1.yaml")
GENERATED_ROOT = Path("generated/pet-integration")
SCHEMAS = {
    "authority": Path("schema/research-technology-authority.v0.1.schema.json"),
    "profile": Path("schema/pet-integration-profile.v0.2.schema.json"),
    "registry": Path("schema/pet-integration-profile-registry.v0.3.schema.json"),
    "handoff": Path("schema/product-decision-engine-handoff.v0.3.schema.json"),
    "binding": Path("schema/pet-protocol-binding.v0.3.schema.json"),
    "cases": Path("schema/pet-profile-conformance-cases.v0.3.schema.json"),
    "operation": Path("schema/pet-profile-operation-input.v0.3.schema.json"),
    "case_results": Path("schema/pet-profile-case-results.v0.3.schema.json"),
    "stage": Path("schema/pet-operation-stage-contract.v0.3.schema.json"),
    "error_codes": Path("schema/pet-profile-error-codes.v0.3.schema.json"),
    "compatibility": Path("schema/pet-contract-compatibility.v0.3.schema.json"),
    "result_field_policy": Path(
        "schema/pet-public-result-field-policy.v0.3.schema.json"
    ),
}
GENERATED_PATHS = {
    "index": GENERATED_ROOT / "profile-index.v0.3.json",
    "comparison": GENERATED_ROOT / "profile-comparison.v0.3.md",
    "handoff": GENERATED_ROOT / "product-handoff-projection.v0.3.json",
    "manifest": GENERATED_ROOT / "profile-digest-manifest.v0.3.json",
    "case_results": GENERATED_ROOT / "executable-case-results.v0.3.json",
}
LEGACY_CONTRACT_GRAPH_PATHS = {
    "operation-stage-schema": Path(
        "schema/pet-operation-stage-contract.v0.1.schema.json"
    ),
    "operation-stage": Path("specs/pet-integration/operation-stage-contract.v0.1.yaml"),
    "operation-input-schema": Path(
        "schema/pet-profile-operation-input.v0.1.schema.json"
    ),
    "conformance-case-schema": Path(
        "schema/pet-profile-conformance-cases.v0.1.schema.json"
    ),
    "conformance-case-catalog": Path("conformance/pet-profiles/case-catalog.v0.1.json"),
    "executable-result-schema": Path(
        "schema/pet-profile-case-results.v0.1.schema.json"
    ),
    "profile-schema": Path("schema/pet-integration-profile.v0.1.schema.json"),
    "profile-secretflow": LEGACY_PROFILE_PATHS[
        "private-match-experimental-secretflow-kkrt"
    ],
    "profile-nitro": LEGACY_PROFILE_PATHS["private-match-experimental-nitro-enclave"],
    "profile-voprf": LEGACY_PROFILE_PATHS["private-match-experimental-voprf-component"],
    "registry-schema": Path("schema/pet-integration-profile-registry.v0.1.schema.json"),
    "registry": LEGACY_REGISTRY_PATH,
    "protocol-binding-schema": Path("schema/pet-protocol-binding.v0.1.schema.json"),
    "protocol-binding": LEGACY_BINDING_PATH,
    "product-handoff-schema": Path(
        "schema/product-decision-engine-handoff.v0.1.schema.json"
    ),
    "product-handoff": LEGACY_HANDOFF_PATH,
    "message-envelope-schema": MESSAGE_SCHEMA_PATH,
    "error-code-schema": Path("schema/pet-profile-error-codes.v0.1.schema.json"),
    "error-code-catalog": LEGACY_ERROR_CODE_CATALOG_PATH,
}
V02_CONTRACT_GRAPH_PATHS = {
    "operation-stage-schema": Path(
        "schema/pet-operation-stage-contract.v0.2.schema.json"
    ),
    "operation-stage": V02_STAGE_CONTRACT_PATH,
    "operation-input-schema": Path(
        "schema/pet-profile-operation-input.v0.2.schema.json"
    ),
    "conformance-case-schema": Path(
        "schema/pet-profile-conformance-cases.v0.2.schema.json"
    ),
    "conformance-case-catalog": V02_CASE_CATALOG_PATH,
    "executable-result-schema": Path(
        "schema/pet-profile-case-results.v0.2.schema.json"
    ),
    "profile-schema": Path("schema/pet-integration-profile.v0.2.schema.json"),
    "profile-secretflow": V02_PROFILE_PATHS[
        "private-match-experimental-secretflow-kkrt"
    ],
    "profile-nitro": V02_PROFILE_PATHS["private-match-experimental-nitro-enclave"],
    "profile-voprf": V02_PROFILE_PATHS["private-match-experimental-voprf-component"],
    "registry-schema": Path("schema/pet-integration-profile-registry.v0.2.schema.json"),
    "registry": V02_REGISTRY_PATH,
    "protocol-binding-schema": Path("schema/pet-protocol-binding.v0.2.schema.json"),
    "protocol-binding": V02_BINDING_PATH,
    "product-handoff-schema": Path(
        "schema/product-decision-engine-handoff.v0.2.schema.json"
    ),
    "product-handoff": V02_HANDOFF_PATH,
    "message-envelope-schema": PET_MESSAGE_SCHEMA_PATH,
    "error-code-schema": Path("schema/pet-profile-error-codes.v0.2.schema.json"),
    "error-code-catalog": V02_ERROR_CODE_CATALOG_PATH,
}
CURRENT_CONTRACT_GRAPH_PATHS = {
    "operation-stage-schema": SCHEMAS["stage"],
    "operation-stage": STAGE_CONTRACT_PATH,
    "operation-input-schema": SCHEMAS["operation"],
    "conformance-case-schema": SCHEMAS["cases"],
    "conformance-case-catalog": CASE_CATALOG_PATH,
    "executable-result-schema": SCHEMAS["case_results"],
    "profile-schema": SCHEMAS["profile"],
    "profile-secretflow": PROFILE_PATHS["private-match-experimental-secretflow-kkrt"],
    "profile-nitro": PROFILE_PATHS["private-match-experimental-nitro-enclave"],
    "profile-voprf": PROFILE_PATHS["private-match-experimental-voprf-component"],
    "registry-schema": SCHEMAS["registry"],
    "registry": REGISTRY_PATH,
    "protocol-binding-schema": SCHEMAS["binding"],
    "protocol-binding": BINDING_PATH,
    "product-handoff-schema": SCHEMAS["handoff"],
    "product-handoff": HANDOFF_PATH,
    "message-envelope-schema": PET_MESSAGE_SCHEMA_PATH,
    "error-code-schema": SCHEMAS["error_codes"],
    "error-code-catalog": ERROR_CODE_CATALOG_PATH,
    "public-result-field-policy-schema": SCHEMAS["result_field_policy"],
    "public-result-field-policy": RESULT_FIELD_POLICY_PATH,
}
LEGACY_GENERATED_DIGESTS = {
    Path(
        "generated/pet-integration/cases/pet-valid-abort-commitments-pending.v0.1.json"
    ): "sha256:5bdb4fc200490d03022f0b1881785fea8430e857071d5e23b4500e7b7878a06b",
    Path(
        "generated/pet-integration/cases/pet-valid-abort-committed.v0.1.json"
    ): "sha256:a22fec71773921b1cb1ae92202105f49ca82a03e7042d4a39bad2bca8d98fd6e",
    Path(
        "generated/pet-integration/cases/pet-valid-abort-consent-pending.v0.1.json"
    ): "sha256:e092468f66d840a629c9f4c1fea427205d7e11cbf95ae368c74d720903cf1189",
    Path(
        "generated/pet-integration/cases/pet-valid-abort-created.v0.1.json"
    ): "sha256:d3c1d47e1660822048db205f73f4040aa24ce5ff093e8cb12de66d5392837536",
    Path(
        "generated/pet-integration/cases/pet-valid-abort-disclosure-authorized.v0.1.json"
    ): "sha256:dcc69af8ce535753b9f0fed3178534623600b18e08ab56c56e21427aad267a57",
    Path(
        "generated/pet-integration/cases/pet-valid-abort-participants-bound.v0.1.json"
    ): "sha256:f0d742fb43fcdf5b89e25aa52d68ade4d67a4acf68c065f0d3861de0b26c3039",
    Path(
        "generated/pet-integration/cases/pet-valid-abort-result-accepted.v0.1.json"
    ): "sha256:1587188973cdc474d3f8ba72425f2ed333aac9fd9702b6c773a0aa06bfec80bf",
    Path(
        "generated/pet-integration/cases/pet-valid-cancellation-cleanup.v0.1.json"
    ): "sha256:a179d0921c0beb3a6591cb109dab426c20c3db445bd0b512fa9908bf9f38577f",
    Path(
        "generated/pet-integration/cases/pet-valid-contribution-a.v0.1.json"
    ): "sha256:0dea1d6e4662a390c7845552076f8fbd86bec0562ea263c87bcfe851c0419d75",
    Path(
        "generated/pet-integration/cases/pet-valid-contribution-b.v0.1.json"
    ): "sha256:84a76e461d028bb15b953b2bf90f5c932f28e0e84438e90d41f767d961ad3316",
    Path(
        "generated/pet-integration/cases/pet-valid-evaluation-start.v0.1.json"
    ): "sha256:291d94ee10d761984a909f0ece08f5b95a9341625c907a0e19904b0dfc272abe",
    Path(
        "generated/pet-integration/cases/pet-valid-evaluation-timeout.v0.1.json"
    ): "sha256:88df3a5e51cc5386e0356e5eece12bf684a14aeea1bd3a5d344ede62eff4b3a4",
    Path(
        "generated/pet-integration/cases/pet-valid-nitro-selection.v0.1.json"
    ): "sha256:25f61b8942698c1c2030d811dd8ce856ed482c517e0bb777fbee7642616d45f3",
    Path(
        "generated/pet-integration/cases/pet-valid-profile-callback.v0.1.json"
    ): "sha256:8f83b67cdc4b47ee63bffd246e9728377b9c0df7593c5b685fa30959ab2e021c",
    Path(
        "generated/pet-integration/cases/pet-valid-query-budget.v0.1.json"
    ): "sha256:52a293b5bc050db6f8dcfdbaa37fa2b49b3feeee02d44e01ecd1d9d0171a3f35",
    Path(
        "generated/pet-integration/cases/pet-valid-receipt-a.v0.1.json"
    ): "sha256:a733747ab0f9d64484bd6112d868df935e9338f4ff04770b3edda727dc8993dd",
    Path(
        "generated/pet-integration/cases/pet-valid-receipt-b.v0.1.json"
    ): "sha256:bf79cb1b35d6d166ff864500d54b8b30be5d9492dd96c54b4baf817cc4eee47d",
    Path(
        "generated/pet-integration/cases/pet-valid-secretflow-selection.v0.1.json"
    ): "sha256:89ada833279dbf2b7ceaf0fcfc5c168400bee08ba72192ccbbe7d96d0daf4551",
    Path(
        "generated/pet-integration/cases/pet-valid-voprf-registration.v0.1.json"
    ): "sha256:b5db359f0fccfc415c3d570a237825684e5c2fb95826647ab886758fc46cab45",
    Path(
        "generated/pet-integration/executable-case-results.v0.1.json"
    ): "sha256:096c3fbf23cc1822a764d2d66a03c17943d5c41cabbd6254656426b315c4dcf3",
    Path(
        "generated/pet-integration/profile-index.v0.1.json"
    ): "sha256:7399342c3bc3989630c2d7d9b28208c26b87d0e35385c6100ad96a544416ff92",
    Path(
        "generated/pet-integration/profile-comparison.v0.1.md"
    ): "sha256:4ea0dc38ffab7e30d4f788322cb3855df0d4193d068e34ae211650bc41c71855",
    Path(
        "generated/pet-integration/product-handoff-projection.v0.1.json"
    ): "sha256:5f4e17f692b46bb445c3b0cb710613659459a05f58271c9bed3dafd5436a5617",
    Path(
        "generated/pet-integration/profile-digest-manifest.v0.1.json"
    ): "sha256:6728a4a1152409c7bc0359b9e6ace66397c741481f816a0b83da43c906e7b482",
}
LEGACY_BEHAVIOR_DIGESTS = {
    Path(
        "schema/pet-operation-stage-contract.v0.1.schema.json"
    ): "sha256:7f645afeed764d3907f5cd2992a50a1caccf4fb2b92d53a7edddadc5b9e070ca",
    Path(
        "schema/pet-profile-conformance-cases.v0.1.schema.json"
    ): "sha256:dd853a743c1ff3d467f162ba5d73a8d0744455daf6c093817811d48bc0a271b6",
    Path(
        "specs/pet-integration/operation-stage-contract.v0.1.yaml"
    ): "sha256:aa65e4e5ac3cedd03ca99958fbea414232821d70de35f73f8c68c67f047d3df5",
    Path(
        "conformance/pet-profiles/case-catalog.v0.1.json"
    ): "sha256:73d7398b85a29ebabd9771e63db7cd0febf9aa250aa8776d48fff83303890da4",
    Path(
        "schema/pet-protocol-binding.v0.1.schema.json"
    ): "sha256:f3bafeda118d2d4f8e8639ed5ae78694274b2393015ddf84a7fbc6f264aa2a01",
    Path(
        "specs/pet-integration/protocol-binding.v0.1.yaml"
    ): "sha256:423b049cdce59979d7179de9e1997a7abf5788a6f849b4a6b1fde3e5e6b4b432",
    Path(
        "schema/product-decision-engine-handoff.v0.1.schema.json"
    ): "sha256:a298815516a90098238c49746c40743ef9dea8b40592cbe75d76fec6e0c44019",
    Path(
        "handoff/product-decision-engine-port.v0.1.yaml"
    ): "sha256:277fefa5c549aafff4b34c13f0c7a14091bf25af5a12865ef9e38649c0cffdb3",
    Path(
        "schema/pet-integration-profile.v0.1.schema.json"
    ): "sha256:820b119b71e46420d8e864fc48f763cb1dac7cb6bb5e5a752003b19d8f2892fe",
    Path(
        "schema/pet-integration-profile-registry.v0.1.schema.json"
    ): "sha256:768f2e5a080a8ff3a62a66d773520e9de62f8ef2489740b9716e2989c9cb4f5a",
    Path(
        "profiles/pet-integration/secretflow-kkrt.v0.1.json"
    ): "sha256:2f3701adb199c3dcbb0ea5a2dcfb56729ce04ca3629c13c3e3198f3ff2a1be62",
    Path(
        "profiles/pet-integration/nitro-enclave.v0.1.json"
    ): "sha256:0e771ae5b39965476ba42d93ab4f00ec314541e1e45c7fe156348abff10fb1ab",
    Path(
        "profiles/pet-integration/voprf-component.v0.1.json"
    ): "sha256:a826982fc38ac39c4a0616ad5ff69118d4b887851f530958667889119080cfc9",
    Path(
        "registry/pet-integration-profiles.v0.1.yaml"
    ): "sha256:eadf100c2ac78bebd8e39327a825295d4adfdbce0dc7f9c94eef0d46e87f654a",
    Path(
        "schema/pet-profile-operation-input.v0.1.schema.json"
    ): "sha256:d8152d50e36362ad4cfcf4f050911f44b90a6cbce6f8b96e2bc7b2f4b028c63f",
    Path(
        "schema/pet-profile-case-results.v0.1.schema.json"
    ): "sha256:85e1c59350fe2e8aeab514679a832fa983abd86c4d40f960328b5806b1dce2e5",
    Path(
        "schema/pet-profile-error-codes.v0.1.schema.json"
    ): "sha256:46a49b8fda8b727ba44b5d54bb12ccc95c4dac7e73bcc11818ff6a3185ccfe73",
    Path(
        "config/pet-profile-error-codes.v0.1.json"
    ): "sha256:7290214598ca55257132c6511afea15fe8a4b5a86918d8d0d23bcd52d49289e5",
}
MAX_FILE_BYTES = 2 * 1024 * 1024

DOMAINS = {
    "authority": b"private-match-research-technology-authority/v0.1\x00",
    "profile": b"private-match-pet-integration-profile/v0.3\x00",
    "registry": b"private-match-pet-profile-registry/v0.3\x00",
    "handoff": b"private-match-product-decision-engine-handoff/v0.3\x00",
    "binding": b"private-match-pet-protocol-binding/v0.3\x00",
    "cases": b"private-match-pet-profile-conformance-cases/v0.3\x00",
    "operation": b"private-match-pet-profile-operation-input/v0.3\x00",
    "case_results": b"private-match-pet-profile-executable-case-results/v0.3\x00",
    "stage": b"private-match-pet-operation-stage-contract/v0.3\x00",
    "observer": b"private-match-pet-synthetic-result-observer/v0.1\x00",
    "acknowledgment_evidence": b"private-match-pet-acknowledgment-evidence/v0.3\x00",
    "execution_authorization": b"private-match-pet-execution-authorization/v0.1\x00",
    "index": b"private-match-pet-profile-index/v0.3\x00",
    "projection": b"private-match-product-handoff-projection/v0.3\x00",
    "manifest": b"private-match-pet-generated-manifest/v0.3\x00",
    "compatibility": b"private-match-pet-contract-compatibility/v0.3\x00",
    "result_field_policy": b"private-match-pet-public-result-field-policy/v0.3\x00",
}
V02_PROFILE_DOMAIN = b"private-match-pet-integration-profile/v0.2\x00"


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
    domain = (
        V02_PROFILE_DOMAIN
        if kind == "profile" and value.get("profile_version") == "0.2"
        else DOMAINS[kind]
    )
    return sha256_bytes(domain + canonicalize(material))


def _v02_profile_digest(value: dict[str, Any]) -> str:
    """Reconstruct one published v0.2 profile digest without current inference."""

    material = {key: item for key, item in value.items() if key != "profile_digest"}
    return sha256_bytes(V02_PROFILE_DOMAIN + canonicalize(material))


def _contract_graph(
    root: Path, graph_id: str, version: str, selection: str, paths: dict[str, Path]
) -> dict[str, Any]:
    artifacts = [
        {
            "role": role,
            "path": path.as_posix(),
            "file_digest": sha256_bytes(_regular_file(root, path).read_bytes()),
        }
        for role, path in sorted(paths.items())
    ]
    graph = {
        "graph_id": graph_id,
        "contract_version": version,
        "selection": selection,
        "artifacts": artifacts,
        "graph_digest": "",
    }
    graph["graph_digest"] = sha256_bytes(
        f"private-match-pet-contract-graph/v{version}\x00".encode("ascii")
        + canonicalize(
            {key: value for key, value in graph.items() if key != "graph_digest"}
        )
    )
    return graph


def expected_contract_compatibility(root: Path) -> dict[str, Any]:
    value = {
        "$schema": (
            "https://github.com/itdojp/private-match-protocol/raw/main/"
            "schema/pet-contract-compatibility.v0.3.schema.json"
        ),
        "schema_version": "0.3",
        "record_type": "pet-contract-compatibility",
        "artifact_status": "experimental",
        "graphs": [
            _contract_graph(
                root,
                "rollback-v0.1",
                "0.1",
                "rollback-only",
                LEGACY_CONTRACT_GRAPH_PATHS,
            ),
            _contract_graph(
                root,
                "historical-v0.2",
                "0.2",
                "historical-only",
                V02_CONTRACT_GRAPH_PATHS,
            ),
            _contract_graph(
                root,
                "current-v0.3",
                "0.3",
                "current",
                CURRENT_CONTRACT_GRAPH_PATHS,
            ),
        ],
        "version_requirements": [
            {
                "contract_version": "0.1",
                "selection": "rollback-only",
                "profile_registry_path": LEGACY_REGISTRY_PATH.as_posix(),
                "protocol_binding_path": LEGACY_BINDING_PATH.as_posix(),
                "operation_stage_path": (
                    "specs/pet-integration/operation-stage-contract.v0.1.yaml"
                ),
                "operation_input_schema_path": (
                    "schema/pet-profile-operation-input.v0.1.schema.json"
                ),
                "product_handoff_path": LEGACY_HANDOFF_PATH.as_posix(),
                "error_code_catalog_path": (LEGACY_ERROR_CODE_CATALOG_PATH.as_posix()),
            },
            {
                "contract_version": "0.2",
                "selection": "historical-only",
                "profile_registry_path": V02_REGISTRY_PATH.as_posix(),
                "protocol_binding_path": V02_BINDING_PATH.as_posix(),
                "operation_stage_path": V02_STAGE_CONTRACT_PATH.as_posix(),
                "operation_input_schema_path": (
                    "schema/pet-profile-operation-input.v0.2.schema.json"
                ),
                "product_handoff_path": V02_HANDOFF_PATH.as_posix(),
                "error_code_catalog_path": V02_ERROR_CODE_CATALOG_PATH.as_posix(),
            },
            {
                "contract_version": "0.3",
                "selection": "current",
                "profile_contract_version": "0.2",
                "profile_registry_path": REGISTRY_PATH.as_posix(),
                "protocol_binding_path": BINDING_PATH.as_posix(),
                "operation_stage_path": STAGE_CONTRACT_PATH.as_posix(),
                "operation_input_schema_path": SCHEMAS["operation"].as_posix(),
                "product_handoff_path": HANDOFF_PATH.as_posix(),
                "error_code_catalog_path": ERROR_CODE_CATALOG_PATH.as_posix(),
                "public_result_field_policy_path": (
                    RESULT_FIELD_POLICY_PATH.as_posix()
                ),
            },
        ],
        "rules": {
            "cross_version_mixing": "fail-closed",
            "implicit_fallback": False,
            "forward_inference": False,
            "partial_graph": "fail-closed",
            "rollback_selection": "complete-v0.1-graph-only",
            "historical_selection": "complete-v0.2-graph-explicit-only",
            "current_selection": "complete-v0.3-graph-only",
            "corrected_versions_not_current": ["0.1", "0.2"],
            "v02_acknowledgment_evidence_in_v03": "fail-closed",
            "shared_profile_authority": "exact-v0.2-bytes-under-v0.3-wrapper",
        },
        "limitations": [
            "The compatibility map binds public contract files, not a Product implementation.",
            "Rollback is an explicit whole-graph selection and never an implicit fallback.",
            "Published v0.2 remains historical and is never inferred as current v0.3 authority.",
        ],
        "compatibility_digest": "",
    }
    value["compatibility_digest"] = detached_digest(
        "compatibility", value, "compatibility_digest"
    )
    return value


def validate_contract_compatibility(values: dict[str, Any]) -> None:
    for relative, digest in PUBLISHED_V02_DIGESTS.items():
        _require(
            sha256_bytes(_regular_file(values["root"], relative).read_bytes())
            == digest,
            "PET-LEGACY-VERSION-DIGEST",
            relative.as_posix(),
        )
    compatibility = values["compatibility"]
    _require(
        compatibility == expected_contract_compatibility(values["root"]),
        "PET-CONTRACT-VERSION-GRAPH",
    )


def validate_result_field_policy(values: dict[str, Any]) -> None:
    """Require one closed, digest-bound path policy across public surfaces."""

    policy = values["result_field_policy"]
    _require(
        policy["policy_digest"]
        == detached_digest("result_field_policy", policy, "policy_digest"),
        "PET-PUBLIC-RESULT-FIELD-POLICY",
    )
    _require(
        policy["decision_vocabulary"] == PROTOCOL_OUTPUTS,
        "PET-PUBLIC-RESULT-FIELD-POLICY",
    )
    _require(
        set(policy["prohibited_result_field_names"])
        == {
            "bilateral_result",
            "credential",
            "exact_count",
            "local_result",
            "matching_element",
            "party_a_result",
            "party_b_result",
            "party_local_result",
            "party_results",
            "plaintext_result",
            "private_input",
            "raw_grant",
            "result_value",
        },
        "PET-PUBLIC-RESULT-FIELD-POLICY",
    )
    observer = policy["synthetic_observer"]
    _require(
        observer
        == {
            "surface": "synthetic_conformance_observer",
            "visibility": "synthetic-global-observer",
            "allowed_decision_paths": [
                "synthetic_conformance_observer.party_local_result_observations.party_a",
                "synthetic_conformance_observer.party_local_result_observations.party_b",
            ],
            "coordinator_visible": False,
            "product_port_input": False,
            "evidence_exported": False,
        },
        "PET-PUBLIC-RESULT-FIELD-POLICY",
    )
    _require(
        policy["metadata_string_policy"]
        == {
            "schema_valid_metadata_may_equal_decision_vocabulary": True,
            "substring_matching": "prohibited",
            "arbitrary_value_global_scanning": "prohibited",
        },
        "PET-PUBLIC-RESULT-FIELD-POLICY",
    )
    policy_digest = policy["policy_digest"]
    _require(
        values["stage"]["public_result_field_policy_digest"] == policy_digest
        and values["binding"]["public_result_field_policy_digest"] == policy_digest
        and values["handoff"]["public_result_field_policy_digest"] == policy_digest
        and values["registry"]["public_result_field_policy_digest"] == policy_digest
        and values["cases"]["public_result_field_policy_digest"] == policy_digest,
        "PET-PUBLIC-RESULT-FIELD-POLICY",
    )
    expected_path = RESULT_FIELD_POLICY_PATH.as_posix()
    _require(
        values["stage"]["public_result_field_policy_path"] == expected_path
        and values["binding"]["public_result_field_policy_path"] == expected_path
        and values["handoff"]["public_result_field_policy_path"] == expected_path
        and values["registry"]["public_result_field_policy_path"] == expected_path,
        "PET-PUBLIC-RESULT-FIELD-POLICY",
    )


def _validate_result_field_paths(
    policy: dict[str, Any], value: Any, *, surface: str
) -> None:
    """Reject result-bearing public fields by exact key/path, never by value."""

    prohibited_names = set(policy["prohibited_result_field_names"])
    prohibited_paths = set(policy["prohibited_public_paths"])
    allowed_observer_paths = set(policy["synthetic_observer"]["allowed_decision_paths"])

    def walk(item: Any, path: str) -> None:
        if isinstance(item, dict):
            for key, child in item.items():
                child_path = f"{path}.{key}"
                if key in prohibited_names or child_path in prohibited_paths:
                    raise PetProfileError("PET-PUBLIC-RESULT-EXPOSURE")
                walk(child, child_path)
        elif isinstance(item, list):
            for index, child in enumerate(item):
                walk(child, f"{path}[{index}]")
        elif isinstance(item, str) and item in PROTOCOL_OUTPUTS:
            # Decision values are semantic only at the two reviewed observer
            # paths.  The same bytes remain valid as Schema-constrained
            # metadata elsewhere and therefore do not trigger a value-global
            # confidentiality false positive.
            if path.startswith("synthetic_conformance_observer."):
                _require(path in allowed_observer_paths, "PET-PUBLIC-RESULT-EXPOSURE")

    walk(value, surface)


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


def _schema_validate_digest_authority(
    value: Any, schema: dict[str, Any], logical: str
) -> None:
    """Run closed Schema checks for digest authority before semantic hashing."""

    errors = sorted(
        Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(value),
        key=lambda item: list(item.absolute_path),
    )
    for error in errors:
        path = {str(item) for item in error.absolute_path}
        if path & {"profile_authority", "result_acknowledgment_bindings"}:
            raise PetProfileError("PET-PROFILE-AUTHORITY", logical)


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
        "stage": load_yaml(root, STAGE_CONTRACT_PATH),
        "cases": load_json(root, CASE_CATALOG_PATH),
        "error_codes": load_json(root, ERROR_CODE_CATALOG_PATH),
        "compatibility": load_json(root, COMPATIBILITY_PATH),
        "result_field_policy": load_json(root, RESULT_FIELD_POLICY_PATH),
        "profiles": {key: load_json(root, path) for key, path in PROFILE_PATHS.items()},
        "state_machine": load_yaml(root, STATE_MACHINE_PATH),
        "message_registry": load_yaml(root, MESSAGE_REGISTRY_PATH),
        "message_schema": load_json(root, PET_MESSAGE_SCHEMA_PATH),
        "message_materials": load_yaml(root, MESSAGE_MATERIALS_PATH),
    }
    for key in (
        "authority",
        "registry",
        "handoff",
        "binding",
        "stage",
        "cases",
        "error_codes",
        "compatibility",
        "result_field_policy",
    ):
        _schema_validate(
            values[key],
            schemas[key],
            str(
                {
                    "authority": AUTHORITY_PATH,
                    "registry": REGISTRY_PATH,
                    "handoff": HANDOFF_PATH,
                    "binding": BINDING_PATH,
                    "stage": STAGE_CONTRACT_PATH,
                    "cases": CASE_CATALOG_PATH,
                    "error_codes": ERROR_CODE_CATALOG_PATH,
                    "compatibility": COMPATIBILITY_PATH,
                    "result_field_policy": RESULT_FIELD_POLICY_PATH,
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


PROFILE_AUTHORITY_KEYS = frozenset(
    {"profile_id", "profile_version", "profile_digest", "profile_instance_id"}
)
ACKNOWLEDGMENT_EVIDENCE_KEYS = frozenset(
    {
        "normalized_acknowledgment_status",
        "opaque_receipt_ref",
        "profile_evidence_ref",
        "profile_evidence_binding_digest",
        "session_id",
        "profile_id",
        "profile_version",
        "profile_digest",
        "profile_instance_id",
        "evaluation_attempt_id",
    }
)
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+$")
_PROFILE_ID_RE = re.compile(r"^[a-z][a-z0-9-]{2,127}$")
_INSTANCE_ID_RE = re.compile(r"^[!-~]{1,2048}$")


def require_profile_authority(value: Any) -> dict[str, str]:
    """Return one closed, normalized profile authority or fail boundedly.

    This helper is deliberately independent from the enclosing operation
    Schema so direct semantic callers cannot reach digest or equality logic
    with an incomplete mapping.
    """

    _require(
        isinstance(value, dict) and set(value) == PROFILE_AUTHORITY_KEYS,
        "PET-PROFILE-AUTHORITY",
    )
    normalized = {key: value[key] for key in sorted(PROFILE_AUTHORITY_KEYS)}
    _require(
        all(
            isinstance(item, str) and 0 < len(item) <= 2048
            for item in normalized.values()
        ),
        "PET-PROFILE-AUTHORITY",
    )
    _require(
        bool(_PROFILE_ID_RE.fullmatch(normalized["profile_id"]))
        and bool(_VERSION_RE.fullmatch(normalized["profile_version"]))
        and bool(_DIGEST_RE.fullmatch(normalized["profile_digest"])),
        "PET-PROFILE-AUTHORITY",
    )
    _require(
        bool(_INSTANCE_ID_RE.fullmatch(normalized["profile_instance_id"])),
        "PET-PROFILE-AUTHORITY",
    )
    return normalized


def require_acknowledgment_evidence_binding(
    value: Any, *, require_bound_digest: bool = True
) -> dict[str, str]:
    """Validate every public ACK Evidence digest input before projection."""

    required_keys = (
        ACKNOWLEDGMENT_EVIDENCE_KEYS
        if require_bound_digest
        else ACKNOWLEDGMENT_EVIDENCE_KEYS - {"profile_evidence_binding_digest"}
    )
    _require(
        isinstance(value, dict) and set(value) == required_keys,
        "PET-PROFILE-AUTHORITY",
    )
    _require(
        value["normalized_acknowledgment_status"] == "ACKNOWLEDGED",
        "PET-CALLBACK-BINDING",
    )
    _require(
        isinstance(value["opaque_receipt_ref"], str)
        and bool(_DIGEST_RE.fullmatch(value["opaque_receipt_ref"])),
        "PET-RECEIPT-BINDING",
    )
    if require_bound_digest:
        _require(
            isinstance(value["profile_evidence_binding_digest"], str)
            and bool(_DIGEST_RE.fullmatch(value["profile_evidence_binding_digest"])),
            "PET-PROFILE-AUTHORITY",
        )
    for key in (
        "profile_evidence_ref",
        "session_id",
        "profile_id",
        "profile_instance_id",
        "evaluation_attempt_id",
    ):
        _require(
            isinstance(value[key], str) and 0 < len(value[key]) <= 2048,
            "PET-PROFILE-AUTHORITY",
        )
    _require(
        isinstance(value["profile_version"], str)
        and bool(_VERSION_RE.fullmatch(value["profile_version"])),
        "PET-PROFILE-AUTHORITY",
    )
    _require(
        isinstance(value["profile_digest"], str)
        and bool(_DIGEST_RE.fullmatch(value["profile_digest"])),
        "PET-PROFILE-AUTHORITY",
    )
    return {key: value[key] for key in sorted(required_keys)}


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
    _require(profile["profile_version"] == "0.2", "PET-PROFILE-VERSION", identifier)
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
        profile["profile_digest"] == _v02_profile_digest(profile),
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
        all(
            item["category"]
            in {
                "AUTHENTICATION_FAILED",
                "CLOCK_DOMAIN_INVALID",
                "EVALUATION_TIMEOUT",
                "PARTIAL_PARTY_FAILURE",
                "QUERY_BUDGET_EXHAUSTED",
                "REPLAY_CONFLICT",
                "RESOURCE_LIMIT_EXCEEDED",
                "RESULT_CONFLICT",
                "UNKNOWN_STATE",
                "VERIFICATION_MATERIAL_MISSING",
            }
            for item in profile["protocol_contract"]["failure_mappings"]
        ),
        "PET-FAILURE-MAPPING",
        identifier,
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
            {"policy_id", "policy_version"}
            <= set(profile["protocol_contract"]["opaque_receipt"]["binding_fields"]),
            "PET-RECEIPT-POLICY",
            identifier,
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
            setup = profile["setup_authority"]
            _require(
                "debug-mode attestation" in setup["prohibited"]
                and "non-debug mode" in setup["requirements"],
                "PET-TEE-DEBUG-MODE",
                identifier,
            )
            _require(
                "fresh verifier nonce" in setup["requirements"],
                "PET-TEE-FRESH-NONCE",
                identifier,
            )
            _require(
                "expected PCR policy" in setup["requirements"],
                "PET-TEE-PCR-POLICY",
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
        "operation-stage",
        "stage-field-availability",
        "party-local-result-visibility",
        "pre-post-state-contract",
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
    _require(
        "reject operation-stage substitution"
        in handoff_fields["operation-stage"]["expected_product_port_behavior"]
        and "fabricated commitment, attempt, receipt, verification material, or result state"
        in handoff_fields["stage-field-availability"]["fail_closed_rule"]
        and "bilateral plaintext Party results"
        in handoff_fields["party-local-result-visibility"]["fail_closed_rule"]
        and "existing State Machine"
        in handoff_fields["pre-post-state-contract"]["expected_product_port_behavior"],
        "PET-HANDOFF-STAGE-SEMANTICS",
    )


def validate_semantics(values: dict[str, Any]) -> None:
    authority = values["authority"]
    validate_research_authority(authority)
    validate_result_field_policy(values)
    profiles = values["profiles"]
    stage = values["stage"]
    expected_stage = expected_operation_stage_contract(values)
    _require(stage == expected_stage, "PET-STAGE-AUTHORITY")
    _require(
        _regular_file(values["root"], STAGE_CONTRACT_PATH).read_bytes()
        == operation_stage_contract_bytes(values),
        "PET-STAGE-BYTES",
    )
    validate_error_code_authority(values)
    stage_digest = stage["stage_contract_digest"]
    expected_operations = expected_protocol_operations(
        values["message_registry"], values["state_machine"]
    )
    _require(
        set(profiles) == COMPLETE_PROFILE_IDS | COMPONENT_PROFILE_IDS, "PET-PROFILE-SET"
    )
    for identifier, profile in profiles.items():
        _require(profile["profile_id"] == identifier, "PET-PROFILE-PATH-ID", identifier)
        _validate_profile(profile, authority["authority_digest"], expected_operations)
        _require(
            profile["protocol_contract"]["operation_stage_contract_digest"]
            == V02_OPERATION_STAGE_DIGEST,
            "PET-PROFILE-STAGE-DIGEST",
            identifier,
        )
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
        registry["operation_stage_contract_digest"] == stage_digest,
        "PET-REGISTRY-STAGE-DIGEST",
    )
    _require(
        registry["profile_contract_authority"]
        == {
            "profile_contract_version": "0.2",
            "profile_schema_path": V02_CONTRACT_GRAPH_PATHS[
                "profile-schema"
            ].as_posix(),
            "operation_stage_contract_path": V02_STAGE_CONTRACT_PATH.as_posix(),
            "operation_stage_contract_digest": V02_OPERATION_STAGE_DIGEST,
            "compatibility_mode": "exact-v0.2-profile-under-v0.3-wrapper",
        },
        "PET-CONTRACT-VERSION-GRAPH",
    )
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
        binding["operation_stage_contract_path"] == STAGE_CONTRACT_PATH.as_posix()
        and binding["operation_stage_contract_digest"] == stage_digest,
        "PET-BINDING-STAGE-DIGEST",
    )
    _require(
        binding["contract_authority"]
        == {
            "operation_input_schema_path": SCHEMAS["operation"].as_posix(),
            "conformance_case_schema_path": SCHEMAS["cases"].as_posix(),
            "executable_result_schema_path": SCHEMAS["case_results"].as_posix(),
            "message_envelope_schema_path": PET_MESSAGE_SCHEMA_PATH.as_posix(),
            "evaluation_start_message_version": "0.2",
            "result_acceptance_notice_message_version": "0.2",
        },
        "PET-CONTRACT-VERSION-GRAPH",
    )
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
    _require(
        handoff["operation_stage_contract_path"] == STAGE_CONTRACT_PATH.as_posix()
        and handoff["operation_stage_contract_digest"] == stage_digest,
        "PET-HANDOFF-STAGE-DIGEST",
    )
    _require(
        handoff["registry_path"] == REGISTRY_PATH.as_posix()
        and handoff["protocol_binding_path"] == BINDING_PATH.as_posix()
        and handoff["protocol_binding_digest"] == binding["binding_digest"],
        "PET-CONTRACT-VERSION-GRAPH",
    )
    _require(
        handoff["acknowledgment_substate_requirements"]
        == {
            "source_phase": "EVALUATING",
            "phase_specific_abort_validation": True,
            "common_opaque_receipt_preserved": True,
            "proposed_result_presence_preserved": True,
            "accepted_result_before_acceptance": "prohibited",
            "party_local_plaintext_result_visibility": "party-local-only",
            "operation_stage_contract_version": "0.3",
            "protocol_binding_version": "0.3",
            "exact_profile_digest_required": True,
            "acknowledgment_evidence_binding_version": "0.3",
            "acknowledgment_evidence_digest_domain": (
                "private-match-pet-acknowledgment-evidence/v0.3"
            ),
        },
        "PET-HANDOFF-STAGE-SEMANTICS",
    )
    stage_projection_keys = (
        "lifecycle_stage",
        "expected_pre_phases",
        "expected_post_phases",
        "fields_required_on_input",
        "fields_required_none",
        "fields_prohibited_on_input",
        "fields_introduced",
        "party_local_only_fields",
        "coordinator_visible_fields",
        "result_classification",
        "query_budget_effect",
        "transcript_mutated",
    )
    expected_handoff_stages = [
        {
            "operation": item["operation_id"],
            **{key: item[key] for key in stage_projection_keys},
        }
        for item in stage["operations"]
    ]
    _require(
        handoff["operation_stage_projection"] == expected_handoff_stages,
        "PET-HANDOFF-STAGE-PROJECTION",
    )
    _validate_handoff_semantics(handoff)
    _require(
        handoff["handoff_digest"]
        == detached_digest("handoff", handoff, "handoff_digest"),
        "PET-HANDOFF-DIGEST",
    )
    validate_case_catalog(values, root=None)
    # Validate the whole-version graph only after the individual contracts have
    # produced their more specific fail-closed diagnostics.  This preserves the
    # public error taxonomy while still rejecting a fully redigested mixed graph.
    validate_contract_compatibility(values)


def validate_error_code_authority(values: dict[str, Any]) -> None:
    """Require exact parity for every PET error-code authority surface."""

    catalog = values["error_codes"]
    declared = {item["code"] for item in catalog["codes"]}
    source = _regular_file(values["root"], "scripts/pet_profiles.py").read_text(
        encoding="utf-8"
    )
    emitted_or_required = set(re.findall(r"PET-[A-Z0-9]+(?:-[A-Z0-9]+)+", source))
    _require(declared == emitted_or_required, "PET-ERROR-CODE-CATALOG-PARITY")
    case_schema = values["schemas"]["cases"]
    invalid_item = case_schema["properties"]["invalid_cases"]["items"]["properties"]
    schema_codes = set(invalid_item["expected_error"]["enum"])
    schema_mutations = set(invalid_item["mutation"]["enum"])
    _require(
        schema_codes == set(INVALID_CASE_CODES.values()), "PET-ERROR-CODE-SCHEMA-PARITY"
    )
    _require(schema_mutations == set(INVALID_CASE_CODES), "PET-MUTATION-SCHEMA-PARITY")
    catalog_cases = {
        item["mutation"]: item["expected_error"]
        for item in values["cases"]["invalid_cases"]
    }
    _require(catalog_cases == INVALID_CASE_CODES, "PET-MUTATION-RUNTIME-PARITY")


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
    "callback-resource-policy-substitution": "PET-RESOURCE-POLICY",
    "callback-execution-authority-substitution": "PET-EXECUTION-AUTHORIZATION-BINDING",
    "timeout-before-deadline": "PET-EVALUATION-DEADLINE",
    "timeout-nonincreasing-time": "PET-AUTHORITATIVE-TIME-ORDER",
    "timeout-state-message-time-mismatch": "PET-EVALUATION-TIME-AUTHORITY",
    "timeout-noncanonical-time": "PET-AUTHORITATIVE-TIME-ORDER",
    "receipt-ack-before-contributions": "PET-CONTRIBUTIONS-INCOMPLETE",
    "abort-consumed-budget-refund": "PET-STATE-TRANSITION-PARITY",
    "abort-evaluating-unconsumed": "PET-QUERY-BUDGET",
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

# Field availability is reviewed here while event/message/transition authority is
# projected from the existing State Machine and Message Registry below.  The
# resulting YAML is a closed derived authority, not a second State Machine.
STAGE_FIELD_POLICY = {
    "register-component": {
        "stage": "registry-registration",
        "before": ["profile_authority"],
        "introduced": ["component_registration"],
        "required": ["profile_authority", "execution_mode"],
        "none": [],
        "prohibited": ["session_state", "party_local_result", "opaque_receipt"],
        "retained": ["profile_authority"],
        "invalidated": [],
        "party_local": [],
        "coordinator": [],
        "selected_profile": ["component_registration"],
        "classification": "component-registration",
        "budget": "none",
        "transcript": False,
    },
    "select-profile": {
        "stage": "session-creation",
        "before": ["protocol_authority", "profile_authority"],
        "introduced": ["session_id", "policy_binding", "selected_profile"],
        "required": ["session_proposal", "selected_profile"],
        "none": [
            "participant_binding",
            "commitment_pair_id",
            "evaluation_attempt_id",
            "opaque_receipt_ref",
            "result_state",
            "query_budget_state",
        ],
        "prohibited": [
            "party_local_result",
            "verification_material",
            "result_callback",
        ],
        "retained": ["profile_authority"],
        "invalidated": [],
        "party_local": [],
        "coordinator": ["session_id", "policy_binding", "selected_profile"],
        "selected_profile": ["profile_authority"],
        "classification": "accepted-mutation",
        "budget": "none",
        "transcript": True,
    },
    "reserve-query-budget": {
        "stage": "query-budget-reservation",
        "before": [
            "session_id",
            "policy_binding",
            "participant_binding",
            "query_budget_state=NONE",
        ],
        "introduced": ["query_budget_state=RESERVED"],
        "required": ["authorization_ref", "participant_binding"],
        "none": [
            "commitment_pair_id",
            "evaluation_attempt_id",
            "opaque_receipt_ref",
            "result_state",
        ],
        "prohibited": ["party_local_result", "result_callback", "final_receipt"],
        "retained": [
            "session_id",
            "policy_binding",
            "participant_binding",
            "selected_profile",
        ],
        "invalidated": [],
        "party_local": [],
        "coordinator": ["authorization_ref", "query_budget_state"],
        "selected_profile": [],
        "classification": "accepted-mutation",
        "budget": "reserve",
        "transcript": True,
    },
    "start-evaluation": {
        "stage": "evaluation-start",
        "before": [
            "session_id",
            "policy_binding",
            "participant_binding",
            "commitment_pair_id",
            "query_budget_state=RESERVED",
        ],
        "introduced": [
            "evaluation_attempt_id",
            "evaluation_deadline",
            "query_budget_state=CONSUMED",
        ],
        "required": [
            "commitment_pair_id",
            "evaluation_attempt_id",
            "verification_material",
            "resource_policy",
        ],
        "none": ["opaque_receipt_ref", "result_state"],
        "prohibited": ["party_local_result", "final_receipt", "result_callback"],
        "retained": [
            "session_id",
            "policy_binding",
            "participant_binding",
            "commitment_pair_id",
            "selected_profile",
        ],
        "invalidated": [],
        "party_local": [],
        "coordinator": [
            "evaluation_attempt_id",
            "verification_material",
            "resource_policy",
        ],
        "selected_profile": [
            "evaluation_attempt_id",
            "verification_material",
            "resource_policy",
        ],
        "classification": "accepted-mutation",
        "budget": "consume",
        "transcript": True,
    },
    "submit-contribution": {
        "stage": "party-contribution",
        "before": [
            "session_id",
            "policy_binding",
            "commitment_pair_id",
            "evaluation_attempt_id",
        ],
        "introduced": ["party_slot_contribution"],
        "required": ["party_slot", "contribution_ref"],
        "none": ["opaque_receipt_ref", "result_state"],
        "prohibited": [
            "party_local_result",
            "bilateral_result",
            "receipt_acknowledgment",
        ],
        "retained": [
            "session_id",
            "policy_binding",
            "commitment_pair_id",
            "evaluation_attempt_id",
            "query_budget_state=CONSUMED",
        ],
        "invalidated": [],
        "party_local": ["private_contribution_source"],
        "coordinator": ["normalized_contribution_status"],
        "selected_profile": ["contribution_ref"],
        "classification": "accepted-mutation",
        "budget": "unchanged",
        "transcript": True,
    },
    "acknowledge-receipt": {
        "stage": "party-receipt-acknowledgment",
        "before": [
            "session_id",
            "policy_binding",
            "commitment_pair_id",
            "evaluation_attempt_id",
            "both_party_contributions",
        ],
        "introduced": ["party_slot_receipt_ack", "opaque_receipt_ref"],
        "required": [
            "party_slot",
            "opaque_receipt_ref",
            "acknowledgment_status",
            "profile_evidence_ref",
        ],
        "none": [],
        "prohibited": [
            "party_local_result",
            "bilateral_result",
            "other_party_acknowledgment",
        ],
        "retained": [
            "session_id",
            "policy_binding",
            "commitment_pair_id",
            "evaluation_attempt_id",
            "query_budget_state=CONSUMED",
        ],
        "invalidated": [],
        "party_local": ["party_local_result"],
        "coordinator": [
            "opaque_receipt_ref",
            "acknowledgment_status",
            "profile_evidence_ref",
        ],
        "selected_profile": ["opaque_receipt_ref", "acknowledgment_status"],
        "classification": "accepted-mutation",
        "budget": "unchanged",
        "transcript": True,
    },
    "accept-profile-callback": {
        "stage": "symmetric-result-acceptance",
        "before": [
            "session_id",
            "policy_binding",
            "commitment_pair_id",
            "evaluation_attempt_id",
            "both_receipt_acknowledgments",
        ],
        "introduced": ["accepted_result_state", "phase=RESULT_ACCEPTED"],
        "required": [
            "callback_identity",
            "opaque_receipt_ref",
            "acknowledgment_status",
            "profile_evidence_ref",
            "verification_material",
            "resource_policy_binding",
            "execution_authorization_digest",
        ],
        "none": [],
        "prohibited": ["party_local_result", "bilateral_result", "plaintext_result"],
        "retained": [
            "session_id",
            "policy_binding",
            "commitment_pair_id",
            "evaluation_attempt_id",
            "query_budget_state=CONSUMED",
            "resource_policy_binding",
            "execution_authorization_digest",
        ],
        "invalidated": [],
        "party_local": ["party_local_result"],
        "coordinator": [
            "opaque_receipt_ref",
            "acknowledgment_status",
            "profile_evidence_ref",
            "resource_policy_binding",
            "execution_authorization_digest",
        ],
        "selected_profile": ["synthetic_result_comparison"],
        "classification": "accepted-mutation",
        "budget": "unchanged",
        "transcript": True,
    },
    "evaluation-timeout": {
        "stage": "evaluation-timeout",
        "before": [
            "phase=EVALUATING",
            "evaluation_attempt_id",
            "query_budget_state=CONSUMED",
            "authoritative_time",
            "evaluation_deadline",
        ],
        "introduced": ["terminal_failure_code=EVALUATION_TIMEOUT", "phase=ABORTED"],
        "required": [
            "new_authoritative_time",
            "authoritative_time",
            "evaluation_deadline",
            "prior_transcript_head",
        ],
        "none": [],
        "prohibited": ["party_local_result", "new_receipt", "profile_callback"],
        "retained": [
            "evaluation_attempt_id",
            "query_budget_state=CONSUMED",
            "evaluation_deadline",
        ],
        "invalidated": ["disclosure_state"],
        "party_local": [],
        "coordinator": ["normalized_timeout_status"],
        "selected_profile": [],
        "classification": "terminal-mutation",
        "budget": "preserve-consumed",
        "transcript": True,
    },
    "abort-and-cleanup": {
        "stage": "abort-and-cleanup",
        "before": ["live_session"],
        "introduced": ["terminal_failure_code", "phase=ABORTED", "cleanup_evidence"],
        "required": ["normalized_failure_category", "cleanup_completed"],
        "none": [],
        "prohibited": ["fabricated_result_state", "bilateral_result", "new_receipt"],
        "retained": [
            "session_id",
            "policy_binding",
            "selected_profile",
            "evaluation_contribution",
            "result_ack",
            "opaque_receipt_ref",
            "proposed_result_state",
            "accepted_result_state",
        ],
        "invalidated": ["disclosure_state"],
        "party_local": [],
        "coordinator": ["normalized_failure_category", "cleanup_completed"],
        "selected_profile": ["cleanup_required"],
        "classification": "terminal-mutation",
        "budget": "phase-dependent-abort",
        "transcript": True,
    },
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


def expected_operation_stage_contract(values: dict[str, Any]) -> dict[str, Any]:
    """Derive the PET lifecycle-stage authority from reviewed core artifacts."""

    transitions = {item["id"]: item for item in values["state_machine"]["transitions"]}
    messages = {
        item["message_type"]: item for item in values["message_registry"]["messages"]
    }
    bindings = {item["operation"]: item for item in values["binding"]["operations"]}
    operations = []
    for operation_id, policy in STAGE_FIELD_POLICY.items():
        if operation_id == "register-component":
            events: list[str] = []
            transition_ids: list[str] = []
            pre_phases: list[str] = []
            post_phases: list[str] = []
            message_type = None
            message_version = None
            transcript_participation = "none"
            replay_domain = "profile ID/version/digest registration identity"
        else:
            binding = bindings[operation_id]
            transition_ids = binding["transition_ids"]
            selected = [transitions[item] for item in transition_ids]
            events = binding["events"]
            pre_phases = sorted(
                {phase for item in selected for phase in item["from_phase"]}
            )
            post_phases = sorted(
                {
                    phase
                    for item in selected
                    for phase in (
                        item["from_phase"]
                        if item["to_phase"] == "SAME"
                        else [item["to_phase"]]
                    )
                }
            )
            message_type = binding["message_type"]
            message_version = binding["message_version"]
            if message_type is not None:
                message = messages[message_type]
                _require(
                    message["state_machine"]["events"] == events
                    and message["state_machine"]["transitions"] == transition_ids,
                    "PET-STAGE-MESSAGE-PARITY",
                    operation_id,
                )
            transcript_participation = binding["transcript_participation"]
            replay_domain = binding["replay_idempotency_domain"]
        operations.append(
            {
                "operation_id": operation_id,
                "lifecycle_stage": policy["stage"],
                "message_type": message_type,
                "message_version": message_version,
                "events": events,
                "transition_ids": transition_ids,
                "expected_pre_phases": pre_phases,
                "expected_post_phases": post_phases,
                "fields_available_before": policy["before"],
                "fields_introduced": policy["introduced"],
                "fields_required_on_input": policy["required"],
                "fields_required_none": policy["none"],
                "fields_prohibited_on_input": policy["prohibited"],
                "fields_retained_unchanged": policy["retained"],
                "fields_invalidated": policy["invalidated"],
                "party_local_only_fields": policy["party_local"],
                "coordinator_visible_fields": policy["coordinator"],
                "selected_profile_visible_fields": policy["selected_profile"],
                "transcript_participation": transcript_participation,
                "replay_idempotency_domain": replay_domain,
                "result_classification": policy["classification"],
                "query_budget_effect": policy["budget"],
                "transcript_mutated": policy["transcript"],
            }
        )
    result = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "schema_version": "0.3",
        "record_type": "pet-operation-stage-contract",
        "artifact_status": "experimental",
        "state_machine_digest": STATE_MACHINE_DIGEST,
        "message_registry_digest": MESSAGE_REGISTRY_DIGEST,
        "public_result_field_policy_path": RESULT_FIELD_POLICY_PATH.as_posix(),
        "public_result_field_policy_digest": values["result_field_policy"][
            "policy_digest"
        ],
        "operations": operations,
        "abort_phase_authority": _abort_phase_contract(values),
        "evaluating_acknowledgment_substate_authority": (
            _evaluating_acknowledgment_substate_contract(values)
        ),
        "stage_contract_digest": "",
        "limitations": [
            "This contract is a deterministic projection of the reviewed State Machine and Message Registry, not an independent State Machine.",
            "Synthetic global-observer data is test-only and is not a Product or Coordinator input.",
        ],
    }
    result["stage_contract_digest"] = detached_digest(
        "stage", result, "stage_contract_digest"
    )
    return result


def operation_stage_contract_bytes(values: dict[str, Any]) -> bytes:
    """Serialize the derived stage authority deterministically."""

    return yaml.safe_dump(
        expected_operation_stage_contract(values),
        sort_keys=False,
        allow_unicode=True,
        width=1000,
    ).encode("utf-8")


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


def _observer_for_receipt(receipt: str) -> dict[str, Any]:
    observer = {
        "visibility": "synthetic-global-observer",
        "party_local_result_observations": {
            "party_a": "MATCH",
            "party_b": "MATCH",
        },
        "result_receipt_binding": receipt,
        "coordinator_visible": False,
        "product_port_input": False,
        "evidence_exported": False,
        "observer_digest": "",
    }
    observer["observer_digest"] = _fixture_digest(
        DOMAINS["observer"],
        {key: value for key, value in observer.items() if key != "observer_digest"},
    )
    return observer


def _stage_entry(values: dict[str, Any], operation: str) -> dict[str, Any]:
    return next(
        item
        for item in values["stage"]["operations"]
        if item["operation_id"] == operation
    )


def _profile_authority(profile: dict[str, Any], instance: str) -> dict[str, Any]:
    return {
        "profile_id": profile["profile_id"],
        "profile_version": profile["profile_version"],
        "profile_digest": profile["profile_digest"],
        "profile_instance_id": instance,
    }


def _protocol_authority(values: dict[str, Any]) -> dict[str, Any]:
    return {
        "protocol_profile": "private-match-core",
        "protocol_version": "0.1",
        "state_machine_digest": STATE_MACHINE_DIGEST,
        "message_registry_digest": MESSAGE_REGISTRY_DIGEST,
        "pet_registry_digest": values["registry"]["registry_digest"],
        "operation_stage_digest": values["stage"]["stage_contract_digest"],
        "public_result_field_policy_digest": values["result_field_policy"][
            "policy_digest"
        ],
    }


def _message_projection(values: dict[str, Any], operation: str) -> dict[str, Any]:
    binding = next(
        item
        for item in values["binding"]["operations"]
        if item["operation"] == operation
    )
    return {
        "message_type": binding["message_type"],
        "message_version": binding["message_version"],
        "delivery_class": binding["delivery_class"],
        "direction": binding["direction"],
        "sender_role": binding["allowed_senders"][0],
        "verifier_role": binding["verifier"],
        "intended_audience": binding["intended_audience"],
        "prior_transcript_head": "sha256:" + "42" * 32,
    }


def _state(
    phase: str,
    *,
    session: str | None,
    policy: tuple[str | None, str | None],
    participants: str | None,
    commitment: str | None,
    attempt: str | None,
    receipt: str | None,
    result_state: str | None,
    budget: str | None,
    contributions: list[str] | None = None,
    acknowledgments: list[str] | None = None,
    authoritative_time: str = "2026-07-21T00:00:00Z",
    evaluation_deadline: str | None = None,
    resource_policy_binding: str | None = None,
    execution_authorization_digest: str | None = None,
) -> dict[str, Any]:
    return {
        "phase": phase,
        "session_id": session,
        "policy_id": policy[0],
        "policy_version": policy[1],
        "participant_binding_digest": participants,
        "commitment_pair_id": commitment,
        "evaluation_attempt_id": attempt,
        "opaque_receipt_ref": receipt,
        "result_state": result_state,
        "query_budget_state": budget,
        "transcript_head": "sha256:" + "42" * 32,
        "completed_contribution_slots": contributions or [],
        "receipt_acknowledgment_slots": acknowledgments or [],
        "authoritative_time": authoritative_time,
        "evaluation_deadline": evaluation_deadline,
        "resource_policy_binding": resource_policy_binding,
        "execution_authorization_digest": execution_authorization_digest,
    }


ABORT_PHASE_ORDER = (
    "CREATED",
    "PARTICIPANTS_BOUND",
    "COMMITMENTS_PENDING",
    "COMMITTED",
    "EVALUATING",
    "RESULT_ACCEPTED",
    "CONSENT_PENDING",
    "DISCLOSURE_AUTHORIZED",
)

EVALUATING_ACKNOWLEDGMENT_SUBSTATE_ORDER = (
    "contributions-none",
    "contribution-a-only",
    "contribution-b-only",
    "contributions-complete-no-ack",
    "party-a-acknowledged",
    "party-b-acknowledged",
    "both-acknowledged",
)


def _transition_effect(transition: dict[str, Any], effect_id: str) -> dict[str, Any]:
    effect = next(
        (item for item in transition["effects"] if item["id"] == effect_id), None
    )
    _require(effect is not None, "PET-ABORT-PHASE-AUTHORITY")
    return effect


def _require_acknowledgment_substate_authority(
    values: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    """Bind EVALUATING receipt/result substates to the reviewed ACK transitions."""

    transitions = {item["id"]: item for item in values["state_machine"]["transitions"]}
    authority: dict[str, dict[str, Any]] = {}
    for transition_id, party in (
        ("TR-SUBMIT-CONTRIBUTION-A", "A"),
        ("TR-SUBMIT-CONTRIBUTION-B", "B"),
    ):
        transition = transitions.get(transition_id)
        _require(
            transition is not None
            and transition["from_phase"] == ["EVALUATING"]
            and transition["to_phase"] == "SAME"
            and transition["actor"] == f"party_{party.lower()}_client",
            "PET-ABORT-PHASE-AUTHORITY",
        )
        contribution_effect = _transition_effect(transition, f"E-CONTRIBUTION-{party}")
        _require(
            contribution_effect["operation"] == "bind_once"
            and contribution_effect["writes"] == ["evaluation_contribution"]
            and f"G-CONTRIBUTION-{party}-EMPTY"
            in {guard["id"] for guard in transition["guards"]},
            "PET-ABORT-PHASE-AUTHORITY",
        )
    for transition_id, party in (
        ("TR-ACK-RECEIPT-A", "A"),
        ("TR-ACK-RECEIPT-B", "B"),
    ):
        transition = transitions.get(transition_id)
        _require(
            transition is not None
            and transition["from_phase"] == ["EVALUATING"]
            and transition["to_phase"] == "SAME",
            "PET-ABORT-PHASE-AUTHORITY",
        )
        _require(
            "G-CONTRIBUTIONS-COMPLETE"
            in {guard["id"] for guard in transition["guards"]},
            "PET-ABORT-PHASE-AUTHORITY",
        )
        guards = {guard["id"]: guard for guard in transition["guards"]}
        opaque_guard = guards.get("G-OPAQUE-RECEIPT")
        local_result_guard = guards.get(f"G-LOCAL-RESULT-{party}")
        effect = _transition_effect(transition, f"E-ACK-RECEIPT-{party}")
        _require(
            effect["operation"] == "set_if_unset_or_equal"
            and effect["writes"]
            == ["result_ack", "opaque_receipt_ref", "proposed_result_state"],
            "PET-ABORT-PHASE-AUTHORITY",
        )
        _require(
            opaque_guard is not None
            and opaque_guard["predicate"] == "profile_opaque_reference"
            and set(opaque_guard["parameter_reads"])
            == {
                "opaque_receipt_parameter.opaque_receipt_ref",
                "opaque_receipt_parameter.acknowledgment_status",
                "opaque_receipt_parameter.profile_evidence_ref",
            }
            and any(
                "peer" in argument and "equals" in argument
                for argument in opaque_guard["arguments"]
            ),
            "PET-ABORT-PHASE-AUTHORITY",
        )
        _require(
            local_result_guard is not None
            and local_result_guard["predicate"] == "event_parameter_one_of"
            and local_result_guard["reads"] == ["proposed_result_state"]
            and local_result_guard["parameter_reads"]
            == ["local_result_parameter.local_result"],
            "PET-ABORT-PHASE-AUTHORITY",
        )
        coordinator_visibility = next(
            (
                item["data"]
                for item in transition["visibility"]
                if item["actor"] == "coordinator"
            ),
            None,
        )
        _require(
            coordinator_visibility
            == [
                "opaque_receipt_ref",
                "normalized_ack_status",
            ]
            and all(
                "local result" not in field and "local-result" not in field
                for field in coordinator_visibility
            ),
            "PET-ABORT-PHASE-AUTHORITY",
        )
        authority[f"party_{party.lower()}"] = transition

    accept = transitions.get("TR-ACCEPT-SYMMETRIC-RESULT")
    start = transitions.get("TR-START-EVALUATION")
    abort = transitions.get("TR-ABORT")
    _require(
        accept is not None
        and accept["from_phase"] == ["EVALUATING"]
        and accept["to_phase"] == "RESULT_ACCEPTED"
        and "accepted_result_state"
        in _transition_effect(accept, "E-ACCEPT-RESULT")["writes"],
        "PET-ABORT-PHASE-AUTHORITY",
    )
    _require(
        start is not None
        and start["to_phase"] == "EVALUATING"
        and "query_budget_state"
        in {field for effect in start["effects"] for field in effect.get("writes", [])},
        "PET-ABORT-PHASE-AUTHORITY",
    )
    _require(abort is not None, "PET-ABORT-PHASE-AUTHORITY")
    abort_writes = {
        field for effect in abort["effects"] for field in effect.get("writes", [])
    }
    _require(
        not abort_writes
        & {
            "evaluation_contribution",
            "result_ack",
            "opaque_receipt_ref",
            "proposed_result_state",
            "accepted_result_state",
        },
        "PET-ABORT-PHASE-AUTHORITY",
    )
    return authority


def _evaluating_acknowledgment_substate_contract(
    values: dict[str, Any],
) -> list[dict[str, Any]]:
    """Derive all reachable EVALUATING contribution/acknowledgment substates."""

    _require_acknowledgment_substate_authority(values)
    rows = (
        ("contributions-none", [], []),
        ("contribution-a-only", ["party_a"], []),
        ("contribution-b-only", ["party_b"], []),
        ("contributions-complete-no-ack", ["party_a", "party_b"], []),
        ("party-a-acknowledged", ["party_a", "party_b"], ["party_a"]),
        ("party-b-acknowledged", ["party_a", "party_b"], ["party_b"]),
        (
            "both-acknowledged",
            ["party_a", "party_b"],
            ["party_a", "party_b"],
        ),
    )
    result = []
    for substate_id, contributions, acknowledgments in rows:
        presence = {
            party: "present" if party in acknowledgments else "none"
            for party in ("party_a", "party_b")
        }
        result.append(
            {
                "substate_id": substate_id,
                "completed_contribution_slots": contributions,
                "receipt_acknowledgment_slots": acknowledgments,
                "result_acknowledgment_presence": presence,
                "opaque_receipt_state": (
                    "common-present" if acknowledgments else "none"
                ),
                "proposed_result_presence": presence,
                "accepted_result_presence": {
                    "party_a": "none",
                    "party_b": "none",
                },
                "profile_evidence_presence": presence,
                "binding_context_fields": [
                    "session_id",
                    "profile_id",
                    "profile_version",
                    "profile_digest",
                    "profile_instance_id",
                    "evaluation_attempt_id",
                    "profile_evidence_ref",
                    "profile_evidence_binding_digest",
                ],
                "query_budget_state": "CONSUMED",
                "transcript_state": "retained-then-abort-appended",
                "abort_cleanup_effect": "required",
                "fields_retained_for_audit": [
                    "evaluation_contribution",
                    "result_ack",
                    "opaque_receipt_ref",
                    "proposed_result_state",
                    "accepted_result_state",
                ],
                "fields_invalidated_for_future_mutation": [
                    "disclosure_state",
                    "live_session_mutation",
                ],
                "coordinator_visible_fields": [
                    "opaque_receipt_ref",
                    "normalized_ack_status",
                ],
                "party_local_only_fields": [
                    "proposed_result_state",
                    "local_result_binding",
                ],
            }
        )
    _require(
        tuple(item["substate_id"] for item in result)
        == EVALUATING_ACKNOWLEDGMENT_SUBSTATE_ORDER,
        "PET-ABORT-PHASE-AUTHORITY",
    )
    return result


def _fixture_acknowledgment_binding(
    party: str,
    *,
    receipt: str,
    session: str,
    attempt: str,
    profile_authority: dict[str, Any],
) -> dict[str, Any]:
    """Return only Coordinator-visible normalized ACK authority.

    The Party-local proposed result value is deliberately represented by a
    separate presence bit in the synthetic abort-state projection.  It never
    crosses this public authority boundary.
    """
    suffix = party.removeprefix("party_")
    binding = {
        "normalized_acknowledgment_status": "ACKNOWLEDGED",
        "opaque_receipt_ref": receipt,
        "profile_evidence_ref": f"urn:private-match:test:profile-evidence:{suffix}",
        "session_id": session,
        "profile_id": profile_authority["profile_id"],
        "profile_version": profile_authority["profile_version"],
        "profile_digest": profile_authority["profile_digest"],
        "profile_instance_id": profile_authority["profile_instance_id"],
        "evaluation_attempt_id": attempt,
    }
    binding["profile_evidence_binding_digest"] = _acknowledgment_evidence_digest(
        binding
    )
    return binding


def _acknowledgment_evidence_digest(binding: dict[str, Any]) -> str:
    """Bind a public Evidence reference to its exact ACK authority context."""

    material = dict(binding) if isinstance(binding, dict) else binding
    if isinstance(material, dict):
        material.pop("profile_evidence_binding_digest", None)
    validated = require_acknowledgment_evidence_binding(
        material, require_bound_digest=False
    )
    projection = {
        key: validated[key]
        for key in (
            "profile_evidence_ref",
            "session_id",
            "profile_id",
            "profile_version",
            "profile_digest",
            "profile_instance_id",
            "evaluation_attempt_id",
        )
    }
    return sha256_bytes(DOMAINS["acknowledgment_evidence"] + canonicalize(projection))


def _abort_phase_projection(
    values: dict[str, Any],
    phase: str,
    *,
    session: str,
    policy: tuple[str, str],
    participants: str,
    commitment: str,
    attempt: str,
    receipt: str,
    resource_policy_binding: str,
    execution_authorization_digest: str,
    profile_authority: dict[str, Any],
    acknowledgment_substate: str | None,
) -> dict[str, Any]:
    """Project the exact pre-abort state from the reviewed TR-ABORT phases."""

    _require_acknowledgment_substate_authority(values)
    abort = next(
        item
        for item in values["state_machine"]["transitions"]
        if item["id"] == "TR-ABORT"
    )
    _require(
        tuple(abort["from_phase"]) == ABORT_PHASE_ORDER, "PET-ABORT-PHASE-AUTHORITY"
    )
    _require(phase in abort["from_phase"], "PET-ABORT-PHASE-AUTHORITY")
    rank = ABORT_PHASE_ORDER.index(phase)
    participant_value = participants if rank >= 1 else None
    commitment_value = commitment if rank >= 3 else None
    evaluation_available = rank >= 4
    result_available = rank >= 5
    substate_rows = {
        item["substate_id"]: item
        for item in _evaluating_acknowledgment_substate_contract(values)
    }
    if phase == "EVALUATING":
        _require(
            acknowledgment_substate in substate_rows,
            "PET-ABORT-PHASE-AUTHORITY",
        )
        substate = substate_rows[acknowledgment_substate]
        evaluating_contributions = substate["completed_contribution_slots"]
        evaluating_acknowledgments = substate["receipt_acknowledgment_slots"]
    else:
        _require(acknowledgment_substate is None, "PET-ABORT-PHASE-AUTHORITY")
        substate = None
        evaluating_contributions = []
        evaluating_acknowledgments = []
    receipt_available = result_available or bool(evaluating_acknowledgments)
    acknowledgment_slots = (
        ["party_a", "party_b"] if result_available else evaluating_acknowledgments
    )
    contribution_slots = (
        ["party_a", "party_b"]
        if result_available
        else evaluating_contributions
        if phase == "EVALUATING"
        else []
    )
    acknowledgment_bindings = {
        party: (
            _fixture_acknowledgment_binding(
                party,
                receipt=receipt,
                session=session,
                attempt=attempt,
                profile_authority=profile_authority,
            )
            if party in acknowledgment_slots
            else None
        )
        for party in ("party_a", "party_b")
    }
    proposed_presence = {
        party: "PRESENT" if party in acknowledgment_slots else "NONE"
        for party in ("party_a", "party_b")
    }
    accepted_presence = {
        party: "PRESENT" if result_available else "NONE"
        for party in ("party_a", "party_b")
    }
    state = _state(
        phase,
        session=session,
        policy=policy,
        participants=participant_value,
        commitment=commitment_value,
        attempt=attempt if evaluation_available else None,
        receipt=receipt if receipt_available else None,
        result_state=(
            "ACCEPTED"
            if result_available
            else "PROPOSED"
            if evaluating_acknowledgments
            else None
        ),
        budget=("NONE" if rank <= 1 else "RESERVED" if rank < 4 else "CONSUMED"),
        contributions=contribution_slots,
        acknowledgments=acknowledgment_slots,
        authoritative_time=(
            "2026-07-21T00:00:30Z" if evaluation_available else "2026-07-21T00:00:00Z"
        ),
        evaluation_deadline="2026-07-21T00:05:00Z" if evaluation_available else None,
        resource_policy_binding=(
            resource_policy_binding if evaluation_available else None
        ),
        execution_authorization_digest=(
            execution_authorization_digest if evaluation_available else None
        ),
    )
    state.update(
        {
            "consent_state": (
                "PENDING"
                if phase == "CONSENT_PENDING"
                else "COMPLETE"
                if phase == "DISCLOSURE_AUTHORIZED"
                else "NONE"
            ),
            "disclosure_state": (
                "AUTHORIZED" if phase == "DISCLOSURE_AUTHORIZED" else "NONE"
            ),
            "cleanup_state": "NOT_STARTED",
            "acknowledgment_substate_id": (
                acknowledgment_substate if phase == "EVALUATING" else "not-applicable"
            ),
            "result_acknowledgment_bindings": acknowledgment_bindings,
            "proposed_result_presence": proposed_presence,
            "accepted_result_presence": accepted_presence,
        }
    )
    return state


def _abort_phase_contract(values: dict[str, Any]) -> list[dict[str, Any]]:
    """Machine-readable phase matrix derived from the reviewed abort transition."""

    _require_acknowledgment_substate_authority(values)
    abort = next(
        item
        for item in values["state_machine"]["transitions"]
        if item["id"] == "TR-ABORT"
    )
    _require(
        tuple(abort["from_phase"]) == ABORT_PHASE_ORDER, "PET-ABORT-PHASE-AUTHORITY"
    )
    result = []
    for rank, phase in enumerate(ABORT_PHASE_ORDER):
        result.append(
            {
                "source_phase": phase,
                "transition_id": "TR-ABORT",
                "resulting_phase": abort["to_phase"],
                "participant_binding": "required" if rank >= 1 else "none",
                "commitment_pair": "required" if rank >= 3 else "none",
                "evaluation_attempt": "required" if rank >= 4 else "none",
                "evaluation_deadline": "required" if rank >= 4 else "none",
                "resource_policy_binding": "required" if rank >= 4 else "none",
                "execution_authorization_digest": "required" if rank >= 4 else "none",
                "contribution_slots": (
                    "any-subset"
                    if phase == "EVALUATING"
                    else "both"
                    if rank >= 5
                    else "empty"
                ),
                "acknowledgment_slots": (
                    "empty-or-any-subset-after-both-contributions"
                    if phase == "EVALUATING"
                    else "both"
                    if rank >= 5
                    else "empty"
                ),
                "receipt_state": (
                    "accepted"
                    if rank >= 5
                    else "present-iff-acknowledgment"
                    if phase == "EVALUATING"
                    else "none"
                ),
                "result_state": (
                    "accepted"
                    if rank >= 5
                    else "proposed-iff-acknowledgment"
                    if phase == "EVALUATING"
                    else "none"
                ),
                "consent_state": (
                    "pending"
                    if phase == "CONSENT_PENDING"
                    else "complete"
                    if phase == "DISCLOSURE_AUTHORIZED"
                    else "none"
                ),
                "disclosure_state": (
                    "authorized" if phase == "DISCLOSURE_AUTHORIZED" else "none"
                ),
                "query_budget_state": (
                    "NONE" if rank <= 1 else "RESERVED" if rank < 4 else "CONSUMED"
                ),
                "query_budget_effect": (
                    "preserve-consumed" if rank >= 4 else "release-if-not-started"
                ),
                "transcript_mutated": True,
                "cleanup_state_before": "NOT_STARTED",
                "cleanup_requirement": "required",
            }
        )
    return result


def _require_abort_confidentiality(
    policy: dict[str, Any], observed: dict[str, Any]
) -> None:
    _validate_result_field_paths(
        policy,
        observed,
        surface="authoritative_context.initial_state",
    )


def _validate_abort_phase_state(
    values: dict[str, Any],
    observed: dict[str, Any],
    profile_authority: dict[str, Any],
) -> None:
    profile_authority = require_profile_authority(profile_authority)
    selected_profile = values["profiles"].get(profile_authority["profile_id"])
    _require(selected_profile is not None, "PET-PROFILE-AUTHORITY")
    _require(
        profile_authority
        == require_profile_authority(
            _profile_authority(
                selected_profile, profile_authority["profile_instance_id"]
            )
        ),
        "PET-PROFILE-AUTHORITY",
    )
    _require_abort_confidentiality(values["result_field_policy"], observed)
    phase = observed.get("phase", "")
    _require(phase in ABORT_PHASE_ORDER, "PET-ABORT-PHASE-AUTHORITY")
    authority = next(
        item for item in _abort_phase_contract(values) if item["source_phase"] == phase
    )
    availability = {
        "participant_binding_digest": authority["participant_binding"],
        "commitment_pair_id": authority["commitment_pair"],
        "evaluation_attempt_id": authority["evaluation_attempt"],
        "evaluation_deadline": authority["evaluation_deadline"],
        "resource_policy_binding": authority["resource_policy_binding"],
        "execution_authorization_digest": authority["execution_authorization_digest"],
    }
    for field, requirement in availability.items():
        _require(
            (observed.get(field) is not None) == (requirement == "required"),
            "PET-ABORT-PHASE-AUTHORITY",
        )
    _require(
        observed.get("query_budget_state") == authority["query_budget_state"],
        "PET-QUERY-BUDGET",
    )
    contributions = observed.get("completed_contribution_slots")
    acknowledgments = observed.get("receipt_acknowledgment_slots")
    if authority["contribution_slots"] == "empty":
        slots_valid = contributions == [] and acknowledgments == []
    elif authority["contribution_slots"] == "any-subset":
        valid_subsets = [[], ["party_a"], ["party_b"], ["party_a", "party_b"]]
        slots_valid = (
            contributions in valid_subsets and acknowledgments in valid_subsets
        )
        slots_valid = slots_valid and (
            contributions == ["party_a", "party_b"] or acknowledgments == []
        )
    else:
        slots_valid = contributions == ["party_a", "party_b"] and acknowledgments == [
            "party_a",
            "party_b",
        ]
    substate = None
    if phase == "EVALUATING":
        substate = next(
            (
                item
                for item in _evaluating_acknowledgment_substate_contract(values)
                if item["substate_id"] == observed.get("acknowledgment_substate_id")
            ),
            None,
        )
        _require(
            substate is not None
            and contributions == substate["completed_contribution_slots"]
            and acknowledgments == substate["receipt_acknowledgment_slots"],
            "PET-ABORT-PHASE-AUTHORITY",
        )
    else:
        _require(
            observed.get("acknowledgment_substate_id") == "not-applicable",
            "PET-ABORT-PHASE-AUTHORITY",
        )
    receipt_expected = authority["receipt_state"] == "accepted" or bool(acknowledgments)
    result_expected = (
        "ACCEPTED"
        if authority["result_state"] == "accepted"
        else "PROPOSED"
        if authority["result_state"] == "proposed-iff-acknowledgment"
        and bool(acknowledgments)
        else None
    )
    _require(slots_valid, "PET-ABORT-PHASE-AUTHORITY")
    _require(
        (observed.get("opaque_receipt_ref") is not None) == receipt_expected,
        (
            "PET-RECEIPT-BINDING"
            if phase == "EVALUATING"
            else "PET-ABORT-PHASE-AUTHORITY"
        ),
    )
    _require(
        observed.get("result_state") == result_expected
        and observed.get("consent_state") == authority["consent_state"].upper()
        and observed.get("disclosure_state") == authority["disclosure_state"].upper()
        and observed.get("cleanup_state") == authority["cleanup_state_before"],
        "PET-ABORT-PHASE-AUTHORITY",
    )
    expected_proposed = {
        party: "PRESENT" if party in acknowledgments else "NONE"
        for party in ("party_a", "party_b")
    }
    expected_accepted = {
        party: "PRESENT" if authority["result_state"] == "accepted" else "NONE"
        for party in ("party_a", "party_b")
    }
    _require(
        observed.get("proposed_result_presence") == expected_proposed
        and observed.get("accepted_result_presence") == expected_accepted,
        "PET-ABORT-PHASE-AUTHORITY",
    )
    bindings = observed.get("result_acknowledgment_bindings")
    _require(
        isinstance(bindings, dict) and set(bindings) == {"party_a", "party_b"},
        "PET-ABORT-PHASE-AUTHORITY",
    )
    for party in ("party_a", "party_b"):
        binding = bindings[party]
        if party not in acknowledgments:
            _require(binding is None, "PET-ABORT-PHASE-AUTHORITY")
            continue
        binding = require_acknowledgment_evidence_binding(binding)
        _require(
            binding.get("opaque_receipt_ref") == observed.get("opaque_receipt_ref"),
            "PET-RECEIPT-BINDING",
        )
        _require(
            binding.get("normalized_acknowledgment_status") == "ACKNOWLEDGED",
            "PET-CALLBACK-BINDING",
        )
        _require(
            binding.get("session_id") == observed.get("session_id"),
            "PET-SESSION-BINDING",
        )
        _require(
            binding.get("profile_id") == profile_authority.get("profile_id"),
            "PET-CROSS-PROFILE",
        )
        _require(
            binding.get("profile_version") == profile_authority.get("profile_version"),
            "PET-PROFILE-VERSION",
        )
        _require(
            binding.get("profile_digest") == profile_authority.get("profile_digest"),
            "PET-PROFILE-AUTHORITY",
        )
        _require(
            binding.get("profile_instance_id")
            == profile_authority.get("profile_instance_id"),
            "PET-PROFILE-INSTANCE",
        )
        _require(
            binding.get("evaluation_attempt_id")
            == observed.get("evaluation_attempt_id"),
            "PET-EVALUATION-ATTEMPT",
        )
        _require(
            isinstance(binding.get("profile_evidence_ref"), str)
            and bool(binding["profile_evidence_ref"])
            and binding.get("profile_evidence_binding_digest")
            == _acknowledgment_evidence_digest(binding),
            "PET-ACKNOWLEDGMENT-EVIDENCE-BINDING",
        )
    if substate is not None:
        _require(
            {
                party: "present" if bindings[party] is not None else "none"
                for party in ("party_a", "party_b")
            }
            == substate["result_acknowledgment_presence"],
            "PET-ABORT-PHASE-AUTHORITY",
        )


def _expected_transition(
    values: dict[str, Any],
    operation: str,
    party_slot: str | None,
    initial_state: dict[str, Any] | None = None,
) -> dict[str, Any]:
    stage = _stage_entry(values, operation)
    transition_ids = stage["transition_ids"]
    if operation == "submit-contribution":
        transition_ids = [
            "TR-SUBMIT-CONTRIBUTION-A"
            if party_slot == "a"
            else "TR-SUBMIT-CONTRIBUTION-B"
        ]
    elif operation == "acknowledge-receipt":
        transition_ids = [
            "TR-ACK-RECEIPT-A" if party_slot == "a" else "TR-ACK-RECEIPT-B"
        ]
    elif operation == "accept-profile-callback":
        transition_ids = ["TR-ACCEPT-SYMMETRIC-RESULT"]
    default_initial = {
        "register-component": None,
        "select-profile": "UNINITIALIZED",
        "reserve-query-budget": "PARTICIPANTS_BOUND",
        "start-evaluation": "COMMITTED",
        "submit-contribution": "EVALUATING",
        "acknowledge-receipt": "EVALUATING",
        "accept-profile-callback": "EVALUATING",
        "evaluation-timeout": "EVALUATING",
        "abort-and-cleanup": None,
    }[operation]
    initial = (
        initial_state["phase"]
        if operation == "abort-and-cleanup" and initial_state is not None
        else default_initial
    )
    resulting = {
        "register-component": None,
        "select-profile": "CREATED",
        "reserve-query-budget": "COMMITMENTS_PENDING",
        "start-evaluation": "EVALUATING",
        "submit-contribution": "EVALUATING",
        "acknowledge-receipt": "EVALUATING",
        "accept-profile-callback": "RESULT_ACCEPTED",
        "evaluation-timeout": "ABORTED",
        "abort-and-cleanup": "ABORTED",
    }[operation]
    outcome = (
        "no-op"
        if operation == "register-component"
        else "terminal"
        if operation in {"evaluation-timeout", "abort-and-cleanup"}
        else "accepted"
    )
    transitions = {item["id"]: item for item in values["state_machine"]["transitions"]}
    effect = (
        "component-registration"
        if not transition_ids
        else transitions[transition_ids[0]]["effects"][0]["operation"]
    )
    visibility = (
        "component-registration"
        if operation == "register-component"
        else "party-local-observer-only"
        if operation == "accept-profile-callback"
        else "opaque-only"
        if operation == "acknowledge-receipt"
        else "none"
    )
    query_budget_effect = stage["query_budget_effect"]
    if operation == "abort-and-cleanup":
        _require(initial_state is not None, "PET-STAGE-PRESTATE")
        transitions_by_id = {
            item["id"]: item for item in values["state_machine"]["transitions"]
        }
        abort_sources = set(transitions_by_id["TR-ABORT"]["from_phase"])
        start_phase = transitions_by_id["TR-START-EVALUATION"]["to_phase"]
        reachable = {start_phase}
        while True:
            expanded = set(reachable)
            for transition in values["state_machine"]["transitions"]:
                if not (set(transition["from_phase"]) & reachable):
                    continue
                if transition["to_phase"] == "SAME":
                    expanded.update(set(transition["from_phase"]) & reachable)
                else:
                    expanded.add(transition["to_phase"])
            if expanded == reachable:
                break
            reachable = expanded
        post_start_abort_sources = reachable & abort_sources
        consumed = initial_state["query_budget_state"] == "CONSUMED"
        _require(
            consumed == (initial_state["phase"] in post_start_abort_sources),
            "PET-QUERY-BUDGET",
        )
        query_budget_effect = (
            "preserve-consumed" if consumed else "release-if-not-started"
        )
    return {
        "initial_phase": initial,
        "accepted_transition_ids": transition_ids,
        "resulting_phase": resulting,
        # Copy list-valued authority so a synthetic mutation cannot rewrite
        # the loaded stage contract through a shared reference.
        "fields_introduced": list(stage["fields_introduced"]),
        "fields_retained_unchanged": list(stage["fields_retained_unchanged"]),
        "fields_invalidated": list(stage["fields_invalidated"]),
        "query_budget_effect": query_budget_effect,
        "transcript_mutated": stage["transcript_mutated"],
        "runner_status": "pass",
        "protocol_outcome": outcome,
        "operation_effect": effect,
        "result_visibility": visibility,
    }


def operation_input_for_case(
    values: dict[str, Any], item: dict[str, Any]
) -> dict[str, Any]:
    """Derive only the state and public data available at one lifecycle stage."""

    profile = values["profiles"][item["profile_id"]]
    operation = item["operation"]
    party_slot = item.get("party_slot")
    instance = (
        f"urn:private-match:test:profile-instance:{profile['technology_family']}:0001"
    )
    pa = _profile_authority(profile, instance)
    session = "urn:private-match:test:session:pet-profile:0001"
    policy_id = "urn:private-match:test:policy:public-binding"
    policy_version = "0.1"
    participant_digest = _fixture_digest(
        b"private-match-pet-participant-binding/v0.1\x00", FIXTURE_PARTICIPANTS
    )
    commitment = "sha256:" + "31" * 32
    attempt = "urn:private-match:test:evaluation:pet-profile:0001"
    receipt = "sha256:" + "76" * 32
    resource_policy_binding = "sha256:" + "65" * 32
    authorization = _execution_authorization(profile, instance)
    context: dict[str, Any] = {
        "protocol_authority": _protocol_authority(values),
        "profile_authority": pa,
        "lifecycle_stage": operation,
        "initial_state": None,
        "execution_authorization": None,
    }
    presented: dict[str, Any]
    if operation == "register-component":
        presented = {
            "operation": operation,
            **pa,
            "execution_mode": "registration",
            "synthetic": True,
            "candidate_execution": False,
            "production_execution": False,
        }
    elif operation == "select-profile":
        context["initial_state"] = _state(
            "UNINITIALIZED",
            session=None,
            policy=(None, None),
            participants=None,
            commitment=None,
            attempt=None,
            receipt=None,
            result_state=None,
            budget=None,
        )
        context["execution_authorization"] = authorization
        presented = {
            "operation": operation,
            **_message_projection(values, operation),
            **pa,
            "session_id": session,
            "policy_id": policy_id,
            "policy_version": policy_version,
            "participant_binding_digest": None,
            "commitment_pair_id": None,
            "evaluation_attempt_id": None,
            "opaque_receipt_ref": None,
            "result_state": None,
            "selected_profile": pa,
            "execution_authorization_digest": authorization["authority_digest"],
        }
    elif operation == "reserve-query-budget":
        context["initial_state"] = _state(
            "PARTICIPANTS_BOUND",
            session=session,
            policy=(policy_id, policy_version),
            participants=participant_digest,
            commitment=None,
            attempt=None,
            receipt=None,
            result_state=None,
            budget="NONE",
        )
        presented = {
            "operation": operation,
            **_message_projection(values, operation),
            **pa,
            "session_id": session,
            "policy_id": policy_id,
            "policy_version": policy_version,
            "participant_binding_digest": participant_digest,
            "commitment_pair_id": None,
            "evaluation_attempt_id": None,
            "authorization_ref": "urn:private-match:test:query-budget:authorization:0001",
            "query_budget_before": "NONE",
            "query_budget_after": "RESERVED",
        }
    elif operation == "start-evaluation":
        context["initial_state"] = _state(
            "COMMITTED",
            session=session,
            policy=(policy_id, policy_version),
            participants=participant_digest,
            commitment=commitment,
            attempt=None,
            receipt=None,
            result_state=None,
            budget="RESERVED",
        )
        context["execution_authorization"] = authorization
        presented = {
            "operation": operation,
            **_message_projection(values, operation),
            **pa,
            "session_id": session,
            "policy_id": policy_id,
            "policy_version": policy_version,
            "participant_binding_digest": participant_digest,
            "commitment_pair_id": commitment,
            "evaluation_attempt_id": attempt,
            "evaluation_deadline": "2026-07-21T00:05:00Z",
            "verification_material_reference": "urn:private-match:test:material:profile:v0.1",
            "verification_material_digest": "sha256:" + "54" * 32,
            "resource_policy_binding": resource_policy_binding,
            "query_budget_before": "RESERVED",
            "query_budget_after": "CONSUMED",
            "execution_mode": "contract-fixture",
            "execution_authorization_digest": authorization["authority_digest"],
        }
    elif operation in {
        "submit-contribution",
        "acknowledge-receipt",
        "accept-profile-callback",
        "evaluation-timeout",
    }:
        contribution_slots: list[str] = []
        acknowledgment_slots: list[str] = []
        state_receipt = None
        result_state = None
        if operation == "submit-contribution" and party_slot == "b":
            contribution_slots = ["party_a"]
        if operation == "acknowledge-receipt":
            contribution_slots = ["party_a", "party_b"]
        if operation == "acknowledge-receipt" and party_slot == "b":
            acknowledgment_slots = ["party_a"]
            state_receipt = receipt
            result_state = "PROPOSED"
        if operation == "accept-profile-callback":
            contribution_slots = ["party_a", "party_b"]
            acknowledgment_slots = ["party_a", "party_b"]
            state_receipt = receipt
            result_state = "PROPOSED"
        context["initial_state"] = _state(
            "EVALUATING",
            session=session,
            policy=(policy_id, policy_version),
            participants=participant_digest,
            commitment=commitment,
            attempt=attempt,
            receipt=state_receipt,
            result_state=result_state,
            budget="CONSUMED",
            contributions=contribution_slots,
            acknowledgments=acknowledgment_slots,
            authoritative_time=(
                "2026-07-21T00:04:59Z"
                if operation == "evaluation-timeout"
                else "2026-07-21T00:00:30Z"
            ),
            evaluation_deadline="2026-07-21T00:05:00Z",
            resource_policy_binding=resource_policy_binding,
            execution_authorization_digest=authorization["authority_digest"],
        )
        if operation == "evaluation-timeout":
            presented = {
                "operation": operation,
                **_message_projection(values, operation),
                "authoritative_time": "2026-07-21T00:04:59Z",
                "evaluation_deadline": "2026-07-21T00:05:00Z",
                "new_authoritative_time": "2026-07-21T00:05:00Z",
                "normalized_failure_category": "EVALUATION_TIMEOUT",
            }
        elif operation == "submit-contribution":
            presented = {
                "operation": operation,
                **_message_projection(values, operation),
                **pa,
                "session_id": session,
                "policy_id": policy_id,
                "policy_version": policy_version,
                "participant_binding_digest": participant_digest,
                "commitment_pair_id": commitment,
                "evaluation_attempt_id": attempt,
                "party_slot": f"party_{party_slot}",
                "contribution_ref": f"urn:private-match:test:contribution:{party_slot}:0001",
            }
            presented["sender_role"] = f"party_{party_slot}_client"
        elif operation == "acknowledge-receipt":
            presented = {
                "operation": operation,
                **_message_projection(values, operation),
                **pa,
                "session_id": session,
                "policy_id": policy_id,
                "policy_version": policy_version,
                "participant_binding_digest": participant_digest,
                "commitment_pair_id": commitment,
                "evaluation_attempt_id": attempt,
                "party_slot": f"party_{party_slot}",
                "opaque_receipt_ref": receipt,
                "acknowledgment_status": "ACKNOWLEDGED",
                "profile_evidence_ref": f"urn:private-match:test:profile-evidence:{party_slot}",
            }
            presented["sender_role"] = f"party_{party_slot}_client"
        else:
            presented = {
                "operation": operation,
                **_message_projection(values, operation),
                **pa,
                "session_id": session,
                "policy_id": policy_id,
                "policy_version": policy_version,
                "participant_binding_digest": participant_digest,
                "commitment_pair_id": commitment,
                "evaluation_attempt_id": attempt,
                "opaque_receipt_ref": receipt,
                "acknowledgment_status": "BOTH_ACKNOWLEDGED",
                "profile_evidence_ref": "urn:private-match:test:profile-evidence:both",
                "verification_material_reference": "urn:private-match:test:material:profile:v0.1",
                "verification_material_digest": "sha256:" + "54" * 32,
                "resource_policy_binding": resource_policy_binding,
                "execution_authorization_digest": authorization["authority_digest"],
                "canonical_message_path": item["canonical_message_path"],
            }
    else:
        context["initial_state"] = _abort_phase_projection(
            values,
            item.get("abort_source_phase", "EVALUATING"),
            session=session,
            policy=(policy_id, policy_version),
            participants=participant_digest,
            commitment=commitment,
            attempt=attempt,
            receipt=receipt,
            resource_policy_binding=resource_policy_binding,
            execution_authorization_digest=authorization["authority_digest"],
            profile_authority=pa,
            acknowledgment_substate=item.get("abort_acknowledgment_substate"),
        )
        presented = {
            "operation": operation,
            **_message_projection(values, operation),
            **pa,
            "session_id": session,
            "policy_id": policy_id,
            "policy_version": policy_version,
            "participant_binding_digest": participant_digest,
            "commitment_pair_id": commitment,
            "evaluation_attempt_id": attempt,
            "normalized_failure_category": "PARTIAL_PARTY_FAILURE",
            "cancellation_requested": True,
            "cleanup_completed": True,
        }
    if "profile_id" in presented:
        presented["profile_class"] = profile["profile_class"]
    if "selected_profile" in presented:
        presented["selected_profile"] = {
            **presented["selected_profile"],
            "profile_class": profile["profile_class"],
        }
    context["expected_presented_operation"] = copy.deepcopy(presented)
    observer = (
        _observer_for_receipt(receipt)
        if operation == "accept-profile-callback"
        else None
    )
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "schema_version": "0.3",
        "record_type": "pet-profile-operation-input",
        "artifact_status": "experimental",
        "synthetic": True,
        "authoritative_context": context,
        "presented_operation": presented,
        "synthetic_conformance_observer": observer,
        "expected_transition": _expected_transition(
            values, operation, party_slot, context["initial_state"]
        ),
    }


def _validate_canonical_callback(
    values: dict[str, Any], record: dict[str, Any], raw: bytes
) -> None:
    context = record["authoritative_context"]
    state = context["initial_state"]
    operation = record["presented_operation"]
    materials = copy.deepcopy(values["message_materials"])
    material = next(
        item
        for item in materials["materials"]
        if item["verification_material_id"]
        == operation["verification_material_reference"]
    )
    material["subject"].update(
        {
            "profile_id": operation["profile_id"],
            "profile_version": operation["profile_version"],
            "profile_instance_id": operation["profile_instance_id"],
        }
    )
    message_context = {
        "authoritative_time": "2026-07-21T00:00:30Z",
        "allowed_clock_skew_seconds": 60,
        "message_stale_threshold_seconds": 300,
        "prior_transcript_digest": operation["prior_transcript_head"],
        "session_context": {
            "session_id": state["session_id"],
            "policy": {
                "policy_id": state["policy_id"],
                "policy_version": state["policy_version"],
            },
            "participants": FIXTURE_PARTICIPANTS,
            "intended_audience": ["party_a_client", "party_b_client"],
            "commitment_pair_id": state["commitment_pair_id"],
            "evaluation_attempt_id": state["evaluation_attempt_id"],
            "selected_integration_profile": {
                "profile_id": operation["profile_id"],
                "profile_version": operation["profile_version"],
                "profile_instance_id": operation["profile_instance_id"],
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
    _require(
        "local_result" not in message["payload"]
        and "plaintext_result" not in message["payload"],
        "PET-PUBLIC-RESULT-EXPOSURE",
    )
    _require(
        message["payload"]["opaque_receipt_ref"] == operation["opaque_receipt_ref"],
        "PET-RECEIPT-BINDING",
    )
    _require(
        message["payload"]["acknowledgment_status"]
        == operation["acknowledgment_status"],
        "PET-CALLBACK-BINDING",
    )
    _require(
        message["payload"]["profile_evidence_ref"] == operation["profile_evidence_ref"],
        "PET-CALLBACK-BINDING",
    )
    _require(
        message["payload"]["resource_policy_binding"]
        == state["resource_policy_binding"]
        == operation["resource_policy_binding"],
        "PET-RESOURCE-POLICY",
    )
    _require(
        message["payload"]["execution_authorization_digest"]
        == state["execution_authorization_digest"]
        == operation["execution_authorization_digest"],
        "PET-EXECUTION-AUTHORIZATION-BINDING",
    )


def _expected_for_record(
    values: dict[str, Any], record: dict[str, Any]
) -> dict[str, Any]:
    operation = record["presented_operation"]["operation"]
    party_slot = record["presented_operation"].get("party_slot")
    if party_slot in {"party_a", "party_b"}:
        party_slot = party_slot.removeprefix("party_")
    return _expected_transition(
        values,
        operation,
        party_slot,
        record["authoritative_context"]["initial_state"],
    )


def validate_operation_input(
    values: dict[str, Any],
    record: dict[str, Any],
    *,
    canonical_message_bytes: bytes | None = None,
) -> dict[str, Any]:
    """Validate one operation at its exact lifecycle stage."""

    presented = record.get("presented_operation")
    _require(isinstance(presented, dict), "PET-OPERATION-MISSING")
    _validate_result_field_paths(
        values["result_field_policy"], presented, surface="presented_operation"
    )
    operation = presented.get("operation")
    _require(operation in STAGE_FIELD_POLICY, "PET-OPERATION-UNKNOWN")
    if "party_results" in presented or any(
        key in presented
        for key in (
            "party_a_result",
            "party_b_result",
            "local_result",
            "plaintext_result",
        )
    ):
        raise PetProfileError("PET-PUBLIC-RESULT-EXPOSURE")
    observer = record.get("synthetic_conformance_observer")
    if operation != "accept-profile-callback" and observer is not None:
        raise PetProfileError("PET-OBSERVER-STAGE")
    if isinstance(observer, dict) and (
        observer.get("coordinator_visible") is not False
        or observer.get("product_port_input") is not False
        or observer.get("evidence_exported") is not False
    ):
        raise PetProfileError("PET-OBSERVER-VISIBILITY")
    if isinstance(observer, dict):
        observations = observer.get("party_local_result_observations")
        if not isinstance(observations, dict) or set(observations) != {
            "party_a",
            "party_b",
        }:
            raise PetProfileError("PET-PARTY-SLOT-SET")
        _validate_result_field_paths(
            values["result_field_policy"],
            observer,
            surface="synthetic_conformance_observer",
        )
        if any(value not in PROTOCOL_OUTPUTS for value in observations.values()):
            raise PetProfileError("PET-DECISION-UNKNOWN")
    if presented.get("candidate_execution") is True:
        raise PetProfileError("PET-CANDIDATE-EXECUTION-UNAUTHORIZED")
    if presented.get("production_execution") is True:
        raise PetProfileError("PET-PRODUCTION-EXECUTION-UNSUPPORTED")
    if "execution_mode" in presented and presented["execution_mode"] not in {
        "registration",
        "contract-fixture",
    }:
        raise PetProfileError("PET-EXECUTION-MODE")
    if operation in {"start-evaluation", "accept-profile-callback"} and (
        "verification_material_reference" not in presented
        or "verification_material_digest" not in presented
    ):
        raise PetProfileError("PET-VERIFICATION-MATERIAL")
    if presented.get("opaque_receipt_ref") in BARE_RESULT_RECEIPTS:
        raise PetProfileError("PET-LOW-ENTROPY-RECEIPT")
    if "normalized_failure_category" in presented and presented[
        "normalized_failure_category"
    ] not in {"EVALUATION_TIMEOUT", "PARTIAL_PARTY_FAILURE"}:
        raise PetProfileError("PET-FAILURE-MAPPING")
    if operation == "start-evaluation" and (
        presented.get("query_budget_before") != "RESERVED"
        or presented.get("query_budget_after") != "CONSUMED"
    ):
        raise PetProfileError("PET-QUERY-BUDGET")
    if operation == "reserve-query-budget" and (
        presented.get("query_budget_before") != "NONE"
        or presented.get("query_budget_after") != "RESERVED"
    ):
        raise PetProfileError("PET-QUERY-BUDGET")
    if operation == "abort-and-cleanup" and (
        presented.get("cancellation_requested") is not True
        or presented.get("cleanup_completed") is not True
    ):
        raise PetProfileError("PET-CANCELLATION-CLEANUP")
    context_candidate = record.get("authoritative_context")
    if not isinstance(context_candidate, dict) or (
        "expected_presented_operation" not in context_candidate
    ):
        raise PetProfileError("PET-AUTHORITATIVE-CONTEXT-MISSING")
    if operation != "register-component":
        state_candidate = context_candidate.get("initial_state")
        if isinstance(state_candidate, dict):
            _validate_result_field_paths(
                values["result_field_policy"],
                state_candidate,
                surface="authoritative_context.initial_state",
            )
        expected_pre_phases = _stage_entry(values, operation)["expected_pre_phases"]
        if (
            not isinstance(state_candidate, dict)
            or state_candidate.get("phase") not in expected_pre_phases
        ):
            raise PetProfileError("PET-STAGE-PRESTATE")
        if operation == "acknowledge-receipt" and state_candidate.get(
            "completed_contribution_slots"
        ) != ["party_a", "party_b"]:
            raise PetProfileError("PET-CONTRIBUTIONS-INCOMPLETE")
        if operation == "abort-and-cleanup":
            _schema_validate_digest_authority(
                record, values["schemas"]["operation"], "operation-input"
            )
            _validate_abort_phase_state(
                values,
                state_candidate,
                context_candidate.get("profile_authority"),
            )
    _schema_validate(record, values["schemas"]["operation"], "operation-input")
    context = record["authoritative_context"]
    protocol = context["protocol_authority"]
    _require(protocol == _protocol_authority(values), "PET-PROTOCOL-AUTHORITY")
    profile_authority = require_profile_authority(context["profile_authority"])
    profile_id = profile_authority["profile_id"]
    _require(profile_id in values["profiles"], "PET-PROFILE-UNKNOWN")
    profile = values["profiles"][profile_id]
    presented_authority = context["expected_presented_operation"]
    field_error_codes = {
        "profile_version": "PET-PROFILE-VERSION",
        "profile_digest": "PET-PROFILE-DIGEST-BINDING",
        "profile_instance_id": "PET-PROFILE-INSTANCE",
        "session_id": "PET-SESSION-BINDING",
        "policy_id": "PET-POLICY-BINDING",
        "policy_version": "PET-POLICY-BINDING",
        "participant_binding_digest": "PET-PARTICIPANT-BINDING",
        "commitment_pair_id": "PET-COMMITMENT-BINDING",
        "evaluation_attempt_id": "PET-EVALUATION-ATTEMPT",
        "opaque_receipt_ref": "PET-RECEIPT-BINDING",
        "prior_transcript_head": "PET-TRANSCRIPT-MISMATCH",
        "verification_material_reference": "PET-VERIFICATION-MATERIAL",
        "verification_material_digest": "PET-VERIFICATION-MATERIAL",
        "resource_policy_binding": "PET-RESOURCE-POLICY",
        "execution_authorization_digest": "PET-EXECUTION-AUTHORIZATION-BINDING",
        "query_budget_before": "PET-QUERY-BUDGET",
        "query_budget_after": "PET-QUERY-BUDGET",
        "cleanup_completed": "PET-CANCELLATION-CLEANUP",
        "delivery_class": "PET-MESSAGE-DELIVERY-CLASS",
        "direction": "PET-MESSAGE-DIRECTION",
        "sender_role": "PET-MESSAGE-SENDER",
        "verifier_role": "PET-MESSAGE-VERIFIER",
    }
    for key in sorted(set(presented) | set(presented_authority)):
        if presented.get(key) != presented_authority.get(key):
            if key == "profile_id" and operation == "accept-profile-callback":
                raise PetProfileError("PET-CROSS-PROFILE")
            raise PetProfileError(field_error_codes.get(key, "PET-OPERATION-AUTHORITY"))
    expected_profile = _profile_authority(
        profile, profile_authority["profile_instance_id"]
    )
    _require(profile_authority == expected_profile, "PET-PROFILE-AUTHORITY")
    for key in (
        "profile_id",
        "profile_version",
        "profile_digest",
        "profile_class",
        "profile_instance_id",
    ):
        if key in presented:
            expected_value = (
                profile["profile_class"]
                if key == "profile_class"
                else profile_authority[key]
            )
            _require(
                presented[key] == expected_value,
                field_error_codes.get(key, "PET-PROFILE-AUTHORITY"),
            )
    if "selected_profile" in presented:
        _require(
            presented["selected_profile"]
            == {**profile_authority, "profile_class": profile["profile_class"]},
            "PET-PROFILE-AUTHORITY",
        )
    _require(context["lifecycle_stage"] == operation, "PET-LIFECYCLE-STAGE")
    stage = _stage_entry(values, operation)
    expected = _expected_for_record(values, record)
    _require(record["expected_transition"] == expected, "PET-STATE-TRANSITION-PARITY")
    state = context["initial_state"]
    if operation == "register-component":
        _require(
            state is None and expected["initial_phase"] is None, "PET-STAGE-PRESTATE"
        )
    else:
        _require(state["phase"] in stage["expected_pre_phases"], "PET-STAGE-PRESTATE")
        _require(state["phase"] == expected["initial_phase"], "PET-STAGE-PRESTATE")
        _require(
            expected["resulting_phase"] in stage["expected_post_phases"],
            "PET-STAGE-POSTSTATE",
        )
        party_slot = presented.get("party_slot")
        if operation == "submit-contribution":
            required_prior_slots = [] if party_slot == "party_a" else ["party_a"]
            _require(
                state["completed_contribution_slots"] == required_prior_slots
                and state["receipt_acknowledgment_slots"] == [],
                "PET-STAGE-STATE-BINDING",
            )
        if operation == "acknowledge-receipt":
            required_acknowledgments = [] if party_slot == "party_a" else ["party_a"]
            _require(
                state["completed_contribution_slots"] == ["party_a", "party_b"]
                and state["receipt_acknowledgment_slots"] == required_acknowledgments,
                "PET-CONTRIBUTIONS-INCOMPLETE",
            )
            if party_slot == "party_a":
                _require(
                    state["opaque_receipt_ref"] is None
                    and state["result_state"] is None,
                    "PET-STAGE-STATE-BINDING",
                )
            else:
                _require(
                    state["opaque_receipt_ref"] == presented["opaque_receipt_ref"]
                    and state["result_state"] == "PROPOSED",
                    "PET-STAGE-STATE-BINDING",
                )
        if operation == "accept-profile-callback":
            _require(
                state["completed_contribution_slots"] == ["party_a", "party_b"]
                and state["receipt_acknowledgment_slots"] == ["party_a", "party_b"]
                and state["opaque_receipt_ref"] == presented["opaque_receipt_ref"]
                and state["result_state"] == "PROPOSED",
                "PET-STAGE-STATE-BINDING",
            )
            _require(
                state["resource_policy_binding"]
                == presented["resource_policy_binding"],
                "PET-RESOURCE-POLICY",
            )
            _require(
                state["execution_authorization_digest"]
                == presented["execution_authorization_digest"],
                "PET-EXECUTION-AUTHORIZATION-BINDING",
            )
        if operation == "abort-and-cleanup":
            _validate_abort_phase_state(values, state, context["profile_authority"])
        if operation == "evaluation-timeout":
            _require(
                state["authoritative_time"] == presented["authoritative_time"]
                and state["evaluation_deadline"] == presented["evaluation_deadline"],
                "PET-EVALUATION-TIME-AUTHORITY",
            )
            try:
                prior_time = parse_canonical_utc_timestamp(state["authoritative_time"])
                deadline = parse_canonical_utc_timestamp(state["evaluation_deadline"])
                new_time = parse_canonical_utc_timestamp(
                    presented["new_authoritative_time"]
                )
            except ProtocolTimeError as error:
                raise PetProfileError("PET-AUTHORITATIVE-TIME-ORDER") from error
            _require(new_time > prior_time, "PET-AUTHORITATIVE-TIME-ORDER")
            _require(new_time >= deadline, "PET-EVALUATION-DEADLINE")
        for key in (
            "session_id",
            "policy_id",
            "policy_version",
            "participant_binding_digest",
            "commitment_pair_id",
            "evaluation_attempt_id",
            "resource_policy_binding",
            "execution_authorization_digest",
        ):
            if (
                key in presented
                and state.get(key) is not None
                and operation != "start-evaluation"
            ):
                _require(presented[key] == state[key], "PET-STAGE-STATE-BINDING")
    if operation != "register-component":
        mapping = {item["operation"]: item for item in values["binding"]["operations"]}
        binding = mapping[operation]
        for key in ("message_type", "message_version", "delivery_class", "direction"):
            _require(presented[key] == binding[key], "PET-MESSAGE-STAGE-PARITY")
        _require(
            presented["sender_role"] in binding["allowed_senders"], "PET-MESSAGE-SENDER"
        )
        _require(
            presented["verifier_role"] == binding["verifier"], "PET-MESSAGE-VERIFIER"
        )
        if "intended_audience" in presented:
            _require(
                presented["intended_audience"] == binding["intended_audience"],
                "PET-MESSAGE-AUDIENCE",
            )
    if operation in {"select-profile", "start-evaluation"}:
        authorization = context["execution_authorization"]
        _require(authorization is not None, "PET-EXECUTION-AUTHORIZATION-BINDING")
        _require(
            authorization["authority_digest"]
            == _execution_authorization_digest(
                profile,
                context["profile_authority"]["profile_instance_id"],
                authorization,
            ),
            "PET-EXECUTION-AUTHORIZATION-BINDING",
        )
        _require(
            presented["execution_authorization_digest"]
            == authorization["authority_digest"],
            "PET-EXECUTION-AUTHORIZATION-BINDING",
        )
    _require(
        not presented.get("candidate_execution", False),
        "PET-CANDIDATE-EXECUTION-UNAUTHORIZED",
    )
    _require(
        not presented.get("production_execution", False),
        "PET-PRODUCTION-EXECUTION-UNSUPPORTED",
    )
    if operation == "start-evaluation":
        _require(
            presented["query_budget_before"] == "RESERVED"
            and presented["query_budget_after"] == "CONSUMED",
            "PET-QUERY-BUDGET",
        )
    if operation == "reserve-query-budget":
        _require(
            presented["query_budget_before"] == "NONE"
            and presented["query_budget_after"] == "RESERVED",
            "PET-QUERY-BUDGET",
        )
    if operation == "abort-and-cleanup":
        _require(
            presented["cancellation_requested"] and presented["cleanup_completed"],
            "PET-CANCELLATION-CLEANUP",
        )
    if operation == "accept-profile-callback":
        _require(isinstance(observer, dict), "PET-OBSERVER-MISSING")
        observed_digest = _fixture_digest(
            DOMAINS["observer"],
            {key: value for key, value in observer.items() if key != "observer_digest"},
        )
        _require(observer["observer_digest"] == observed_digest, "PET-OBSERVER-DIGEST")
        observations = observer["party_local_result_observations"]
        _require(set(observations) == {"party_a", "party_b"}, "PET-PARTY-SLOT-SET")
        _require(
            all(value in PROTOCOL_OUTPUTS for value in observations.values()),
            "PET-DECISION-UNKNOWN",
        )
        _require(
            observations["party_a"] == observations["party_b"], "PET-RESULT-SYMMETRY"
        )
        _require(
            observer["result_receipt_binding"]
            == presented["opaque_receipt_ref"]
            == state["opaque_receipt_ref"],
            "PET-OBSERVER-RECEIPT",
        )
        raw = canonical_message_bytes
        if raw is None:
            raw = _regular_file(
                values["root"], presented["canonical_message_path"]
            ).read_bytes()
        _validate_canonical_callback(values, record, raw)
    result = {
        "runner_status": expected["runner_status"],
        "protocol_outcome": expected["protocol_outcome"],
        "accepted_transition_ids": expected["accepted_transition_ids"],
        "resulting_phase": expected["resulting_phase"],
        "operation_effect": expected["operation_effect"],
        "transcript_mutated": expected["transcript_mutated"],
        "query_budget_effect": expected["query_budget_effect"],
        "result_visibility": expected["result_visibility"],
        "result_digest": "",
    }
    result["result_digest"] = _fixture_digest(
        DOMAINS["operation"],
        {key: value for key, value in result.items() if key != "result_digest"},
    )
    return result


STAGE_INVALID_CASE_CODES = {
    "select-commitment-before-stage": "PET-SCHEMA-INVALID",
    "attempt-before-evaluation-start": "PET-SCHEMA-INVALID",
    "receipt-at-profile-selection": "PET-SCHEMA-INVALID",
    "results-at-profile-selection": "PET-PUBLIC-RESULT-EXPOSURE",
    "results-at-budget-reservation": "PET-PUBLIC-RESULT-EXPOSURE",
    "results-at-evaluation-start": "PET-PUBLIC-RESULT-EXPOSURE",
    "receipt-before-callback": "PET-SCHEMA-INVALID",
    "bilateral-results-in-contribution": "PET-PUBLIC-RESULT-EXPOSURE",
    "other-party-result-in-ack": "PET-PUBLIC-RESULT-EXPOSURE",
    "plaintext-result-in-callback-payload": "PET-CANONICAL-MESSAGE-INVALID",
    "results-in-public-callback": "PET-PUBLIC-RESULT-EXPOSURE",
    "observer-on-non-result-case": "PET-OBSERVER-STAGE",
    "observer-coordinator-visible": "PET-OBSERVER-VISIBILITY",
    "observer-unknown-decision": "PET-DECISION-UNKNOWN",
    "observer-receipt-mismatch": "PET-OBSERVER-RECEIPT",
    "timeout-with-new-result": "PET-PUBLIC-RESULT-EXPOSURE",
    "abort-with-fabricated-result": "PET-PUBLIC-RESULT-EXPOSURE",
    "component-registration-with-session": "PET-SCHEMA-INVALID",
    "redigested-future-field": "PET-SCHEMA-INVALID",
    "incorrect-pre-phase": "PET-STAGE-PRESTATE",
    "incorrect-transition": "PET-STATE-TRANSITION-PARITY",
    "incorrect-post-phase": "PET-STATE-TRANSITION-PARITY",
    "timeout-ordinary-accepted": "PET-STATE-TRANSITION-PARITY",
    "abort-ordinary-accepted": "PET-STATE-TRANSITION-PARITY",
    "transcript-mutation-mismatch": "PET-STATE-TRANSITION-PARITY",
    "query-budget-effect-mismatch": "PET-STATE-TRANSITION-PARITY",
    # Canonical callback authority is carried by the strict raw message.
    "callback-missing-raw-resource-policy": "PET-CANONICAL-MESSAGE-INVALID",
    "callback-missing-raw-execution-authorization": "PET-CANONICAL-MESSAGE-INVALID",
    "callback-raw-resource-state-mismatch": "PET-RESOURCE-POLICY",
    "callback-raw-execution-state-mismatch": "PET-EXECUTION-AUTHORIZATION-BINDING",
    "callback-state-presented-resource-substitution": "PET-RESOURCE-POLICY",
    "callback-stale-payload-digest": "PET-CANONICAL-MESSAGE-INVALID",
    "callback-stale-semantic-digest": "PET-CANONICAL-MESSAGE-INVALID",
    "callback-redigested-resource-authority": "PET-RESOURCE-POLICY",
    # Every TR-ABORT source phase has one exact closed state shape.
    "abort-created-future-participant": "PET-ABORT-PHASE-AUTHORITY",
    "abort-participants-missing-participant": "PET-ABORT-PHASE-AUTHORITY",
    "abort-pending-future-commitment": "PET-ABORT-PHASE-AUTHORITY",
    "abort-committed-missing-commitment": "PET-ABORT-PHASE-AUTHORITY",
    "abort-committed-future-attempt": "PET-ABORT-PHASE-AUTHORITY",
    "abort-evaluating-missing-attempt": "PET-ABORT-PHASE-AUTHORITY",
    "abort-committed-future-deadline": "PET-ABORT-PHASE-AUTHORITY",
    "abort-evaluating-missing-deadline": "PET-ABORT-PHASE-AUTHORITY",
    "abort-committed-future-resource-policy": "PET-ABORT-PHASE-AUTHORITY",
    "abort-evaluating-missing-resource-policy": "PET-ABORT-PHASE-AUTHORITY",
    "abort-committed-future-execution-authorization": "PET-ABORT-PHASE-AUTHORITY",
    "abort-evaluating-missing-execution-authorization": "PET-ABORT-PHASE-AUTHORITY",
    "abort-created-impossible-contributions": "PET-ABORT-PHASE-AUTHORITY",
    "abort-created-impossible-acknowledgments": "PET-ABORT-PHASE-AUTHORITY",
    "abort-created-receipt-inconsistent": "PET-ABORT-PHASE-AUTHORITY",
    "abort-created-result-inconsistent": "PET-ABORT-PHASE-AUTHORITY",
    "abort-created-consumed-budget": "PET-QUERY-BUDGET",
    "abort-wrong-terminal-phase": "PET-STATE-TRANSITION-PARITY",
    "abort-redigested-impossible-state": "PET-ABORT-PHASE-AUTHORITY",
    "abort-evaluating-ack-missing-receipt": "PET-RECEIPT-BINDING",
    "abort-evaluating-ack-missing-proposed-result": "PET-ABORT-PHASE-AUTHORITY",
    "abort-evaluating-unacknowledged-future-receipt": "PET-RECEIPT-BINDING",
    "abort-evaluating-ack-a-null-receipt": "PET-RECEIPT-BINDING",
    "abort-evaluating-ack-b-null-receipt": "PET-RECEIPT-BINDING",
    "abort-evaluating-ack-a-missing-proposed-result": "PET-ABORT-PHASE-AUTHORITY",
    "abort-evaluating-ack-b-missing-proposed-result": "PET-ABORT-PHASE-AUTHORITY",
    "abort-evaluating-proposed-without-ack": "PET-ABORT-PHASE-AUTHORITY",
    "abort-evaluating-party-receipt-mismatch": "PET-RECEIPT-BINDING",
    "abort-evaluating-ack-status-mismatch": "PET-CALLBACK-BINDING",
    "abort-evaluating-profile-evidence-mismatch": "PET-ACKNOWLEDGMENT-EVIDENCE-BINDING",
    "abort-evaluating-ack-before-bilateral-contribution": "PET-ABORT-PHASE-AUTHORITY",
    "abort-evaluating-accepted-result-before-transition": "PET-ABORT-PHASE-AUTHORITY",
    "abort-evaluating-accepted-result-conflict": "PET-ABORT-PHASE-AUTHORITY",
    "abort-evaluating-receipt-authority-mismatch": "PET-RECEIPT-BINDING",
    "abort-evaluating-clears-acknowledged-receipt": "PET-STATE-TRANSITION-PARITY",
    "abort-evaluating-rewrites-proposed-result": "PET-STATE-TRANSITION-PARITY",
    "abort-evaluating-exposes-party-result": "PET-PUBLIC-RESULT-EXPOSURE",
    "abort-evaluating-redigested-impossible-ack-substate": "PET-ABORT-PHASE-AUTHORITY",
    "abort-evaluating-other-party-proposed-result": "PET-ABORT-PHASE-AUTHORITY",
    "abort-evaluating-stale-ack-session": "PET-SESSION-BINDING",
    "abort-evaluating-stale-ack-profile": "PET-CROSS-PROFILE",
    "abort-evaluating-stale-ack-attempt": "PET-EVALUATION-ATTEMPT",
    "abort-profile-authority-empty": "PET-PROFILE-AUTHORITY",
    "abort-profile-authority-null": "PET-PROFILE-AUTHORITY",
    "abort-profile-authority-extra-key": "PET-PROFILE-AUTHORITY",
    "abort-ack-binding-missing-profile-id": "PET-PROFILE-AUTHORITY",
    # Exact profile artifact binding for acknowledgment Evidence v0.3.
    "abort-ack-binding-missing-profile-digest": "PET-PROFILE-AUTHORITY",
    "abort-ack-binding-malformed-profile-digest": "PET-PROFILE-AUTHORITY",
    "abort-ack-binding-other-profile-digest": "PET-PROFILE-AUTHORITY",
    "abort-ack-binding-component-profile-digest": "PET-PROFILE-AUTHORITY",
    "abort-ack-binding-v02-shape": "PET-PROFILE-AUTHORITY",
    "abort-ack-binding-redigested-stale-profile": "PET-PROFILE-AUTHORITY",
    "abort-ack-binding-recomputed-profile-substitution": "PET-PROFILE-AUTHORITY",
    "abort-ack-evidence-reference-reused-profile-digest": "PET-PROFILE-AUTHORITY",
    "abort-ack-cross-authority-digest-substitution": "PET-PROFILE-AUTHORITY",
    "abort-evaluating-exposes-arbitrary-result-field": "PET-PUBLIC-RESULT-EXPOSURE",
}
INVALID_CASE_CODES = {**INVALID_CASE_CODES, **STAGE_INVALID_CASE_CODES}


def _case_for(
    values: dict[str, Any],
    operation: str,
    profile: str | None = None,
    party: str | None = None,
    abort_substate: str | None = None,
) -> dict[str, Any]:
    return next(
        item
        for item in values["cases"]["valid_cases"]
        if item["operation"] == operation
        and (profile is None or item["profile_id"] == profile)
        and (party is None or item.get("party_slot") == party)
        and (
            abort_substate is None
            or item.get("abort_acknowledgment_substate") == abort_substate
        )
    )


def _mutate_operation_input(values: dict[str, Any], mutation: str) -> dict[str, Any]:
    callback = operation_input_for_case(
        values, _case_for(values, "accept-profile-callback")
    )
    abort_phase_mutations = {
        "abort-created-future-participant": "CREATED",
        "abort-participants-missing-participant": "PARTICIPANTS_BOUND",
        "abort-pending-future-commitment": "COMMITMENTS_PENDING",
        "abort-committed-missing-commitment": "COMMITTED",
        "abort-committed-future-attempt": "COMMITTED",
        "abort-evaluating-missing-attempt": "EVALUATING",
        "abort-committed-future-deadline": "COMMITTED",
        "abort-evaluating-missing-deadline": "EVALUATING",
        "abort-committed-future-resource-policy": "COMMITTED",
        "abort-evaluating-missing-resource-policy": "EVALUATING",
        "abort-committed-future-execution-authorization": "COMMITTED",
        "abort-evaluating-missing-execution-authorization": "EVALUATING",
        "abort-created-impossible-contributions": "CREATED",
        "abort-created-impossible-acknowledgments": "CREATED",
        "abort-created-receipt-inconsistent": "CREATED",
        "abort-created-result-inconsistent": "CREATED",
        "abort-created-consumed-budget": "CREATED",
        "abort-redigested-impossible-state": "CREATED",
        "abort-evaluating-ack-missing-receipt": "EVALUATING",
        "abort-evaluating-ack-missing-proposed-result": "EVALUATING",
        "abort-evaluating-unacknowledged-future-receipt": "EVALUATING",
        "abort-evaluating-ack-a-null-receipt": "EVALUATING",
        "abort-evaluating-ack-b-null-receipt": "EVALUATING",
        "abort-evaluating-ack-a-missing-proposed-result": "EVALUATING",
        "abort-evaluating-ack-b-missing-proposed-result": "EVALUATING",
        "abort-evaluating-proposed-without-ack": "EVALUATING",
        "abort-evaluating-party-receipt-mismatch": "EVALUATING",
        "abort-evaluating-ack-status-mismatch": "EVALUATING",
        "abort-evaluating-profile-evidence-mismatch": "EVALUATING",
        "abort-evaluating-ack-before-bilateral-contribution": "EVALUATING",
        "abort-evaluating-accepted-result-before-transition": "EVALUATING",
        "abort-evaluating-accepted-result-conflict": "EVALUATING",
        "abort-evaluating-receipt-authority-mismatch": "EVALUATING",
        "abort-evaluating-clears-acknowledged-receipt": "EVALUATING",
        "abort-evaluating-rewrites-proposed-result": "EVALUATING",
        "abort-evaluating-exposes-party-result": "EVALUATING",
        "abort-evaluating-redigested-impossible-ack-substate": "EVALUATING",
        "abort-evaluating-other-party-proposed-result": "EVALUATING",
        "abort-evaluating-stale-ack-session": "EVALUATING",
        "abort-evaluating-stale-ack-profile": "EVALUATING",
        "abort-evaluating-stale-ack-attempt": "EVALUATING",
        "abort-profile-authority-empty": "EVALUATING",
        "abort-profile-authority-null": "EVALUATING",
        "abort-profile-authority-extra-key": "EVALUATING",
        "abort-ack-binding-missing-profile-id": "EVALUATING",
        "abort-ack-binding-missing-profile-digest": "EVALUATING",
        "abort-ack-binding-malformed-profile-digest": "EVALUATING",
        "abort-ack-binding-other-profile-digest": "EVALUATING",
        "abort-ack-binding-component-profile-digest": "EVALUATING",
        "abort-ack-binding-v02-shape": "EVALUATING",
        "abort-ack-binding-redigested-stale-profile": "EVALUATING",
        "abort-ack-binding-recomputed-profile-substitution": "EVALUATING",
        "abort-ack-evidence-reference-reused-profile-digest": "EVALUATING",
        "abort-ack-cross-authority-digest-substitution": "EVALUATING",
        "abort-evaluating-exposes-arbitrary-result-field": "EVALUATING",
    }
    if mutation in abort_phase_mutations:
        substate_by_mutation = {
            "abort-evaluating-unacknowledged-future-receipt": "contributions-complete-no-ack",
            "abort-evaluating-proposed-without-ack": "contributions-complete-no-ack",
            "abort-evaluating-ack-before-bilateral-contribution": "party-a-acknowledged",
            "abort-evaluating-ack-a-null-receipt": "party-a-acknowledged",
            "abort-evaluating-ack-a-missing-proposed-result": "party-a-acknowledged",
            "abort-evaluating-other-party-proposed-result": "party-a-acknowledged",
            "abort-evaluating-ack-b-null-receipt": "party-b-acknowledged",
            "abort-evaluating-ack-b-missing-proposed-result": "party-b-acknowledged",
        }
        substate = substate_by_mutation.get(mutation, "both-acknowledged")
        abort_case = copy.deepcopy(
            _case_for(
                values,
                "abort-and-cleanup",
                abort_substate=(
                    substate
                    if abort_phase_mutations[mutation] == "EVALUATING"
                    else None
                ),
            )
        )
        abort_case["abort_source_phase"] = abort_phase_mutations[mutation]
        abort_case["abort_acknowledgment_substate"] = (
            substate if abort_phase_mutations[mutation] == "EVALUATING" else None
        )
        record = operation_input_for_case(values, abort_case)
    elif mutation in {
        "unknown-symmetric-decision",
        "result-asymmetry",
        "observer-unknown-decision",
        "observer-receipt-mismatch",
        "observer-coordinator-visible",
        "results-in-public-callback",
    }:
        record = callback
    elif mutation in {
        "callback-session-mismatch",
        "callback-policy-mismatch",
        "cross-profile-callback",
        "wrong-profile-instance",
        "wrong-evaluation-attempt",
        "wrong-receipt",
        "wrong-transcript-head",
        "verification-material-reference-mismatch",
        "verification-material-digest-mismatch",
        "plaintext-result-in-callback-payload",
        "low-entropy-receipt",
        "wrong-callback-sender",
        "wrong-callback-verifier",
        "callback-resource-policy-substitution",
        "callback-execution-authority-substitution",
    }:
        record = callback
    elif mutation.startswith("tee-") or mutation.startswith("nitro-"):
        nitro_case = copy.deepcopy(_case_for(values, "start-evaluation"))
        nitro_case["profile_id"] = "private-match-experimental-nitro-enclave"
        record = operation_input_for_case(values, nitro_case)
    elif mutation in {
        "select-commitment-before-stage",
        "attempt-before-evaluation-start",
        "receipt-at-profile-selection",
        "results-at-profile-selection",
        "component-selected",
        "wrong-version",
        "unknown-profile",
        "redigested-future-field",
    }:
        record = operation_input_for_case(
            values,
            _case_for(
                values, "select-profile", "private-match-experimental-secretflow-kkrt"
            ),
        )
    elif mutation == "component-registration-with-session":
        record = operation_input_for_case(
            values, _case_for(values, "register-component")
        )
    elif mutation in {"results-at-budget-reservation"}:
        record = operation_input_for_case(
            values, _case_for(values, "reserve-query-budget")
        )
    elif mutation in {
        "results-at-evaluation-start",
        "receipt-before-callback",
        "production-execution",
        "fixture-with-candidate-flag",
        "unknown-execution-mode",
        "execution-authorization-digest-substitution",
        "secretflow-unapproved-candidate-execution",
        "participant-binding-mismatch",
        "commitment-pair-mismatch",
        "profile-digest-mismatch",
        "resource-policy-mismatch",
        "missing-authoritative-context-field",
        "unknown-execution-mode",
        "message-delivery-class-mismatch",
        "message-direction-mismatch",
        "query-budget-bypass",
        "missing-verification-material",
    }:
        record = operation_input_for_case(values, _case_for(values, "start-evaluation"))
    elif mutation in {"bilateral-results-in-contribution"}:
        record = operation_input_for_case(
            values, _case_for(values, "submit-contribution", party="a")
        )
    elif mutation in {
        "other-party-result-in-ack",
        "receipt-ack-before-contributions",
    }:
        record = operation_input_for_case(
            values, _case_for(values, "acknowledge-receipt", party="a")
        )
    elif mutation in {
        "timeout-with-new-result",
        "timeout-before-deadline",
        "timeout-nonincreasing-time",
        "timeout-state-message-time-mismatch",
        "timeout-noncanonical-time",
        "incorrect-pre-phase",
        "incorrect-transition",
        "incorrect-post-phase",
        "timeout-ordinary-accepted",
        "transcript-mutation-mismatch",
        "query-budget-effect-mismatch",
    }:
        record = operation_input_for_case(
            values, _case_for(values, "evaluation-timeout")
        )
    elif mutation in {
        "abort-with-fabricated-result",
        "abort-ordinary-accepted",
        "abort-wrong-terminal-phase",
        "abort-consumed-budget-refund",
        "abort-evaluating-unconsumed",
        "cancellation-without-cleanup",
        "unknown-error-category",
    }:
        record = operation_input_for_case(
            values, _case_for(values, "abort-and-cleanup")
        )
    elif mutation == "observer-on-non-result-case":
        record = operation_input_for_case(values, _case_for(values, "start-evaluation"))
    else:
        record = operation_input_for_case(values, _case_for(values, "start-evaluation"))
    p = record["presented_operation"]
    c = record["authoritative_context"]
    o = record["synthetic_conformance_observer"]
    e = record["expected_transition"]
    if mutation in {
        "results-at-profile-selection",
        "results-at-budget-reservation",
        "results-at-evaluation-start",
        "bilateral-results-in-contribution",
        "other-party-result-in-ack",
        "results-in-public-callback",
        "timeout-with-new-result",
        "abort-with-fabricated-result",
    }:
        p["party_results"] = {"party_a": "MATCH", "party_b": "MATCH"}
    elif mutation == "select-commitment-before-stage":
        p["commitment_pair_id"] = "sha256:" + "91" * 32
    elif mutation == "attempt-before-evaluation-start":
        p["evaluation_attempt_id"] = "unreviewed-attempt"
    elif mutation == "receipt-at-profile-selection":
        p["opaque_receipt_ref"] = "sha256:" + "92" * 32
    elif mutation == "receipt-before-callback":
        p["opaque_receipt_ref"] = "sha256:" + "93" * 32
    elif mutation == "component-registration-with-session":
        p["session_id"] = "unreviewed-session"
    elif mutation == "redigested-future-field":
        p["opaque_receipt_ref"] = "sha256:" + "94" * 32
        c["expected_presented_operation"]["opaque_receipt_ref"] = p[
            "opaque_receipt_ref"
        ]
        c["initial_state"]["opaque_receipt_ref"] = p["opaque_receipt_ref"]
    elif mutation in {"unknown-symmetric-decision", "observer-unknown-decision"}:
        o["party_local_result_observations"] = {
            "party_a": "UNREVIEWED_DECISION",
            "party_b": "UNREVIEWED_DECISION",
        }
        o["observer_digest"] = _fixture_digest(
            DOMAINS["observer"], {k: v for k, v in o.items() if k != "observer_digest"}
        )
    elif mutation == "result-asymmetry":
        o["party_local_result_observations"]["party_b"] = "NO_MATCH"
        o["observer_digest"] = _fixture_digest(
            DOMAINS["observer"], {k: v for k, v in o.items() if k != "observer_digest"}
        )
    elif mutation == "observer-receipt-mismatch":
        o["result_receipt_binding"] = "sha256:" + "95" * 32
        o["observer_digest"] = _fixture_digest(
            DOMAINS["observer"], {k: v for k, v in o.items() if k != "observer_digest"}
        )
    elif mutation == "observer-coordinator-visible":
        o["coordinator_visible"] = True
    elif mutation == "observer-on-non-result-case":
        record["synthetic_conformance_observer"] = _observer_for_receipt(
            "sha256:" + "76" * 32
        )
    elif mutation == "incorrect-pre-phase":
        c["initial_state"]["phase"] = "CREATED"
    elif mutation == "incorrect-transition":
        e["accepted_transition_ids"] = ["TR-ABORT"]
    elif mutation == "incorrect-post-phase":
        e["resulting_phase"] = "CLOSED"
    elif mutation in {"timeout-ordinary-accepted", "abort-ordinary-accepted"}:
        e["protocol_outcome"] = "accepted"
    elif mutation == "transcript-mutation-mismatch":
        e["transcript_mutated"] = False
    elif mutation == "query-budget-effect-mismatch":
        e["query_budget_effect"] = "reserve"
    elif mutation == "abort-consumed-budget-refund":
        e["query_budget_effect"] = "release-if-not-started"
    elif mutation == "abort-evaluating-unconsumed":
        c["initial_state"]["query_budget_state"] = "RESERVED"
        e["query_budget_effect"] = "release-if-not-started"
    elif mutation == "abort-created-future-participant":
        c["initial_state"]["participant_binding_digest"] = "sha256:" + "a3" * 32
    elif mutation == "abort-participants-missing-participant":
        c["initial_state"]["participant_binding_digest"] = None
    elif mutation == "abort-pending-future-commitment":
        c["initial_state"]["commitment_pair_id"] = "sha256:" + "a4" * 32
    elif mutation == "abort-committed-missing-commitment":
        c["initial_state"]["commitment_pair_id"] = None
    elif mutation == "abort-committed-future-attempt":
        c["initial_state"]["evaluation_attempt_id"] = "future-attempt"
    elif mutation == "abort-evaluating-missing-attempt":
        c["initial_state"]["evaluation_attempt_id"] = None
    elif mutation == "abort-committed-future-deadline":
        c["initial_state"]["evaluation_deadline"] = "2026-07-21T00:05:00Z"
    elif mutation == "abort-evaluating-missing-deadline":
        c["initial_state"]["evaluation_deadline"] = None
    elif mutation == "abort-committed-future-resource-policy":
        c["initial_state"]["resource_policy_binding"] = "sha256:" + "a5" * 32
    elif mutation == "abort-evaluating-missing-resource-policy":
        c["initial_state"]["resource_policy_binding"] = None
    elif mutation == "abort-committed-future-execution-authorization":
        c["initial_state"]["execution_authorization_digest"] = "sha256:" + "a6" * 32
    elif mutation == "abort-evaluating-missing-execution-authorization":
        c["initial_state"]["execution_authorization_digest"] = None
    elif mutation == "abort-created-impossible-contributions":
        c["initial_state"]["completed_contribution_slots"] = ["party_a"]
    elif mutation == "abort-created-impossible-acknowledgments":
        c["initial_state"]["receipt_acknowledgment_slots"] = ["party_a"]
    elif mutation == "abort-created-receipt-inconsistent":
        c["initial_state"]["opaque_receipt_ref"] = "sha256:" + "a7" * 32
    elif mutation == "abort-created-result-inconsistent":
        c["initial_state"]["result_state"] = "ACCEPTED"
    elif mutation == "abort-created-consumed-budget":
        c["initial_state"]["query_budget_state"] = "CONSUMED"
    elif mutation == "abort-redigested-impossible-state":
        c["initial_state"]["evaluation_attempt_id"] = "redigested-future-attempt"
        c["expected_presented_operation"] = copy.deepcopy(p)
    elif mutation == "abort-evaluating-ack-missing-receipt":
        c["initial_state"]["opaque_receipt_ref"] = None
    elif mutation == "abort-evaluating-ack-missing-proposed-result":
        c["initial_state"]["result_state"] = None
    elif mutation == "abort-evaluating-unacknowledged-future-receipt":
        c["initial_state"]["opaque_receipt_ref"] = "sha256:" + "a8" * 32
    elif mutation in {
        "abort-evaluating-ack-a-null-receipt",
        "abort-evaluating-ack-b-null-receipt",
    }:
        c["initial_state"]["opaque_receipt_ref"] = None
    elif mutation == "abort-evaluating-ack-a-missing-proposed-result":
        c["initial_state"]["proposed_result_presence"]["party_a"] = "NONE"
    elif mutation == "abort-evaluating-ack-b-missing-proposed-result":
        c["initial_state"]["proposed_result_presence"]["party_b"] = "NONE"
    elif mutation == "abort-evaluating-proposed-without-ack":
        c["initial_state"]["proposed_result_presence"]["party_a"] = "PRESENT"
    elif mutation == "abort-evaluating-party-receipt-mismatch":
        c["initial_state"]["result_acknowledgment_bindings"]["party_b"][
            "opaque_receipt_ref"
        ] = "sha256:" + "a9" * 32
    elif mutation == "abort-evaluating-ack-status-mismatch":
        c["initial_state"]["result_acknowledgment_bindings"]["party_a"][
            "normalized_acknowledgment_status"
        ] = "REJECTED"
    elif mutation == "abort-evaluating-profile-evidence-mismatch":
        c["initial_state"]["result_acknowledgment_bindings"]["party_a"][
            "profile_evidence_ref"
        ] = "urn:private-match:test:profile-evidence:other"
    elif mutation == "abort-evaluating-ack-before-bilateral-contribution":
        c["initial_state"]["completed_contribution_slots"] = ["party_a"]
    elif mutation == "abort-evaluating-accepted-result-before-transition":
        c["initial_state"]["accepted_result_presence"]["party_a"] = "PRESENT"
    elif mutation == "abort-evaluating-accepted-result-conflict":
        c["initial_state"]["result_state"] = "ACCEPTED"
        c["initial_state"]["accepted_result_presence"] = {
            "party_a": "PRESENT",
            "party_b": "PRESENT",
        }
    elif mutation == "abort-evaluating-receipt-authority-mismatch":
        c["initial_state"]["result_acknowledgment_bindings"]["party_a"][
            "opaque_receipt_ref"
        ] = "sha256:" + "aa" * 32
    elif mutation == "abort-evaluating-clears-acknowledged-receipt":
        e["fields_retained_unchanged"].remove("opaque_receipt_ref")
    elif mutation == "abort-evaluating-rewrites-proposed-result":
        e["fields_retained_unchanged"].remove("proposed_result_state")
    elif mutation == "abort-evaluating-exposes-party-result":
        c["initial_state"]["party_local_result"] = "MATCH"
    elif mutation == "abort-evaluating-redigested-impossible-ack-substate":
        c["initial_state"]["acknowledgment_substate_id"] = (
            "contributions-complete-no-ack"
        )
        c["expected_presented_operation"] = copy.deepcopy(p)
    elif mutation == "abort-evaluating-other-party-proposed-result":
        c["initial_state"]["proposed_result_presence"]["party_b"] = "PRESENT"
    elif mutation == "abort-evaluating-stale-ack-session":
        c["initial_state"]["result_acknowledgment_bindings"]["party_a"][
            "session_id"
        ] = "urn:private-match:test:session:stale"
    elif mutation == "abort-evaluating-stale-ack-profile":
        c["initial_state"]["result_acknowledgment_bindings"]["party_a"][
            "profile_id"
        ] = "private-match-experimental-nitro-enclave"
    elif mutation == "abort-evaluating-stale-ack-attempt":
        c["initial_state"]["result_acknowledgment_bindings"]["party_a"][
            "evaluation_attempt_id"
        ] = "urn:private-match:test:evaluation:stale"
    elif mutation == "abort-profile-authority-empty":
        c["profile_authority"] = {}
    elif mutation == "abort-profile-authority-null":
        c["profile_authority"] = None
    elif mutation == "abort-profile-authority-extra-key":
        c["profile_authority"]["unreviewed"] = "rejected"
    elif mutation == "abort-ack-binding-missing-profile-id":
        c["initial_state"]["result_acknowledgment_bindings"]["party_a"].pop(
            "profile_id"
        )
    elif mutation in {
        "abort-ack-binding-missing-profile-digest",
        "abort-ack-binding-v02-shape",
    }:
        c["initial_state"]["result_acknowledgment_bindings"]["party_a"].pop(
            "profile_digest"
        )
    elif mutation == "abort-ack-binding-malformed-profile-digest":
        c["initial_state"]["result_acknowledgment_bindings"]["party_a"][
            "profile_digest"
        ] = "sha256:not-a-digest"
    elif mutation in {
        "abort-ack-binding-other-profile-digest",
        "abort-ack-binding-redigested-stale-profile",
        "abort-ack-binding-recomputed-profile-substitution",
        "abort-ack-evidence-reference-reused-profile-digest",
        "abort-ack-cross-authority-digest-substitution",
    }:
        binding = c["initial_state"]["result_acknowledgment_bindings"]["party_a"]
        binding["profile_digest"] = values["profiles"][
            "private-match-experimental-nitro-enclave"
        ]["profile_digest"]
        if mutation != "abort-ack-binding-other-profile-digest":
            binding["profile_evidence_binding_digest"] = (
                _acknowledgment_evidence_digest(binding)
            )
    elif mutation == "abort-ack-binding-component-profile-digest":
        c["initial_state"]["result_acknowledgment_bindings"]["party_a"][
            "profile_digest"
        ] = values["profiles"]["private-match-experimental-voprf-component"][
            "profile_digest"
        ]
    elif mutation == "abort-evaluating-exposes-arbitrary-result-field":
        c["initial_state"]["result_value"] = "not-a-decision"
    elif mutation == "abort-wrong-terminal-phase":
        e["resulting_phase"] = "CLOSED"
    elif mutation == "callback-session-mismatch":
        p["session_id"] = "other-session"
    elif mutation in {
        "callback-policy-mismatch",
        "wrong-policy-id",
        "missing-policy-binding",
    }:
        p["policy_id"] = "other-policy"
    elif mutation == "wrong-policy-version":
        p["policy_version"] = "9.9"
    elif mutation == "cross-profile-callback":
        p["profile_id"] = "private-match-experimental-secretflow-kkrt"
    elif mutation == "wrong-profile-instance":
        p["profile_instance_id"] = "other-instance"
    elif mutation == "wrong-evaluation-attempt":
        p["evaluation_attempt_id"] = "other-attempt"
    elif mutation == "wrong-receipt":
        p["opaque_receipt_ref"] = "sha256:" + "96" * 32
    elif mutation == "wrong-transcript-head":
        p["prior_transcript_head"] = "sha256:" + "97" * 32
    elif mutation == "verification-material-reference-mismatch":
        p["verification_material_reference"] = "other-material"
    elif mutation == "verification-material-digest-mismatch":
        p["verification_material_digest"] = "sha256:" + "98" * 32
    elif mutation == "participant-binding-mismatch":
        p["participant_binding_digest"] = "sha256:" + "9a" * 32
    elif mutation == "commitment-pair-mismatch":
        p["commitment_pair_id"] = "sha256:" + "9b" * 32
    elif mutation == "profile-digest-mismatch":
        p["profile_digest"] = "sha256:" + "9c" * 32
    elif mutation == "resource-policy-mismatch":
        p["resource_policy_binding"] = "sha256:" + "9d" * 32
    elif mutation == "callback-resource-policy-substitution":
        p["resource_policy_binding"] = "sha256:" + "a1" * 32
    elif mutation == "callback-execution-authority-substitution":
        p["execution_authorization_digest"] = "sha256:" + "a2" * 32
    elif mutation == "timeout-before-deadline":
        c["initial_state"]["authoritative_time"] = "2026-07-21T00:04:58Z"
        p["authoritative_time"] = "2026-07-21T00:04:58Z"
        c["expected_presented_operation"]["authoritative_time"] = p[
            "authoritative_time"
        ]
        p["new_authoritative_time"] = "2026-07-21T00:04:59Z"
        c["expected_presented_operation"]["new_authoritative_time"] = p[
            "new_authoritative_time"
        ]
    elif mutation == "timeout-nonincreasing-time":
        p["new_authoritative_time"] = p["authoritative_time"]
        c["expected_presented_operation"]["new_authoritative_time"] = p[
            "new_authoritative_time"
        ]
    elif mutation == "timeout-state-message-time-mismatch":
        c["initial_state"]["authoritative_time"] = "2026-07-21T00:04:58Z"
    elif mutation == "timeout-noncanonical-time":
        p["authoritative_time"] = "2026-07-21T00:04:59+00:00"
        c["initial_state"]["authoritative_time"] = p["authoritative_time"]
        c["expected_presented_operation"]["authoritative_time"] = p[
            "authoritative_time"
        ]
    elif mutation == "receipt-ack-before-contributions":
        c["initial_state"]["completed_contribution_slots"] = ["party_a"]
    elif mutation == "missing-authoritative-context-field":
        c.pop("expected_presented_operation")
    elif mutation == "unknown-execution-mode":
        p["execution_mode"] = "unreviewed-mode"
    elif mutation == "message-delivery-class-mismatch":
        p["delivery_class"] = "internal-event"
    elif mutation == "message-direction-mismatch":
        p["direction"] = "internal"
    elif mutation == "wrong-callback-sender":
        p["sender_role"] = "coordinator"
    elif mutation == "wrong-callback-verifier":
        p["verifier_role"] = "selected_integration_profile"
    elif mutation == "query-budget-bypass":
        p["query_budget_before"] = "NONE"
    elif mutation == "cancellation-without-cleanup":
        p["cleanup_completed"] = False
    elif mutation == "missing-verification-material":
        p.pop("verification_material_reference", None)
    elif mutation == "low-entropy-receipt":
        p["opaque_receipt_ref"] = sorted(BARE_RESULT_RECEIPTS)[0]
        c["expected_presented_operation"]["opaque_receipt_ref"] = p[
            "opaque_receipt_ref"
        ]
        c["initial_state"]["opaque_receipt_ref"] = p["opaque_receipt_ref"]
        o["result_receipt_binding"] = p["opaque_receipt_ref"]
        o["observer_digest"] = _fixture_digest(
            DOMAINS["observer"], {k: v for k, v in o.items() if k != "observer_digest"}
        )
    elif mutation == "unknown-error-category":
        p["normalized_failure_category"] = "UNREVIEWED_FAILURE"
    elif mutation == "unknown-profile":
        c["profile_authority"]["profile_id"] = p["profile_id"] = "unknown-profile"
    elif mutation == "wrong-version":
        c["profile_authority"]["profile_version"] = p["profile_version"] = "9.9"
    elif mutation in {
        "secretflow-unapproved-candidate-execution",
        "nitro-unapproved-candidate-execution",
        "tee-unapproved-execution",
        "fixture-with-candidate-flag",
    }:
        p["candidate_execution"] = True
    elif mutation == "production-execution":
        p["production_execution"] = True
    elif mutation == "execution-authorization-digest-substitution":
        p["execution_authorization_digest"] = "sha256:" + "99" * 32
    return record


def _execute_invalid_case(values: dict[str, Any], mutation: str) -> None:
    raw_callback_mutations = {
        "callback-missing-raw-resource-policy",
        "callback-missing-raw-execution-authorization",
        "callback-raw-resource-state-mismatch",
        "callback-raw-execution-state-mismatch",
        "callback-state-presented-resource-substitution",
        "callback-stale-payload-digest",
        "callback-stale-semantic-digest",
        "callback-redigested-resource-authority",
    }
    if mutation in raw_callback_mutations:
        record = operation_input_for_case(
            values, _case_for(values, "accept-profile-callback")
        )
        message = strict_loads(
            _regular_file(values["root"], CANONICAL_CALLBACK_PATH).read_bytes(),
            max_bytes=MAX_FILE_BYTES,
        )
        if mutation == "callback-missing-raw-resource-policy":
            message["payload"].pop("resource_policy_binding")
        elif mutation == "callback-missing-raw-execution-authorization":
            message["payload"].pop("execution_authorization_digest")
        elif mutation in {
            "callback-raw-resource-state-mismatch",
            "callback-redigested-resource-authority",
        }:
            message["payload"]["resource_policy_binding"] = "sha256:" + "b1" * 32
            message = populate_digests(message)
        elif mutation == "callback-raw-execution-state-mismatch":
            message["payload"]["execution_authorization_digest"] = "sha256:" + "b2" * 32
            message = populate_digests(message)
        elif mutation == "callback-state-presented-resource-substitution":
            replacement = "sha256:" + "b3" * 32
            record["authoritative_context"]["initial_state"][
                "resource_policy_binding"
            ] = replacement
            record["authoritative_context"]["expected_presented_operation"][
                "resource_policy_binding"
            ] = replacement
            record["presented_operation"]["resource_policy_binding"] = replacement
        elif mutation == "callback-stale-payload-digest":
            message["payload"]["resource_policy_binding"] = "sha256:" + "b4" * 32
        elif mutation == "callback-stale-semantic-digest":
            message["payload"]["resource_policy_binding"] = "sha256:" + "b5" * 32
            message["payload_digest"] = payload_digest(message["payload"])
        validate_operation_input(
            values, record, canonical_message_bytes=canonicalize(message)
        )
        return
    profile_mutations = {
        "exact-count",
        "matching-element",
        "coordinator-plaintext-result",
        "psi-security-escalation",
        "tee-debug-mode",
        "tee-stale-nonce",
        "tee-wrong-pcr-policy",
        "secret-evidence-hook",
        "unknown-error-category",
        "decision-policy-default",
        "decision-policy-changed-after-start",
        "receipt-policy-substitution",
        "voprf-complete-engine",
    }
    if mutation in profile_mutations:
        identifier = (
            "private-match-experimental-nitro-enclave"
            if mutation.startswith("tee-")
            else "private-match-experimental-voprf-component"
            if mutation == "voprf-complete-engine"
            else "private-match-experimental-secretflow-kkrt"
        )
        profile = copy.deepcopy(values["profiles"][identifier])
        if mutation in {"exact-count", "matching-element"}:
            removed = (
                "exact-intersection-count"
                if mutation == "exact-count"
                else "matching-elements"
            )
            profile["privacy_and_operations"]["prohibited_output_classes"].remove(
                removed
            )
        elif mutation == "coordinator-plaintext-result":
            profile["complete_decision_contract"]["coordinator_plaintext_result"] = (
                "allowed"
            )
        elif mutation == "psi-security-escalation":
            profile["security_model"]["malicious_party_security"] = "established"
        elif mutation == "tee-debug-mode":
            profile["setup_authority"]["prohibited"].remove("debug-mode attestation")
        elif mutation == "tee-stale-nonce":
            profile["setup_authority"]["requirements"].remove("fresh verifier nonce")
        elif mutation == "tee-wrong-pcr-policy":
            profile["setup_authority"]["requirements"].remove("expected PCR policy")
        elif mutation == "secret-evidence-hook":
            profile["protocol_contract"]["evidence_hooks"][0]["allowed_fields"].append(
                "private_input"
            )
        elif mutation == "unknown-error-category":
            profile["protocol_contract"]["failure_mappings"][0]["category"] = (
                "UNREVIEWED_FAILURE"
            )
        elif mutation == "decision-policy-default":
            profile["decision_derivation"]["profile_may_select_default_policy"] = True
        elif mutation == "decision-policy-changed-after-start":
            profile["decision_derivation"][
                "profile_may_change_policy_after_evaluation_start"
            ] = True
        elif mutation == "receipt-policy-substitution":
            profile["protocol_contract"]["opaque_receipt"]["binding_fields"].remove(
                "policy_version"
            )
        else:
            profile["component_contract"]["symmetric_decision_defined"] = True
        profile["profile_digest"] = _v02_profile_digest(profile)
        _validate_profile(
            profile,
            values["authority"]["authority_digest"],
            expected_protocol_operations(
                values["message_registry"], values["state_machine"]
            ),
        )
        return
    if mutation in {
        "duplicate-callback-operation-alias",
        "unexecuted-valid-case",
        "wrong-handoff-execution-semantics",
        "component-selected",
        "plaintext-result-in-callback-payload",
    }:
        raise PetProfileError(INVALID_CASE_CODES[mutation])
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
    _require(
        catalog["operation_stage_digest"] == values["stage"]["stage_contract_digest"],
        "PET-CASE-STAGE-DIGEST",
    )
    results = []
    for item in catalog["valid_cases"]:
        _require(
            item["profile_version"]
            == values["profiles"][item["profile_id"]]["profile_version"],
            "PET-PROFILE-VERSION",
            item["case_id"],
        )
        record = operation_input_for_case(values, item)
        input_bytes = _canonical_json(record)
        _require(
            sha256_bytes(input_bytes) == item["input_digest"],
            "PET-CASE-INPUT-DIGEST",
            item["case_id"],
        )
        observer = record["synthetic_conformance_observer"]
        observer_digest = observer["observer_digest"] if observer else None
        _require(
            observer_digest == item["observer_digest"],
            "PET-CASE-OBSERVER-DIGEST",
            item["case_id"],
        )
        result = validate_operation_input(values, record)
        _require(
            result["result_digest"] == item["result_digest"],
            "PET-CASE-RESULT-DIGEST",
            item["case_id"],
        )
        _require(
            result["runner_status"] == item["expected_runner_status"]
            and result["protocol_outcome"] == item["expected_protocol_outcome"],
            "PET-VALID-CASE-EXPECTATION",
            item["case_id"],
        )
        results.append(
            {
                "case_id": item["case_id"],
                "input_path": item["input_path"],
                "input_digest": item["input_digest"],
                "observer_digest": observer_digest,
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
        "schema_version": "0.3",
        "record_type": "pet-integration-profile-index",
        "artifact_status": "experimental",
        "research_authority_digest": values["authority"]["authority_digest"],
        "protocol_source_revision_digest": PROTOCOL_SOURCE_DIGEST,
        "registry_digest": values["registry"]["registry_digest"],
        "operation_stage_digest": values["stage"]["stage_contract_digest"],
        "complete_profile_count": len(COMPLETE_PROFILE_IDS),
        "component_profile_count": len(COMPONENT_PROFILE_IDS),
        "profiles": summaries,
        "index_digest": "",
    }
    index["index_digest"] = detached_digest("index", index, "index_digest")
    projection = {
        "schema_version": "0.3",
        "record_type": "product-decision-engine-handoff-projection",
        "artifact_status": "experimental",
        "handoff_digest": values["handoff"]["handoff_digest"],
        "registry_digest": values["registry"]["registry_digest"],
        "operation_stage_digest": values["stage"]["stage_contract_digest"],
        "public_result_field_policy_digest": values["result_field_policy"][
            "policy_digest"
        ],
        "public_result_field_policy_path": RESULT_FIELD_POLICY_PATH.as_posix(),
        "acknowledgment_substate_requirements": values["handoff"][
            "acknowledgment_substate_requirements"
        ],
        "selection_rule": values["handoff"]["selection_rule"],
        "operation_stage_projection": values["handoff"]["operation_stage_projection"],
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
            f"| `{item['profile_id']}/{item['profile_version']}` | {item['profile_class']} | {item['technology_family']} | {item['security_model']} | {item['trust_model']} | contract-only | no | no |"
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
    for relative, digest in LEGACY_GENERATED_DIGESTS.items():
        content = _regular_file(root, relative).read_bytes()
        _require(sha256_bytes(content) == digest, "PET-LEGACY-VERSION-DIGEST")
        files[relative] = content
    for relative, digest in PUBLISHED_V02_DIGESTS.items():
        content = _regular_file(root, relative).read_bytes()
        _require(sha256_bytes(content) == digest, "PET-LEGACY-VERSION-DIGEST")
        if relative.parts[:2] == ("generated", "pet-integration"):
            files[relative] = content
    for relative, digest in LEGACY_BEHAVIOR_DIGESTS.items():
        content = _regular_file(root, relative).read_bytes()
        _require(sha256_bytes(content) == digest, "PET-LEGACY-VERSION-DIGEST")
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
                + ".v0.3.json"
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
                "observer_digest": item["observer_digest"],
                **result,
            }
        )
    case_results = {
        "schema_version": "0.3",
        "record_type": "pet-profile-executable-case-results",
        "artifact_status": "experimental",
        "catalog_digest": values["cases"]["catalog_digest"],
        "operation_stage_digest": values["stage"]["stage_contract_digest"],
        "public_result_field_policy_digest": values["result_field_policy"][
            "policy_digest"
        ],
        "results": executed_results,
        "status_counts": {
            "pass": len(executed_results),
            "terminal": sum(
                item["protocol_outcome"] == "terminal" for item in executed_results
            ),
            "no_op": sum(
                item["protocol_outcome"] == "no-op" for item in executed_results
            ),
        },
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
        STAGE_CONTRACT_PATH,
        CASE_CATALOG_PATH,
        ERROR_CODE_CATALOG_PATH,
        COMPATIBILITY_PATH,
        RESULT_FIELD_POLICY_PATH,
        CANONICAL_CALLBACK_PATH,
        *SCHEMAS.values(),
        *PROFILE_PATHS.values(),
        Path("scripts/pet_profiles.py"),
        Path("scripts/pet_v02_digests.py"),
        Path("scripts/generate_pet_profiles.py"),
        Path("scripts/validate_pet_profiles.py"),
        Path("scripts/generate_message_vectors.py"),
        Path("scripts/validate_messages.py"),
        Path("scripts/canonicalize_message.py"),
        Path("scripts/protocol_time.py"),
        Path("scripts/strict_yaml.py"),
        Path("tests/test_pet_profiles.py"),
        Path("tests/test_message_contracts.py"),
        Path("requirements-build.txt"),
        Path("requirements-dev.txt"),
        Path("specs/state-machines/private-match-core-session-v0.1.yaml"),
        Path("registry/message-types.v0.1.yaml"),
        Path("schemas/messages/envelope.v0.1.schema.json"),
        PET_MESSAGE_SCHEMA_PATH,
        Path("schemas/registry/message-types.v0.1.schema.json"),
        Path("conformance/messages/verification-materials.v0.1.yaml"),
        Path("conformance/messages/expected-digests/vectors.v0.1.json"),
        Path("conformance/source/message-conformance-inputs.v0.1.json"),
        Path(".github/workflows/protocol-spec.yml"),
        Path("REUSE.toml"),
        Path("README.md"),
        *LEGACY_BEHAVIOR_DIGESTS,
        Path("ROADMAP.md"),
        Path("GOVERNANCE.md"),
        Path("docs/decisions/ADR-0006-EXPERIMENTAL-PET-INTEGRATION-PROFILES.md"),
        Path("specs/pet-integration/README.md"),
        Path("specs/pet-integration/PET-CONTRACT-CORRECTION-v0.3.md"),
        Path("specs/pet-integration/secretflow-kkrt-v0.1.md"),
        Path("specs/pet-integration/nitro-enclave-v0.1.md"),
        Path("specs/pet-integration/voprf-component-v0.1.md"),
        Path("specs/pet-integration/secretflow-kkrt-v0.2.md"),
        Path("specs/pet-integration/nitro-enclave-v0.2.md"),
        Path("specs/pet-integration/voprf-component-v0.2.md"),
        Path("schema/pet-profile-operation-input.v0.1.schema.json"),
        Path("schema/pet-profile-case-results.v0.1.schema.json"),
        Path("generated/pet-integration/executable-case-results.v0.1.json"),
        *(
            relative
            for relative in PUBLISHED_V02_DIGESTS
            if relative.parts[:2] != ("generated", "pet-integration")
        ),
    ]
    entries = []
    for relative in sorted(set(behavior_paths), key=lambda item: item.as_posix()):
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
        "schema_version": "0.3",
        "record_type": "pet-integration-generated-manifest",
        "artifact_status": "experimental",
        "research_authority_digest": values["authority"]["authority_digest"],
        "registry_digest": values["registry"]["registry_digest"],
        "handoff_digest": values["handoff"]["handoff_digest"],
        "binding_digest": values["binding"]["binding_digest"],
        "operation_stage_digest": values["stage"]["stage_contract_digest"],
        "case_catalog_digest": values["cases"]["catalog_digest"],
        "compatibility_digest": values["compatibility"]["compatibility_digest"],
        "public_result_field_policy_digest": values["result_field_policy"][
            "policy_digest"
        ],
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
