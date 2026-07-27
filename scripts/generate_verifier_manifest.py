#!/usr/bin/env python3
"""Generate the closed reference-verifier implementation dependency manifest."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

from canonicalize_message import canonicalize
from conformance_common import (
    REFERENCE_IMPLEMENTATION_FILES,
    REFERENCE_IMPLEMENTATION_MANIFEST,
    REFERENCE_PROTOCOL_ARTIFACTS,
    implementation_manifest_digest,
    sha256_bytes,
    validate_reference_implementation_manifest,
)

PROTOCOL_PINS = {
    "state_machine_digest": "sha256:32e514a61a83aeb1593623eb1144f323d1115dc8c812b5fd72af93a3ae06ba16",
    "message_registry_digest": "sha256:df3eea26ad07b477912b124c96c9325676e9d1a89744e672f26c00538377a7ea",
    "message_conformance_tree_digest": "sha256:4902a58e94110d4c1d3b5780daf5e9e059a7b39972911e0df23ee9cd993b5afa",
}


def build_manifest(root: Path) -> dict[str, Any]:
    pin_by_id = {
        "state-machine": PROTOCOL_PINS["state_machine_digest"],
        "message-registry": PROTOCOL_PINS["message_registry_digest"],
        "message-conformance-input-tree": PROTOCOL_PINS[
            "message_conformance_tree_digest"
        ],
    }
    manifest: dict[str, Any] = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "schema_version": "0.1",
        "artifact_status": "draft",
        "verifier": {"id": "private-match-reference-verifier", "version": "0.1"},
        "canonicalization_runtime": {
            "standard": "RFC8785",
            "package": "rfc8785",
            "version": "0.1.4",
        },
        "tested_runtime_target": {
            "implementation": "CPython",
            "python_version": "3.12.11",
            "platform": "linux-x86_64",
            "execution_provenance_claimed": False,
        },
        "files": [
            {
                "path": relative,
                "digest": sha256_bytes((root / relative).read_bytes()),
                "role": role,
            }
            for relative, role in sorted(REFERENCE_IMPLEMENTATION_FILES.items())
        ],
        "protocol_artifacts": [
            {
                "id": identifier,
                "path": REFERENCE_PROTOCOL_ARTIFACTS[identifier],
                "digest": pin_by_id[identifier],
            }
            for identifier in sorted(REFERENCE_PROTOCOL_ARTIFACTS)
        ],
        "implementation_digest": "sha256:" + "0" * 64,
        "limitations": [
            "The implementation digest binds reviewed source, runtime Schemas, policy, profile, and dependency locks; it does not establish correctness, cryptographic security, or execution provenance."
        ],
        "license": "Apache-2.0",
    }
    manifest["implementation_digest"] = implementation_manifest_digest(manifest)
    validate_reference_implementation_manifest(
        root, manifest, protocol_pins=PROTOCOL_PINS
    )
    return manifest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    root = args.root.resolve()
    try:
        raw = canonicalize(build_manifest(root))
        target = root / REFERENCE_IMPLEMENTATION_MANIFEST
        if args.check:
            if (
                not target.is_file()
                or target.is_symlink()
                or target.read_bytes() != raw
            ):
                raise ValueError
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)
    except (OSError, ValueError, KeyError, TypeError):
        print("verifier-manifest: error [bounded]", file=sys.stderr)
        return 1
    print("verifier-manifest: valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
