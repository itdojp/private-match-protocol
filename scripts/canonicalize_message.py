#!/usr/bin/env python3
"""RFC 8785 canonicalization and domain-separated digest helpers.

The module deliberately delegates JSON Canonicalization Scheme serialization to
the reviewed ``rfc8785`` package.  It adds strict JSON parsing because the
package accepts Python values rather than JSON source text: duplicate names,
non-finite values, invalid UTF-8, and negative zero are rejected before a value
can be authenticated.

This module computes authentication inputs and digests.  It does not implement
or select a signature, MAC, attestation, key, or verification mechanism.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import sys
from pathlib import Path
from typing import Any, NoReturn

import rfc8785


PAYLOAD_DOMAIN = "private-match-payload/v0.1"
MESSAGE_DOMAIN = "private-match-message/v0.1"
TRANSCRIPT_DOMAIN = "private-match-transcript/v0.1"
TRANSCRIPT_GENESIS_DOMAIN = "private-match-transcript-genesis/v0.1"
TIMER_EVENT_DOMAIN = "private-match-timer-event/v0.1"
COMMITMENT_PAIR_DOMAIN = "private-match-commitment-pair/v0.1"

SHA256_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
MAX_JSON_BYTES = 1_048_576
MAX_SAFE_INTEGER = 2**53 - 1


class CanonicalMessageError(ValueError):
    """A bounded, expected canonical-message validation failure."""


class DuplicateJSONKeyError(CanonicalMessageError):
    """A JSON object contained a duplicate member name."""


def _reject_constant(token: str) -> NoReturn:
    raise CanonicalMessageError(f"non-finite JSON number is forbidden: {token}")


def _parse_int(token: str) -> int:
    value = int(token)
    if value == 0 and token.lstrip().startswith("-"):
        raise CanonicalMessageError("negative zero is forbidden")
    if not -MAX_SAFE_INTEGER <= value <= MAX_SAFE_INTEGER:
        raise CanonicalMessageError("JSON integer exceeds the I-JSON safe domain")
    return value


def _parse_float(token: str) -> float:
    value = float(token)
    if not math.isfinite(value):
        raise CanonicalMessageError("non-finite JSON number is forbidden")
    if value == 0.0 and token.lstrip().startswith("-"):
        # Verified RFC 8785 erratum 7920 recommends rejecting source-level -0
        # so a distinct input cannot collapse to the canonical representation 0.
        raise CanonicalMessageError("negative zero is forbidden")
    return value


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateJSONKeyError(f"duplicate JSON member name: {key}")
        result[key] = value
    return result


def strict_loads(raw: bytes | str, *, max_bytes: int = MAX_JSON_BYTES) -> Any:
    """Parse one UTF-8 JSON value with I-JSON/JCS source restrictions."""

    if isinstance(raw, bytes):
        if len(raw) > max_bytes:
            raise CanonicalMessageError("JSON input exceeds the configured size limit")
        try:
            text = raw.decode("utf-8", errors="strict")
        except UnicodeDecodeError as error:
            raise CanonicalMessageError("JSON input is not valid UTF-8") from error
    else:
        text = raw
        try:
            encoded = text.encode("utf-8", errors="strict")
        except UnicodeEncodeError as error:
            raise CanonicalMessageError(
                "JSON input contains a lone Unicode surrogate"
            ) from error
        if len(encoded) > max_bytes:
            raise CanonicalMessageError("JSON input exceeds the configured size limit")

    try:
        value = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
            parse_int=_parse_int,
            parse_float=_parse_float,
        )
    except CanonicalMessageError:
        raise
    except (UnicodeError, json.JSONDecodeError, ValueError) as error:
        raise CanonicalMessageError(f"invalid JSON: {bounded_error(error)}") from error
    _validate_value_domain(value)
    return value


def _validate_value_domain(value: Any, path: str = "$") -> None:
    if value is None or isinstance(value, (bool, str)):
        if isinstance(value, str):
            try:
                value.encode("utf-8", errors="strict")
            except UnicodeEncodeError as error:
                raise CanonicalMessageError(
                    f"{path}: string contains a lone Unicode surrogate"
                ) from error
        return
    if isinstance(value, int):
        if not -MAX_SAFE_INTEGER <= value <= MAX_SAFE_INTEGER:
            raise CanonicalMessageError(
                f"{path}: integer exceeds the I-JSON safe domain"
            )
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise CanonicalMessageError(f"{path}: non-finite number is forbidden")
        if value == 0.0 and math.copysign(1.0, value) < 0:
            raise CanonicalMessageError(f"{path}: negative zero is forbidden")
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _validate_value_domain(item, f"{path}[{index}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise CanonicalMessageError(
                    f"{path}: object member names must be strings"
                )
            _validate_value_domain(key, f"{path}.<key>")
            _validate_value_domain(item, f"{path}.{key}")
        return
    raise CanonicalMessageError(
        f"{path}: unsupported JSON value type {type(value).__name__}"
    )


def canonicalize(value: Any) -> bytes:
    """Return RFC 8785 bytes after enforcing the local strict input domain."""

    _validate_value_domain(value)
    try:
        return rfc8785.dumps(value)
    except rfc8785.CanonicalizationError as error:
        raise CanonicalMessageError(bounded_error(error)) from error


def domain(label: str) -> bytes:
    """Encode a domain label with an unambiguous two-byte length prefix."""

    encoded = label.encode("ascii", errors="strict")
    if len(encoded) > 65_535:
        raise CanonicalMessageError("digest domain label is too long")
    return len(encoded).to_bytes(2, "big") + encoded


def digest_bytes(label: str, *parts: bytes) -> bytes:
    hasher = hashlib.sha256()
    hasher.update(domain(label))
    for part in parts:
        hasher.update(part)
    return hasher.digest()


def format_digest(raw: bytes) -> str:
    if len(raw) != 32:
        raise CanonicalMessageError("SHA-256 digest must contain 32 bytes")
    return f"sha256:{raw.hex()}"


def parse_digest(value: str) -> bytes:
    if not SHA256_PATTERN.fullmatch(value):
        raise CanonicalMessageError("digest must use sha256:<64 lowercase hex> format")
    return bytes.fromhex(value.removeprefix("sha256:"))


def payload_digest(payload: Any) -> str:
    return format_digest(digest_bytes(PAYLOAD_DOMAIN, canonicalize(payload)))


def commitment_pair_digest(
    *,
    protocol_profile: str,
    policy_binding: dict[str, Any],
    session_id: str,
    participant_binding: dict[str, Any],
    selected_integration_profile_binding: dict[str, Any],
    commitment_a: str,
    commitment_b: str,
) -> str:
    """Derive the v0.1 commitment-pair identity in canonical A/B slot order.

    The result binds two opaque commitments to reviewed session context.  It is
    not evidence that either commitment is truthful and does not establish PET
    security or input completeness.
    """

    value = {
        "protocol_profile": protocol_profile,
        "policy_binding": policy_binding,
        "session_id": session_id,
        "participant_binding": {
            "party_a": participant_binding.get("party_a"),
            "party_b": participant_binding.get("party_b"),
        },
        "selected_integration_profile_binding": selected_integration_profile_binding,
        "commitment_a": commitment_a,
        "commitment_b": commitment_b,
    }
    return format_digest(digest_bytes(COMMITMENT_PAIR_DOMAIN, canonicalize(value)))


def authentication_input(message: dict[str, Any]) -> dict[str, Any]:
    """Build the exact authenticated field set without a circular reference."""

    required = {
        "protocol_profile",
        "protocol_version",
        "message_type",
        "message_version",
        "delivery_class",
        "session_context",
        "sender",
        "audience",
        "issued_at",
        "expires_at",
        "identity",
        "prior_transcript_digest",
        "payload_digest",
        "authentication",
    }
    missing = sorted(required - message.keys())
    if missing:
        raise CanonicalMessageError(
            "authentication input is missing fields: " + ", ".join(missing)
        )
    authentication = message.get("authentication")
    if not isinstance(authentication, dict):
        raise CanonicalMessageError("authentication must be an object")
    auth_metadata = {
        key: authentication.get(key)
        for key in (
            "mode",
            "algorithm_id",
            "key_id",
            "verification_material_id",
        )
    }
    if any(value is None for value in auth_metadata.values()):
        raise CanonicalMessageError("authentication metadata is incomplete")
    return {
        key: message[key]
        for key in (
            "protocol_profile",
            "protocol_version",
            "message_type",
            "message_version",
            "delivery_class",
            "session_context",
            "sender",
            "audience",
            "issued_at",
            "expires_at",
            "identity",
            "prior_transcript_digest",
            "payload_digest",
        )
    } | {"authentication": auth_metadata}


def message_digest(message: dict[str, Any]) -> str:
    return format_digest(
        digest_bytes(MESSAGE_DOMAIN, canonicalize(authentication_input(message)))
    )


def populate_digests(message: dict[str, Any]) -> dict[str, Any]:
    """Return a copy with recomputed payload and message digests."""

    result = dict(message)
    result["payload_digest"] = payload_digest(result.get("payload"))
    result["message_digest"] = message_digest(result)
    return result


def transcript_genesis_digest() -> str:
    return format_digest(digest_bytes(TRANSCRIPT_GENESIS_DOMAIN))


def append_transcript(
    prior_digest: str,
    accepted_event_index: int,
    accepted_event_digest: str,
) -> str:
    """Append one accepted mutating event to the authoritative transcript."""

    if not 1 <= accepted_event_index < 2**64:
        raise CanonicalMessageError("accepted event index must be in 1..2^64-1")
    return format_digest(
        digest_bytes(
            TRANSCRIPT_DOMAIN,
            parse_digest(prior_digest),
            accepted_event_index.to_bytes(8, "big"),
            parse_digest(accepted_event_digest),
        )
    )


def timer_event_digest(timer_event: dict[str, Any]) -> str:
    return format_digest(digest_bytes(TIMER_EVENT_DOMAIN, canonicalize(timer_event)))


def bounded_error(error: BaseException, limit: int = 280) -> str:
    text = " ".join(str(error).split()) or error.__class__.__name__
    return text if len(text) <= limit else text[: limit - 3] + "..."


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("json_file", type=Path)
    parser.add_argument(
        "--check-canonical",
        action="store_true",
        help="fail unless the file bytes are already exact RFC 8785 JSON",
    )
    args = parser.parse_args(argv)
    try:
        raw = args.json_file.read_bytes()
        value = strict_loads(raw)
        canonical = canonicalize(value)
        if args.check_canonical and raw != canonical:
            raise CanonicalMessageError("input bytes are not canonical RFC 8785 JSON")
        sys.stdout.buffer.write(canonical)
    except (OSError, UnicodeError, CanonicalMessageError) as error:
        print(f"canonical-message: error: {bounded_error(error)}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
