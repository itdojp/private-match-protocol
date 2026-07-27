#!/usr/bin/env python3
"""Deterministic Protocol time derivations for Draft core v0.1.

This module operates only on canonical UTC whole-second timestamps.  It does
not read a wall clock or select a production timeout value.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Any


CANONICAL_UTC_TIMESTAMP = re.compile(
    r"^(?P<year>[0-9]{4})-(?P<month>[0-9]{2})-(?P<day>[0-9]{2})"
    r"T(?P<hour>[0-9]{2}):(?P<minute>[0-9]{2}):(?P<second>[0-9]{2})Z$"
)


class ProtocolTimeError(ValueError):
    """A bounded error for a malformed or inconsistent Protocol time input."""


def parse_canonical_utc_timestamp(value: Any) -> datetime:
    """Parse the closed Draft v0.1 timestamp representation.

    Offsets, fractional seconds, leap-second spellings, and non-string values
    are rejected rather than normalized to another wire representation.
    """

    if not isinstance(value, str) or CANONICAL_UTC_TIMESTAMP.fullmatch(value) is None:
        raise ProtocolTimeError("noncanonical-timestamp")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError as error:
        raise ProtocolTimeError("invalid-timestamp") from error
    if parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != value:
        raise ProtocolTimeError("noncanonical-timestamp")
    return parsed


def derive_evaluation_deadline(
    *,
    authoritative_time: Any,
    evaluation_timeout_seconds: Any,
    session_expires_at: Any,
) -> str:
    """Return ``min(now + evaluation timeout, session expiry)`` canonically.

    All values are explicit reviewed state or policy inputs.  No process time,
    client-issued time, or case-specific constant is consulted.
    """

    if (
        not isinstance(evaluation_timeout_seconds, int)
        or isinstance(evaluation_timeout_seconds, bool)
        or evaluation_timeout_seconds <= 0
    ):
        raise ProtocolTimeError("invalid-evaluation-timeout")
    current = parse_canonical_utc_timestamp(authoritative_time)
    expiry = parse_canonical_utc_timestamp(session_expires_at)
    if expiry <= current:
        raise ProtocolTimeError("session-not-live")
    try:
        timeout_deadline = current + timedelta(seconds=evaluation_timeout_seconds)
    except OverflowError as error:
        raise ProtocolTimeError("evaluation-deadline-overflow") from error
    derived = min(timeout_deadline, expiry)
    return derived.strftime("%Y-%m-%dT%H:%M:%SZ")
