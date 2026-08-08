#!/usr/bin/env python3
"""Validate the closed experimental PET integration-profile authority."""

from __future__ import annotations

import argparse
from pathlib import Path

from pet_profiles import bounded_main, validate_repository


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path("."))
    args = parser.parse_args(argv)
    return bounded_main(lambda: validate_repository(args.root.resolve()))


if __name__ == "__main__":
    raise SystemExit(main())
