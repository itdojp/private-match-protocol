#!/usr/bin/env python3
"""Generate or check deterministic experimental PET-profile artifacts."""

from __future__ import annotations

import argparse
from pathlib import Path

from pet_profiles import bounded_main, compare_generated, write_generated


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path("."))
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    root = args.root.resolve()
    return bounded_main(
        lambda: compare_generated(root) if args.check else write_generated(root)
    )


if __name__ == "__main__":
    raise SystemExit(main())
