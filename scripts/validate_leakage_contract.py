#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator, FormatChecker


class NoDatesSafeLoader(yaml.SafeLoader):
    pass


for first_char, resolvers in list(NoDatesSafeLoader.yaml_implicit_resolvers.items()):
    NoDatesSafeLoader.yaml_implicit_resolvers[first_char] = [
        entry for entry in resolvers if entry[0] != "tag:yaml.org,2002:timestamp"
    ]


def load_contract(path: Path):
    with path.open("r", encoding="utf-8") as handle:
        return yaml.load(handle, Loader=NoDatesSafeLoader)


def validate(root: Path) -> list[str]:
    schema_path = root / "schema" / "leakage-contract.schema.json"
    contract_path = root / "privacy" / "leakage-contract.v0.1.yaml"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    contract = load_contract(contract_path)
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    messages = []
    for error in sorted(validator.iter_errors(contract), key=lambda item: list(item.absolute_path)):
        location = ".".join(str(value) for value in error.absolute_path) or "$"
        messages.append(f"{location}: {error.message}")
    return messages


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path.cwd())
    args = parser.parse_args(argv)
    errors = validate(args.root.resolve())
    if errors:
        for error in errors:
            print(error)
        return 1
    print("leakage-contract: valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
