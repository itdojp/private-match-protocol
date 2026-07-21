"""Strict YAML loading for security-sensitive repository artifacts.

PyYAML's default mapping constructor accepts duplicate keys using last-wins
semantics.  Protocol registries and state artifacts must instead reject an
ambiguous mapping before any semantic index is constructed.
"""

from __future__ import annotations

from typing import Any

import yaml


class DuplicateKeyError(yaml.YAMLError):
    """Raised when one YAML mapping contains the same key more than once."""


class UniqueKeySafeLoader(yaml.SafeLoader):
    """SafeLoader variant with duplicate-key rejection."""


# PyYAML stores resolver entries on the loader class.  Copy both the mapping
# and each entry list before removing timestamps so SafeLoader's global
# behavior is never mutated by this protocol-specific loader.
UniqueKeySafeLoader.yaml_implicit_resolvers = {
    first: list(entries)
    for first, entries in yaml.SafeLoader.yaml_implicit_resolvers.items()
}
UniqueKeySafeLoader.yaml_constructors = dict(yaml.SafeLoader.yaml_constructors)
for first, entries in list(UniqueKeySafeLoader.yaml_implicit_resolvers.items()):
    UniqueKeySafeLoader.yaml_implicit_resolvers[first] = [
        entry for entry in entries if entry[0] != "tag:yaml.org,2002:timestamp"
    ]


def _construct_unique_mapping(
    loader: UniqueKeySafeLoader, node: yaml.MappingNode, deep: bool = False
) -> dict[Any, Any]:
    loader.flatten_mapping(node)
    result: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in result
        except TypeError as error:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                "found an unhashable key",
                key_node.start_mark,
            ) from error
        if duplicate:
            raise DuplicateKeyError(
                f"duplicate key {key!r} at line {key_node.start_mark.line + 1}, "
                f"column {key_node.start_mark.column + 1}"
            )
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


UniqueKeySafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


def strict_yaml_load(text: str) -> Any:
    """Load YAML without executable tags and reject duplicate mapping keys."""

    return yaml.load(text, Loader=UniqueKeySafeLoader)
