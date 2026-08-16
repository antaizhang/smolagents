"""Dependency-free policy configuration loader."""

from __future__ import annotations

import ast
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sensitiveguard.policy.rules import PolicyRule


@dataclass(frozen=True, slots=True)
class PolicyConfig:
    version: str
    rules: tuple[PolicyRule, ...]


def _parse_scalar(value: str) -> Any:
    value = value.strip()
    if not value:
        return None
    lowered = value.casefold()
    if lowered in {"null", "none", "~"}:
        return None
    if lowered in {"true", "yes"}:
        return True
    if lowered in {"false", "no"}:
        return False
    if value.startswith("[") and value.endswith("]"):
        inner = value[1:-1].strip()
        if not inner:
            return []
        return [_parse_scalar(item) for item in inner.split(",")]
    try:
        return ast.literal_eval(value)
    except (SyntaxError, ValueError):
        return value.strip("'\"")


def _parse_minimal_yaml(text: str) -> dict[str, Any]:
    """Parse the flat rule-list subset used by bundled policy files."""

    root: dict[str, Any] = {}
    rules: list[dict[str, Any]] = []
    current_rule: dict[str, Any] | None = None
    in_rules = False
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped == "rules:":
            in_rules = True
            root["rules"] = rules
            continue
        if in_rules and stripped.startswith("-"):
            current_rule = {}
            rules.append(current_rule)
            remainder = stripped[1:].strip()
            if remainder:
                if ":" not in remainder:
                    raise ValueError(f"Invalid policy YAML at line {line_number}")
                key, value = remainder.split(":", 1)
                current_rule[key.strip()] = _parse_scalar(value)
            continue
        if ":" not in stripped:
            raise ValueError(f"Invalid policy YAML at line {line_number}")
        key, value = stripped.split(":", 1)
        target = current_rule if in_rules and current_rule is not None else root
        target[key.strip()] = _parse_scalar(value)
    return root


def _decode(text: str) -> Any:
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return _parse_minimal_yaml(text)


def load_policy_config(source: str | Path | Mapping[str, Any] | Sequence[Mapping[str, Any]]) -> PolicyConfig:
    """Load JSON, JSON-compatible YAML, or the bundled flat YAML subset."""

    data: Any
    if isinstance(source, Path):
        data = _decode(source.read_text(encoding="utf-8"))
    elif isinstance(source, str):
        stripped = source.lstrip()
        if "\n" in source or stripped.startswith(("{", "[")):
            data = _decode(source)
        else:
            candidate = Path(source)
            try:
                is_file = candidate.is_file()
            except OSError:
                is_file = False
            data = _decode(candidate.read_text(encoding="utf-8")) if is_file else _decode(source)
    else:
        data = source

    if isinstance(data, Mapping):
        version = str(data.get("version", "unversioned"))
        raw_rules = data.get("rules", ())
    elif isinstance(data, Sequence) and not isinstance(data, (str, bytes, bytearray)):
        version = "unversioned"
        raw_rules = data
    else:
        raise TypeError("Policy configuration must be a mapping or a sequence of rules")
    if not isinstance(raw_rules, Sequence) or isinstance(raw_rules, (str, bytes, bytearray)):
        raise TypeError("Policy configuration 'rules' must be a sequence")
    rules = tuple(rule if isinstance(rule, PolicyRule) else PolicyRule.from_dict(rule) for rule in raw_rules)
    seen: set[str] = set()
    for rule in rules:
        if rule.policy_id in seen:
            raise ValueError(f"Duplicate policy_id: {rule.policy_id}")
        seen.add(rule.policy_id)
    return PolicyConfig(version=version, rules=rules)


def load_policy_rules(
    source: str | Path | Mapping[str, Any] | Sequence[Mapping[str, Any]],
) -> tuple[PolicyRule, ...]:
    return load_policy_config(source).rules


__all__ = ["PolicyConfig", "load_policy_config", "load_policy_rules"]
