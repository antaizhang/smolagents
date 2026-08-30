"""Load, validate and diff policy files.

A policy is a file, so it goes through code review, ships with a version, and
can be compared between releases. :func:`diff_policies` is the part that makes a
change reviewable in one line — "this release stopped hashing emails" is worth
seeing before it ships, not after.

Validation is strict on purpose. A label typo in a rule would otherwise be a
rule that silently never fires, which is the worst failure a guard can have:
everything looks configured and nothing is enforced.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from ..detection.patterns import KNOWN_LABELS
from .model import Action, Condition, Expectation, Policy, RequestContext, Rule


DEFAULT_POLICY_PATH = Path(__file__).with_name("default_policy.yaml")

_CONDITION_KEYS = frozenset(
    {"labels", "destinations", "caller_roles", "purposes", "kinds", "min_confidence", "max_confidence"}
)
_RULE_KEYS = frozenset({"id", "action", "when", "reason", "alert", "restore_on_response"})
_POLICY_KEYS = frozenset({"name", "version", "default_action", "default_reason", "labels", "rules", "expectations"})


class PolicyError(ValueError):
    """Raised when a policy file cannot be trusted to mean what it says."""


def _require_keys(data: Mapping[str, Any], allowed: frozenset[str], where: str) -> None:
    unknown = sorted(set(data) - allowed)
    if unknown:
        raise PolicyError(
            f"{where}: unknown key(s) {', '.join(unknown)}; allowed keys are {', '.join(sorted(allowed))}"
        )


def _as_frozenset(value: Any, where: str) -> frozenset[str]:
    if value is None:
        return frozenset()
    if isinstance(value, str):
        return frozenset({value})
    if isinstance(value, Iterable):
        items = list(value)
        if not all(isinstance(item, str) and item.strip() for item in items):
            raise PolicyError(f"{where}: expected a list of non-empty strings, got {value!r}")
        return frozenset(items)
    raise PolicyError(f"{where}: expected a string or a list of strings, got {value!r}")


def _as_action(value: Any, where: str) -> Action:
    try:
        return Action(value)
    except ValueError as error:
        allowed = ", ".join(action.value for action in Action)
        raise PolicyError(f"{where}: unknown action {value!r}; allowed actions are {allowed}") from error


def _parse_condition(data: Any, where: str, known_labels: frozenset[str] | None) -> Condition:
    if data is None:
        return Condition()
    if not isinstance(data, Mapping):
        raise PolicyError(f"{where}: `when` must be a mapping, got {type(data).__name__}")
    _require_keys(data, _CONDITION_KEYS, where)

    labels = _as_frozenset(data.get("labels"), f"{where}.labels")
    if known_labels is not None:
        unknown = sorted(labels - known_labels)
        if unknown:
            raise PolicyError(
                f"{where}: unknown label(s) {', '.join(unknown)}. A rule naming a label no detector emits "
                f"would never fire. Known labels: {', '.join(sorted(known_labels))}"
            )
    try:
        return Condition(
            labels=labels,
            destinations=_as_frozenset(data.get("destinations"), f"{where}.destinations"),
            caller_roles=_as_frozenset(data.get("caller_roles"), f"{where}.caller_roles"),
            purposes=_as_frozenset(data.get("purposes"), f"{where}.purposes"),
            kinds=_as_frozenset(data.get("kinds"), f"{where}.kinds"),
            min_confidence=float(data.get("min_confidence", 0.0)),
            max_confidence=None if data.get("max_confidence") is None else float(data["max_confidence"]),
        )
    except (TypeError, ValueError) as error:
        raise PolicyError(f"{where}: {error}") from error


def _parse_rule(data: Any, index: int, known_labels: frozenset[str] | None) -> Rule:
    where = f"rules[{index}]"
    if not isinstance(data, Mapping):
        raise PolicyError(f"{where}: each rule must be a mapping, got {type(data).__name__}")
    _require_keys(data, _RULE_KEYS, where)
    if "id" not in data:
        raise PolicyError(f"{where}: every rule needs an `id`")
    if "action" not in data:
        raise PolicyError(f"{where} ({data['id']}): every rule needs an `action`")

    where = f"rules[{index}] ({data['id']})"
    try:
        return Rule(
            id=str(data["id"]),
            action=_as_action(data["action"], where),
            condition=_parse_condition(data.get("when"), where, known_labels),
            reason=str(data.get("reason", "")).strip(),
            alert=bool(data.get("alert", False)),
            restore_on_response=bool(data.get("restore_on_response", False)),
        )
    except PolicyError:
        raise
    except (TypeError, ValueError) as error:
        raise PolicyError(f"{where}: {error}") from error


def _parse_expectation(data: Any, index: int) -> Expectation:
    where = f"expectations[{index}]"
    if not isinstance(data, Mapping):
        raise PolicyError(f"{where}: each expectation must be a mapping, got {type(data).__name__}")
    missing = sorted({"label", "confidence", "destination", "caller_role", "expect_action"} - set(data))
    if missing:
        raise PolicyError(f"{where}: missing key(s) {', '.join(missing)}")
    try:
        context = RequestContext(
            destination=str(data["destination"]),
            caller_role=str(data["caller_role"]),
            purpose=str(data.get("purpose", "unspecified")),
            kind=str(data.get("kind", "text")),
        )
        return Expectation(
            name=str(data.get("name", f"expectation {index}")),
            label=str(data["label"]),
            confidence=float(data["confidence"]),
            context=context,
            expect_action=_as_action(data["expect_action"], where),
            expect_rule=None if data.get("expect_rule") is None else str(data["expect_rule"]),
        )
    except PolicyError:
        raise
    except (TypeError, ValueError) as error:
        raise PolicyError(f"{where}: {error}") from error


def parse_policy(
    data: Mapping[str, Any], *, known_labels: frozenset[str] | None = KNOWN_LABELS, strict: bool = True
) -> Policy:
    """Build a :class:`~sensitiveguard.policy.model.Policy` from a mapping.

    ``known_labels`` is the vocabulary a rule may name. A policy widens it with
    its own ``labels:`` block, which is how a rule set written for a domain the
    shipped detectors know nothing about — twenty-six personal-data fields, say —
    states its vocabulary instead of being told every one of them is a typo.

    ``strict`` runs the structural lint and refuses a policy with an error-level
    finding, so a rule set that only works because of where a line happens to sit
    in the file does not load.
    """

    if not isinstance(data, Mapping):
        raise PolicyError(f"a policy must be a mapping, got {type(data).__name__}")
    _require_keys(data, _POLICY_KEYS, "policy")
    for required in ("name", "version", "rules"):
        if required not in data:
            raise PolicyError(f"policy: missing required key `{required}`")
    rules_data = data["rules"]
    if not isinstance(rules_data, list) or not rules_data:
        raise PolicyError("policy: `rules` must be a non-empty list")

    declared = _as_frozenset(data.get("labels"), "policy.labels")
    for label in sorted(declared):
        if label != label.upper():
            raise PolicyError(f"policy.labels: label {label!r} must be upper-case")
    vocabulary = None if known_labels is None else known_labels | declared

    rules = tuple(_parse_rule(rule, index, vocabulary) for index, rule in enumerate(rules_data))
    expectations = tuple(_parse_expectation(item, index) for index, item in enumerate(data.get("expectations") or []))
    try:
        policy = Policy(
            name=str(data["name"]),
            version=str(data["version"]),
            rules=rules,
            default_action=_as_action(data.get("default_action", Action.REVIEW.value), "policy.default_action"),
            default_reason=str(data.get("default_reason", "no rule matched; the policy fails closed")).strip(),
            expectations=expectations,
            labels=declared,
        )
    except PolicyError:
        raise
    except (TypeError, ValueError) as error:
        raise PolicyError(f"policy: {error}") from error

    if strict:
        _enforce_lint(policy)
    return policy


def _enforce_lint(policy: Policy) -> None:
    """Refuse a policy whose meaning depends on something other than its rules."""

    from .engine import PolicyEngine

    errors = [finding for finding in PolicyEngine(policy).lint() if finding.severity == "error"]
    if errors:
        rendered = "\n".join(f"  {finding.describe()}" for finding in errors)
        raise PolicyError(f"policy {policy.label} does not pass the structural lint:\n{rendered}")


def load_policy(
    source: str | Path | Mapping[str, Any],
    *,
    known_labels: frozenset[str] | None = KNOWN_LABELS,
    strict: bool = True,
) -> Policy:
    """Load a policy from a path, a YAML string, or an already-parsed mapping."""

    if isinstance(source, Mapping):
        return parse_policy(source, known_labels=known_labels, strict=strict)
    if isinstance(source, Path) or (
        isinstance(source, str) and "\n" not in source and source.endswith((".yaml", ".yml"))
    ):
        path = Path(source)
        try:
            raw = path.read_text(encoding="utf-8")
        except OSError as error:
            raise PolicyError(f"cannot read policy file {path}: {error}") from error
    elif isinstance(source, str):
        raw = source
    else:
        raise PolicyError(f"cannot load a policy from {type(source).__name__}")

    try:
        data = yaml.safe_load(raw)
    except yaml.YAMLError as error:
        raise PolicyError(f"policy is not valid YAML: {error}") from error
    return parse_policy(data, known_labels=known_labels, strict=strict)


@lru_cache(maxsize=1)
def default_policy() -> Policy:
    """The policy shipped with the package."""

    return load_policy(DEFAULT_POLICY_PATH)


@dataclass(frozen=True)
class RuleChange:
    rule_id: str
    before: dict[str, Any] | None
    after: dict[str, Any] | None

    @property
    def kind(self) -> str:
        if self.before is None:
            return "added"
        if self.after is None:
            return "removed"
        return "changed"

    def describe(self) -> str:
        if self.kind == "added":
            return f"+ {self.rule_id}: {self.after}"
        if self.kind == "removed":
            return f"- {self.rule_id}: {self.before}"
        fields = sorted(set(self.before or {}) | set(self.after or {}))
        parts = [
            f"{field}: {(self.before or {}).get(field)!r} -> {(self.after or {}).get(field)!r}"
            for field in fields
            if (self.before or {}).get(field) != (self.after or {}).get(field)
        ]
        return f"~ {self.rule_id}: " + "; ".join(parts)


@dataclass(frozen=True)
class PolicyDiff:
    """What changed between two policy versions."""

    before: str
    after: str
    changes: tuple[RuleChange, ...]
    reordered: tuple[str, ...] = ()
    default_action_change: tuple[str, str] | None = None

    @property
    def empty(self) -> bool:
        return not self.changes and not self.reordered and self.default_action_change is None

    def render(self) -> str:
        lines = [f"policy diff {self.before} -> {self.after}"]
        if self.empty:
            lines.append("  (no behavioural change)")
            return "\n".join(lines)
        if self.default_action_change is not None:
            lines.append(f"  ! default action: {self.default_action_change[0]} -> {self.default_action_change[1]}")
        for change in self.changes:
            lines.append(f"  {change.describe()}")
        if self.reordered:
            lines.append(f"  ! evaluation order changed for: {', '.join(self.reordered)}")
        return "\n".join(lines)


def diff_policies(before: Policy, after: Policy) -> PolicyDiff:
    """Compare two policies rule by rule.

    Order is reported as well as content, because a policy is first-match-wins:
    moving a rule up can change every verdict below it without editing a
    single condition.
    """

    before_rules = {rule.id: rule.as_dict() for rule in before.rules}
    after_rules = {rule.id: rule.as_dict() for rule in after.rules}
    changes: list[RuleChange] = []

    for rule_id in before.rule_ids:
        if rule_id not in after_rules:
            changes.append(RuleChange(rule_id, before_rules[rule_id], None))
        elif before_rules[rule_id] != after_rules[rule_id]:
            changes.append(RuleChange(rule_id, before_rules[rule_id], after_rules[rule_id]))
    for rule_id in after.rule_ids:
        if rule_id not in before_rules:
            changes.append(RuleChange(rule_id, None, after_rules[rule_id]))

    shared = [rule_id for rule_id in before.rule_ids if rule_id in after_rules]
    shared_after = [rule_id for rule_id in after.rule_ids if rule_id in before_rules]
    reordered = tuple(shared) if shared != shared_after else ()

    default_change = None
    if before.default_action is not after.default_action:
        default_change = (before.default_action.value, after.default_action.value)

    return PolicyDiff(
        before=before.label,
        after=after.label,
        changes=tuple(changes),
        reordered=reordered,
        default_action_change=default_change,
    )


__all__ = [
    "DEFAULT_POLICY_PATH",
    "PolicyDiff",
    "PolicyError",
    "RuleChange",
    "default_policy",
    "diff_policies",
    "load_policy",
    "parse_policy",
]
