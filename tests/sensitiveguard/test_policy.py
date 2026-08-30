"""Policy: declarative, versioned, diffable, and testable on its own terms."""

from __future__ import annotations

import inspect

import pytest

from sensitiveguard.facts import Finding, Span
from sensitiveguard.policy import (
    Action,
    Condition,
    Policy,
    PolicyEngine,
    PolicyError,
    RequestContext,
    Rule,
    default_policy,
    diff_policies,
    load_policy,
)
from sensitiveguard.policy import engine as engine_module
from sensitiveguard.policy import model as model_module


def context(**overrides: str) -> RequestContext:
    base = {"destination": "external_llm", "caller_role": "agent", "purpose": "tool_call", "kind": "text"}
    return RequestContext(**{**base, **overrides})


def fact(label: str = "PHONE", confidence: float = 0.95) -> Finding:
    return Finding(Span(12, 23), label, confidence, "regex:phone")


# ------------------------------------------------------- the shipped policy


def test_the_default_policy_passes_the_tests_it_ships_with() -> None:
    """The point of expectations in the file: a reordering fails the build."""

    assert PolicyEngine(default_policy()).self_test() == []


def test_no_rule_in_the_default_policy_is_shadowed_into_uselessness() -> None:
    assert PolicyEngine(default_policy()).unreachable_rules() == ()


@pytest.mark.parametrize(
    ("label", "confidence", "overrides", "expected_action", "expected_rule"),
    [
        ("PHONE", 0.95, {}, Action.MASK, "phone-external-egress"),
        (
            "PHONE",
            0.95,
            {"destination": "internal_log", "caller_role": "service", "purpose": "observability"},
            Action.HASH,
            "contact-internal-log",
        ),
        ("ID_CARD", 0.99, {}, Action.BLOCK, "id-card-any-egress"),
        (
            "ID_CARD",
            0.99,
            {"destination": "user_document", "caller_role": "user", "purpose": "editing"},
            Action.BLOCK,
            "id-card-any-egress",
        ),
        (
            "PHONE",
            0.95,
            {"destination": "user_document", "caller_role": "user", "purpose": "editing"},
            Action.ALLOW,
            "owner-editing-passthrough",
        ),
        ("PHONE", 0.95, {"purpose": "round_trip"}, Action.TOKENIZE, "contact-external-round-trip"),
    ],
)
def test_the_same_label_gets_a_different_verdict_per_destination(
    label: str, confidence: float, overrides: dict, expected_action: Action, expected_rule: str
) -> None:
    decision = PolicyEngine(default_policy()).decide(fact(label, confidence), context(**overrides))

    assert decision.action is expected_action
    assert decision.rule_id == expected_rule


def test_an_unclaimed_combination_falls_closed() -> None:
    decision = PolicyEngine(default_policy()).decide(fact(), context(destination="pastebin"))

    assert decision.action is Action.REVIEW
    assert decision.rule_id == "__default__"
    assert "held for a human" in decision.reason


def test_only_tokenisation_is_reversible() -> None:
    engine = PolicyEngine(default_policy())

    masked = engine.decide(fact(), context())
    tokenised = engine.decide(fact(), context(purpose="round_trip"))

    assert not masked.reversible
    assert tokenised.reversible
    assert tokenised.restore_on_response


def test_a_blocked_fact_raises_an_alert() -> None:
    decision = PolicyEngine(default_policy()).decide(fact("ID_CARD", 0.99), context())

    assert decision.action is Action.BLOCK
    assert decision.alert


# ------------------------------------------------------- the decision path


def test_why_this_one_was_blocked_is_a_printable_path() -> None:
    decision = PolicyEngine(default_policy()).decide(fact("ID_CARD", 0.99), context())
    explanation = decision.explain()

    assert "ID_CARD span=[12,23] conf=0.99" in explanation
    assert "destination=external_llm" in explanation
    assert "MATCH id-card-any-egress" in explanation
    assert "verdict block" in explanation
    assert "alert   raised" in explanation
    assert decision.policy_fingerprint in explanation


def test_the_path_records_why_each_earlier_rule_lost() -> None:
    decision = PolicyEngine(default_policy()).decide(fact(), context())
    losers = {step.rule_id: step.failed_predicate for step in decision.trace if not step.matched}

    assert losers["id-card-any-egress"] == "label 'PHONE' not in {ID_CARD}"
    assert losers["owner-editing-passthrough"] == "destination 'external_llm' not in {user_document}"
    assert losers["contact-external-round-trip"] == "purpose 'tool_call' not in {round_trip}"
    assert [step.rule_id for step in decision.trace if step.matched] == ["phone-external-egress"]


def test_a_confidence_gate_says_so_in_the_path() -> None:
    decision = PolicyEngine(default_policy()).decide(fact(confidence=0.35), context())

    assert decision.rule_id == "unsettled-external"
    assert any(step.failed_predicate == "confidence 0.35 below min_confidence 0.50" for step in decision.trace)


def test_a_decision_serialises_without_the_content_it_judged() -> None:
    decision = PolicyEngine(default_policy()).decide(fact(), context())
    assert "13800138000" not in str(decision.as_dict())


# ------------------------------------------------------------- determinism


def test_the_decision_layer_imports_no_model() -> None:
    """The reason the decision is not a prompt: it cannot drift."""

    for module in (engine_module, model_module):
        source = inspect.getsource(module)
        assert "phone_agent" not in source
        assert "smolagents" not in source
        assert "litellm" not in source


def test_the_same_fact_and_context_always_gets_the_same_verdict() -> None:
    engine = PolicyEngine(default_policy())
    verdicts = {engine.decide(fact(), context()).action for _ in range(20)}

    assert verdicts == {Action.MASK}


def test_first_match_wins_so_ordering_is_the_meaning() -> None:
    rules = (
        Rule(id="narrow", action=Action.BLOCK, condition=Condition(labels=frozenset({"PHONE"}))),
        Rule(id="broad", action=Action.ALLOW),
    )
    forward = Policy(name="p", version="1", rules=rules)
    reversed_policy = Policy(name="p", version="2", rules=tuple(reversed(rules)))

    assert PolicyEngine(forward).decide(fact(), context()).action is Action.BLOCK
    assert PolicyEngine(reversed_policy).decide(fact(), context()).action is Action.ALLOW


def test_self_test_reports_every_mismatch_at_once() -> None:
    policy = default_policy()
    broken = Policy(
        name=policy.name,
        version="broken",
        rules=(Rule(id="allow-everything", action=Action.ALLOW),),
        default_action=policy.default_action,
        expectations=policy.expectations,
    )

    failures = PolicyEngine(broken).self_test()

    # Every vector is reported, not just the first, so one run shows the whole
    # blast radius of a rule-set change.
    assert len(failures) == len(policy.expectations)
    assert "expected mask via phone-external-egress, got allow via allow-everything" in failures[0].describe()
    # An expectation pins the rule as well as the action: landing on `allow` by
    # way of the wrong rule is still a regression.
    allow_failure = next(f for f in failures if f.expectation.expect_action is Action.ALLOW)
    assert allow_failure.actual_action is Action.ALLOW
    assert allow_failure.actual_rule == "allow-everything"


# ------------------------------------------------------------------ loading


def test_a_policy_loads_from_yaml_a_path_or_a_mapping() -> None:
    yaml_text = """
    name: inline
    version: "1"
    rules:
      - id: block-phones
        when: {labels: [PHONE]}
        action: block
    """
    from_yaml = load_policy(yaml_text)
    from_mapping = load_policy(
        {
            "name": "inline",
            "version": "1",
            "rules": [{"id": "block-phones", "when": {"labels": ["PHONE"]}, "action": "block"}],
        }
    )

    assert from_yaml.fingerprint() == from_mapping.fingerprint()


@pytest.mark.parametrize(
    ("document", "match"),
    [
        ({"name": "p", "version": "1", "rules": [{"id": "a", "action": "shred"}]}, "unknown action"),
        (
            {"name": "p", "version": "1", "rules": [{"id": "a", "action": "mask", "when": {"labels": ["PHNOE"]}}]},
            "unknown label",
        ),
        (
            {"name": "p", "version": "1", "rules": [{"id": "a", "action": "mask"}, {"id": "a", "action": "block"}]},
            "duplicate rule id",
        ),
        ({"name": "p", "version": "1", "rules": [{"id": "a", "action": "mask", "whn": {}}]}, "unknown key"),
        ({"name": "p", "version": "1", "rules": []}, "non-empty list"),
        ({"name": "p", "rules": [{"id": "a", "action": "mask"}]}, "missing required key"),
        (
            {"name": "p", "version": "1", "rules": [{"id": "a", "action": "mask", "restore_on_response": True}]},
            "reversible action",
        ),
        (
            {
                "name": "p",
                "version": "1",
                "rules": [{"id": "a", "action": "mask", "when": {"min_confidence": 0.9, "max_confidence": 0.2}}],
            },
            "can never match",
        ),
    ],
)
def test_a_policy_that_would_silently_not_enforce_fails_to_load(document: dict, match: str) -> None:
    with pytest.raises(PolicyError, match=match):
        load_policy(document)


def test_a_fingerprint_pins_a_verdict_to_an_exact_rule_set() -> None:
    original = default_policy()
    same = load_policy(original.as_dict() | {"expectations": []})
    changed = load_policy(
        original.as_dict() | {"rules": [rule.as_dict() for rule in original.rules[1:]], "expectations": []}
    )

    assert same.fingerprint() == original.fingerprint()
    assert changed.fingerprint() != original.fingerprint()


# --------------------------------------------------------------------- diff


def _policy(rules: tuple[Rule, ...], *, version: str = "1", default: Action = Action.REVIEW) -> Policy:
    return Policy(name="p", version=version, rules=rules, default_action=default)


def test_a_diff_shows_what_a_release_changed() -> None:
    before = _policy(
        (
            Rule(id="phones", action=Action.MASK, condition=Condition(labels=frozenset({"PHONE"}))),
            Rule(id="emails", action=Action.HASH, condition=Condition(labels=frozenset({"EMAIL"}))),
        )
    )
    after = _policy(
        (
            Rule(id="phones", action=Action.TOKENIZE, condition=Condition(labels=frozenset({"PHONE"}))),
            Rule(id="cards", action=Action.BLOCK, condition=Condition(labels=frozenset({"BANK_CARD"}))),
        ),
        version="2",
    )

    diff = diff_policies(before, after)
    rendered = diff.render()

    assert not diff.empty
    assert {change.rule_id: change.kind for change in diff.changes} == {
        "phones": "changed",
        "emails": "removed",
        "cards": "added",
    }
    assert "'mask' -> 'tokenize'" in rendered
    assert "- emails" in rendered
    assert "+ cards" in rendered


def test_a_diff_reports_reordering_because_ordering_changes_verdicts() -> None:
    rules = (
        Rule(id="a", action=Action.MASK, condition=Condition(labels=frozenset({"PHONE"}))),
        Rule(id="b", action=Action.ALLOW),
    )
    diff = diff_policies(_policy(rules), _policy(tuple(reversed(rules)), version="2"))

    assert diff.reordered == ("a", "b")
    assert "evaluation order changed" in diff.render()


def test_a_diff_calls_out_a_change_of_default_action() -> None:
    rules = (Rule(id="a", action=Action.MASK),)
    diff = diff_policies(_policy(rules), _policy(rules, version="2", default=Action.ALLOW))

    assert diff.default_action_change == ("review", "allow")
    assert "! default action: review -> allow" in diff.render()


def test_an_unchanged_policy_diffs_to_nothing() -> None:
    diff = diff_policies(default_policy(), default_policy())

    assert diff.empty
    assert "no behavioural change" in diff.render()


# ---------------------------------------------------------------- contexts


@pytest.mark.parametrize("field", ["destination", "caller_role", "purpose", "kind"])
def test_a_request_context_needs_every_dimension_filled_in(field: str) -> None:
    with pytest.raises(ValueError, match=field):
        context(**{field: "  "})
