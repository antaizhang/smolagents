"""The policy linter: the invariants a first-match-wins rule file has to hold.

These are the checks that catch the failure a single test vector cannot: a rule
that only means what it looks like it means because of where it sits in the file.
"""

from __future__ import annotations

import pytest

from sensitiveguard.policy import Action, Condition, Policy, PolicyEngine, Rule, load_policy
from sensitiveguard.policy.engine import UNCONSTRAINED
from sensitiveguard.policy.loader import DEFAULT_POLICY_PATH, PolicyError


def _policy(*rules: Rule, **kwargs) -> Policy:
    return Policy(name="t", version="1", rules=tuple(rules), **kwargs)


# ------------------------------------------------------ the unscoped-allow rule


def test_an_allow_without_destinations_is_an_error() -> None:
    """The invariant the review asked for: an allow must say where it allows to."""

    policy = _policy(Rule(id="open", action=Action.ALLOW))
    errors = [f for f in PolicyEngine(policy).lint() if f.severity == "error"]
    assert [f.code for f in errors] == ["unscoped-allow"]


def test_an_allow_with_destinations_is_fine() -> None:
    policy = _policy(Rule(id="scoped", action=Action.ALLOW, condition=Condition(destinations=frozenset({"inside"}))))
    assert [f for f in PolicyEngine(policy).lint() if f.code == "unscoped-allow"] == []


def test_a_strict_load_refuses_an_unscoped_allow() -> None:
    text = """
    name: bad
    version: "1"
    rules:
      - id: open
        action: allow
    """
    with pytest.raises(PolicyError, match="structural lint"):
        load_policy(text)


def test_a_non_strict_load_lets_it_through_for_inspection() -> None:
    text = """
    name: bad
    version: "1"
    rules:
      - id: open
        action: allow
    """
    policy = load_policy(text, strict=False)
    assert any(f.code == "unscoped-allow" for f in PolicyEngine(policy).lint())


# --------------------------------------------------------- unreachable rules


def test_a_rule_a_broader_earlier_rule_covers_is_flagged() -> None:
    policy = _policy(
        Rule(id="broad", action=Action.BLOCK, condition=Condition(labels=frozenset({"PHONE"}))),
        Rule(
            id="narrow",
            action=Action.MASK,
            condition=Condition(labels=frozenset({"PHONE"}), destinations=frozenset({"x"})),
        ),
    )
    findings = PolicyEngine(policy).lint()
    assert any(f.code == "unreachable" and f.rule_id == "narrow" for f in findings)


# ----------------------------------------------------- order-sensitive pairs


def test_two_rules_that_disagree_on_a_shared_request_are_reported_with_a_witness() -> None:
    policy = _policy(
        Rule(
            id="allow-inside",
            action=Action.ALLOW,
            condition=Condition(destinations=frozenset({"inside"}), max_confidence=0.5),
        ),
        Rule(id="review-all", action=Action.REVIEW, condition=Condition(max_confidence=0.5)),
    )
    findings = PolicyEngine(policy).lint()
    order = [f for f in findings if f.code in ("order-sensitive", "order-pinned")]
    assert order, "an allow above a broader review over the same span must be reported"
    witness = order[0].witness
    assert witness is not None
    # The witness is a real request the engine actually resolves to the earlier rule.
    action, rule_id, _ = PolicyEngine(policy).decide_label(
        witness["label"],
        float(witness["confidence"]),
        __import__("sensitiveguard").RequestContext(
            destination=witness["destination"],
            caller_role=witness["caller_role"],
            purpose=witness["purpose"],
            kind=witness["kind"],
        ),
    )
    assert rule_id == order[0].rule_id


def test_an_expectation_downgrades_order_sensitive_to_pinned() -> None:
    from sensitiveguard.policy.model import Expectation, RequestContext

    condition_low = Condition(destinations=frozenset({"inside"}), max_confidence=0.5)
    rules = (
        Rule(id="allow-inside", action=Action.ALLOW, condition=condition_low),
        Rule(id="review-all", action=Action.REVIEW, condition=Condition(max_confidence=0.5)),
    )
    pinned = Policy(
        name="t",
        version="1",
        rules=rules,
        expectations=(
            Expectation(
                name="stays inside",
                label="PHONE",
                confidence=0.2,
                context=RequestContext(destination="inside", caller_role="agent", purpose="p"),
                expect_action=Action.ALLOW,
                expect_rule="allow-inside",
            ),
        ),
    )
    codes = {f.code for f in PolicyEngine(pinned).lint()}
    assert "order-pinned" in codes
    assert "order-sensitive" not in codes


def test_the_witness_search_does_not_give_up_on_a_free_dimension() -> None:
    """A dimension no rule constrains still has to be searched, not skipped.

    Neither rule here names a caller role and the policy names none anywhere, so
    that dimension is free. An earlier version of the search returned no
    candidates for a free dimension and so found no conflict — the bug this pins.
    """

    policy = _policy(
        # Both reachable: the first needs a settled confidence, the second matches
        # any, so the second is not covered by the first and vice versa.
        Rule(
            id="allow-settled",
            action=Action.ALLOW,
            condition=Condition(labels=frozenset({"PHONE"}), destinations=frozenset({"x"}), min_confidence=0.5),
        ),
        Rule(
            id="review-any",
            action=Action.REVIEW,
            condition=Condition(labels=frozenset({"PHONE"}), destinations=frozenset({"x"})),
        ),
    )
    order = [f for f in PolicyEngine(policy).lint() if f.code.startswith("order")]
    assert order, "the free caller-role dimension must not make the pair look conflict-free"
    witness = order[0].witness
    assert witness is not None
    assert witness["caller_role"] == UNCONSTRAINED


# ------------------------------------------------- the shipped policies lint clean


@pytest.mark.parametrize("name", ["default_policy", "airgap_agent_r", "agent_egress"])
def test_the_bundled_policies_pass_the_lint(name: str) -> None:

    root = DEFAULT_POLICY_PATH.parent
    path = DEFAULT_POLICY_PATH if name == "default_policy" else root / f"{name}.yaml"
    policy = load_policy(path)  # strict load: raises if an error-level finding exists
    errors = [f for f in PolicyEngine(policy).lint() if f.severity == "error"]
    assert errors == []
    assert PolicyEngine(policy).self_test() == []


# -------------------------------------------------- the half-open interval


def test_the_confidence_boundary_belongs_to_exactly_one_side() -> None:
    """0.5 must not be claimed by both a >=0.5 rule and a <0.5 rule."""

    from sensitiveguard.policy.model import RequestContext

    policy = _policy(
        Rule(id="settled", action=Action.MASK, condition=Condition(min_confidence=0.5)),
        Rule(id="unsettled", action=Action.REVIEW, condition=Condition(max_confidence=0.5)),
    )
    engine = PolicyEngine(policy)
    ctx = RequestContext(destination="x", caller_role="agent", purpose="p")
    # Exactly at the boundary -> the settled rule, and nothing order-sensitive.
    _, rule_id, _ = engine.decide_label("PHONE", 0.5, ctx)
    assert rule_id == "settled"
    assert [f for f in engine.lint() if f.code.startswith("order")] == []


def test_a_degenerate_interval_is_refused() -> None:
    with pytest.raises(ValueError, match="never match"):
        Condition(min_confidence=0.5, max_confidence=0.5)
