"""Transformation: handlers, the vault, and disposition routing."""

from __future__ import annotations

import pytest

from sensitiveguard.facts import ContentKind
from sensitiveguard.policy import Action, Decision, RequestContext
from sensitiveguard.quarantine import Quarantine
from sensitiveguard.transform import (
    DispositionRouter,
    HashHandler,
    MaskHandler,
    TokenVault,
    normalize_for_hash,
)


CONTEXT = RequestContext(destination="external_llm", caller_role="agent", purpose="tool_call")


def decision(
    label: str = "PHONE",
    action: Action = Action.MASK,
    span: tuple[int, int] = (0, 11),
    *,
    restore: bool = False,
    alert: bool = False,
    confidence: float = 0.95,
) -> Decision:
    return Decision(
        label=label,
        confidence=confidence,
        span=span,
        detector="regex",
        tier=0,
        action=action,
        rule_id=f"rule-{action.value}",
        reason="because the test says so",
        alert=alert,
        restore_on_response=restore,
        policy_label="test@1",
        policy_fingerprint="deadbeef",
        context=CONTEXT,
    )


# ----------------------------------------------------------------- masking


@pytest.mark.parametrize(
    ("label", "value", "expected"),
    [
        ("PHONE", "13800138000", "138****8000"),
        ("BANK_CARD", "4111111111111111", "************1111"),
        ("ID_CARD", "110101199003072615", "*" * 18),
        ("EMAIL", "zhang.san@example.com", "z********@example.com"),
        ("PHONE", "138", "***"),
    ],
)
def test_masking_keeps_shape_without_keeping_identity(label: str, value: str, expected: str) -> None:
    assert MaskHandler().apply(value, decision(label)) == expected


def test_masking_is_one_way() -> None:
    masked = MaskHandler().apply("13800138000", decision())
    assert "0013" not in masked


# ----------------------------------------------------------------- hashing


def test_the_same_subscriber_hashes_the_same_however_it_is_written() -> None:
    handler = HashHandler(salt=b"fixed-salt")
    variants = ["13800138000", "138 0013 8000", "+86-13800138000", "１３８００１３８０００"]

    keys = {handler.apply(value, decision()) for value in variants}

    assert len(keys) == 1
    assert "13800138000" not in keys.pop()


def test_a_hash_is_only_pseudonymous_because_of_the_salt() -> None:
    one = HashHandler(salt=b"deployment-one").apply("13800138000", decision())
    two = HashHandler(salt=b"deployment-two").apply("13800138000", decision())

    assert one != two


def test_email_normalisation_is_case_folding_not_digit_stripping() -> None:
    assert normalize_for_hash("Zhang.San@Example.COM", "EMAIL") == "zhang.san@example.com"


# ------------------------------------------------------------------- vault


def test_a_value_gets_one_stable_token_so_the_text_stays_coherent() -> None:
    vault = TokenVault()

    first = vault.tokenize("13800138000", "PHONE")
    second = vault.tokenize("13800138000", "PHONE")

    assert first == second
    assert "13800138000" not in first
    assert len(vault) == 1


def test_tokenisation_is_the_reversible_one() -> None:
    vault = TokenVault()
    token = vault.tokenize("13800138000", "PHONE")

    restoration = vault.restore_text(f"call {token} tomorrow")

    assert restoration.text == "call 13800138000 tomorrow"
    assert restoration.restored == 1


def test_a_pseudonym_the_policy_did_not_make_restorable_stays_one_way() -> None:
    vault = TokenVault()
    token = vault.tokenize("13800138000", "PHONE", restorable=False)

    assert vault.restore(token) is None
    assert len(vault) == 0
    # Still stable, so repeated mentions read consistently.
    assert vault.tokenize("13800138000", "PHONE", restorable=False) == token


def test_an_unknown_token_is_reported_rather_than_deleted() -> None:
    restoration = TokenVault().restore_text("call [[PHONE_0123abcd]] back")

    assert restoration.text == "call [[PHONE_0123abcd]] back"
    assert restoration.unknown_tokens == ("[[PHONE_0123abcd]]",)
    assert restoration.restored == 0


def test_clearing_the_vault_ends_the_session() -> None:
    vault = TokenVault()
    token = vault.tokenize("13800138000", "PHONE")
    vault.clear()

    assert vault.restore(token) is None


# ------------------------------------------------------ disposition routing


def test_several_spans_are_rewritten_without_corrupting_each_other() -> None:
    text = "a 13800138000 b 13900139000 c"
    sealed = Quarantine(text)
    decisions = [decision(span=(2, 13)), decision(span=(16, 27))]

    result = DispositionRouter().apply(sealed, decisions)

    assert result.text == "a 138****8000 b 139****9000 c"
    assert [item.decision.span for item in result.applied] == [(2, 13), (16, 27)]


def test_a_replacement_of_a_different_length_still_keeps_later_spans_valid() -> None:
    text = "a 13800138000 b 13900139000 c"
    decisions = [decision(span=(2, 13), action=Action.HASH), decision(span=(16, 27), action=Action.HASH)]

    result = DispositionRouter(hash_salt=b"fixed").apply(Quarantine(text), decisions)

    assert result.text.startswith("a <PHONE:sha256:")
    assert result.text.endswith(" c")
    assert "13800138000" not in result.text
    assert "13900139000" not in result.text


def test_a_block_withholds_the_content_entirely() -> None:
    result = DispositionRouter().apply(
        Quarantine("id 110101199003072615"), [decision("ID_CARD", Action.BLOCK, (3, 21), alert=True)]
    )

    assert result.text is None
    assert not result.released
    assert result.withheld
    assert [d.label for d in result.blocked] == ["ID_CARD"]
    assert [d.label for d in result.alerts] == ["ID_CARD"]


def test_a_block_does_not_leave_the_value_sitting_in_the_vault() -> None:
    """Nothing is released, so nothing should be recorded for a round trip."""

    vault = TokenVault()
    router = DispositionRouter(vault=vault)
    decisions = [
        decision(span=(0, 11), action=Action.TOKENIZE, restore=True),
        decision("ID_CARD", Action.BLOCK, (12, 30)),
    ]

    router.apply(Quarantine("13800138000 110101199003072615"), decisions)

    assert len(vault) == 0


def test_review_holds_the_content_without_calling_it_blocked() -> None:
    result = DispositionRouter().apply(Quarantine("13800138000"), [decision(action=Action.REVIEW)])

    assert result.text is None
    assert result.held and not result.blocked
    assert "held for review" in result.describe()


def test_allow_releases_the_text_untouched() -> None:
    result = DispositionRouter().apply(Quarantine("call 13800138000"), [decision(span=(5, 16), action=Action.ALLOW)])

    assert result.text == "call 13800138000"
    assert result.applied == ()
    assert [d.rule_id for d in result.allowed] == ["rule-allow"]


def test_two_verdicts_on_the_same_characters_resolve_to_the_more_protective() -> None:
    router = DispositionRouter()
    overlapping = [decision("PHONE", Action.MASK, (0, 11)), decision("ID_CARD", Action.BLOCK, (0, 11))]

    result = router.apply(Quarantine("13800138000"), overlapping)

    assert result.text is None
    assert [d.label for d in result.blocked] == ["ID_CARD"]
    assert [d.label for d in result.superseded] == ["PHONE"]


def test_disposition_requires_sealed_content() -> None:
    with pytest.raises(TypeError, match="quarantined"):
        DispositionRouter().apply("13800138000", [decision()])


def test_a_missing_handler_fails_loudly_rather_than_passing_the_value_through() -> None:
    router = DispositionRouter(handlers={})

    with pytest.raises(KeyError, match="no handler registered"):
        router.apply(Quarantine("13800138000", ContentKind.TEXT), [decision()])
