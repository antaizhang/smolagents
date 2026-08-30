"""End to end: the four layers together, and the reviewer that checks the output."""

from __future__ import annotations

import pytest
from conftest import ScriptedPhoneAgent

from sensitiveguard.detection import CapabilityRouter, PhoneAgentDetector
from sensitiveguard.facts import ContentKind
from sensitiveguard.pipeline import SensitiveGuard
from sensitiveguard.policy import Action
from sensitiveguard.quarantine import Quarantine
from sensitiveguard.review import OutputReviewer
from sensitiveguard.transform import Disposition, DispositionRouter, TokenVault


PHONE = "13800138000"
EMAIL = "zhang.san@example.com"
ID_CARD = "110101199003072615"
CASE = f"客户 手机 {PHONE}，邮箱 {EMAIL}，请在本周内回访并记录结果。"


@pytest.fixture
def guard() -> SensitiveGuard:
    return SensitiveGuard(escalation=PhoneAgentDetector(ScriptedPhoneAgent()))


# ------------------------------------------- the same fact, four destinations


def test_a_phone_headed_for_an_external_model_is_masked(guard: SensitiveGuard) -> None:
    result = guard.inspect(CASE, destination="external_llm", caller_role="agent", purpose="tool_call")

    assert result.released
    assert PHONE not in result.released_text
    assert "138****8000" in result.released_text
    assert "请在本周内回访并记录结果" in result.released_text
    assert [d.action for d in result.decisions] == [Action.MASK, Action.MASK]


def test_the_same_phone_headed_for_an_internal_log_is_hashed(guard: SensitiveGuard) -> None:
    result = guard.inspect(CASE, destination="internal_log", caller_role="service", purpose="observability")

    assert PHONE not in result.released_text
    assert "<PHONE:sha256:" in result.released_text
    assert all(d.action is Action.HASH for d in result.decisions)


def test_the_same_phone_in_the_users_own_document_is_left_alone(guard: SensitiveGuard) -> None:
    result = guard.inspect(CASE, destination="user_document", caller_role="user", purpose="editing")

    assert result.released_text == CASE
    assert all(d.action is Action.ALLOW for d in result.decisions)


def test_an_id_number_is_blocked_at_every_exit_and_raises_an_alert(guard: SensitiveGuard) -> None:
    for destination, role, purpose in [
        ("external_llm", "agent", "tool_call"),
        ("internal_log", "service", "observability"),
        ("user_document", "user", "editing"),
    ]:
        result = guard.inspect(f"身份证 {ID_CARD}", destination=destination, caller_role=role, purpose=purpose)

        assert result.blocked
        assert result.released_text is None
        assert [d.label for d in result.alerts] == ["ID_CARD"]


def test_a_hashed_log_key_is_stable_across_formats(guard: SensitiveGuard) -> None:
    """What the hash is for: two records about one subscriber still join."""

    def key(text: str) -> str:
        result = guard.inspect(text, destination="internal_log", caller_role="service", purpose="observability")
        return result.released_text

    assert key(f"手机 {PHONE}").split("手机 ")[1] == key("手机 +86 138 0013 8000").split("手机 ")[1]


# ------------------------------------------------------------ hide and seek


def test_a_round_trip_tokenises_on_the_way_out_and_restores_on_the_way_in(guard: SensitiveGuard) -> None:
    outbound = guard.inspect(CASE, destination="external_llm", caller_role="agent", purpose="round_trip")

    assert PHONE not in outbound.released_text
    assert all(d.action is Action.TOKENIZE and d.restore_on_response for d in outbound.decisions)

    token = outbound.released_text.split("手机 ")[1].split("，")[0]
    reply = f"已安排回访，请拨打 {token}。"
    restored = guard.restore(reply)

    assert restored.text == f"已安排回访，请拨打 {PHONE}。"
    assert restored.restored == 1


def test_a_masked_value_has_no_way_back(guard: SensitiveGuard) -> None:
    masked = guard.inspect(CASE, destination="external_llm", caller_role="agent", purpose="tool_call")
    reply = f"回访完成：{masked.released_text}"

    assert guard.restore(reply).text == reply
    assert PHONE not in guard.restore(reply).text


def test_reversibility_is_the_policys_call_not_the_transformers(guard: SensitiveGuard) -> None:
    round_trip = guard.inspect(CASE, destination="external_llm", caller_role="agent", purpose="round_trip")
    one_way = guard.inspect(CASE, destination="external_llm", caller_role="agent", purpose="tool_call")

    assert all(d.reversible for d in round_trip.decisions)
    assert not any(d.reversible for d in one_way.decisions)


def test_repeated_mentions_of_one_value_share_one_token(guard: SensitiveGuard) -> None:
    result = guard.inspect(
        f"主号 {PHONE}，紧急联系同样是 {PHONE}",
        destination="external_llm",
        caller_role="agent",
        purpose="round_trip",
    )
    tokens = {item.replacement for item in result.disposition.applied}

    assert len(tokens) == 1
    assert result.released_text.count(tokens.pop()) == 2


# ------------------------------------------------------------- cost control


def test_the_common_path_costs_no_model_call() -> None:
    agent = ScriptedPhoneAgent()
    guard = SensitiveGuard(escalation=PhoneAgentDetector(agent))

    for _ in range(5):
        guard.inspect(CASE, destination="external_llm", caller_role="agent", purpose="tool_call")

    assert agent.calls == 0


def test_only_the_ambiguous_span_costs_one(guard: SensitiveGuard) -> None:
    result = guard.inspect(
        f"清晰 {PHONE}，混淆 138.0013.8001",
        destination="external_llm",
        caller_role="agent",
        purpose="tool_call",
    )

    assert result.detection.escalation_calls == 1
    assert "138.0013.8001" not in result.released_text


# ------------------------------------------------------------ the reviewer


def test_the_reviewer_passes_output_that_actually_masked(guard: SensitiveGuard) -> None:
    result = guard.inspect(CASE, destination="external_llm", caller_role="agent", purpose="tool_call")

    assert result.review is not None
    assert result.review.ok
    assert result.review.leaks == ()


def test_the_reviewer_catches_a_mask_that_did_not_happen() -> None:
    """The failure the decision path cannot show you: the verdict was right and the output is wrong."""

    guard = SensitiveGuard()
    sealed = Quarantine(CASE)
    report = guard.detector_agent.inspect(sealed)
    decisions = guard.guard_agent.decide(
        report,
        guard.inspect(CASE, destination="external_llm", caller_role="agent", purpose="tool_call").context,
    )
    botched = Disposition(text=CASE, applied=(), allowed=())

    review = guard.reviewer.review(sealed, botched, decisions)

    assert not review.ok
    assert {leak.label for leak in review.leaks} == {"PHONE", "EMAIL"}
    assert all(leak.form == "verbatim" for leak in review.leaks)


def test_the_reviewer_catches_a_value_that_came_back_in_another_format() -> None:
    guard = SensitiveGuard()
    text = f"手机 {PHONE}"
    sealed = Quarantine(text)
    context = guard.inspect(text, destination="external_llm", caller_role="agent", purpose="tool_call").context
    decisions = guard.guard_agent.decide(guard.detector_agent.inspect(sealed), context)
    reformatted = Disposition(text="手机 138****8000（原始记录 138 0013 8000）", applied=())

    review = guard.reviewer.review(sealed, reformatted, decisions)

    assert not review.ok
    assert [leak.form for leak in review.leaks] == ["reformatted"]


def test_the_reviewer_objects_when_nothing_readable_survives() -> None:
    guard = SensitiveGuard()
    result = guard.inspect(PHONE, destination="external_llm", caller_role="agent", purpose="tool_call")

    assert result.review is not None
    assert result.review.over_redacted
    assert not result.review.ok
    assert any("survived the rewrite" in note for note in result.review.notes)


def test_a_long_document_with_a_little_redaction_is_not_over_redacted(guard: SensitiveGuard) -> None:
    text = "本次回访记录如下，客户对服务表示满意，希望下季度继续合作。" * 4 + f" 联系电话 {PHONE}"
    result = guard.inspect(text, destination="external_llm", caller_role="agent", purpose="tool_call")

    assert result.review is not None
    assert result.review.ok
    assert result.review.redacted_ratio < 0.1


def test_withheld_content_gives_the_reviewer_nothing_to_do(guard: SensitiveGuard) -> None:
    result = guard.inspect(f"身份证 {ID_CARD}", destination="external_llm", caller_role="agent", purpose="tool_call")

    assert result.review is not None
    assert result.review.ok
    assert "withheld" in result.review.describe()


def test_the_reviewer_can_be_tuned_per_deployment() -> None:
    router = CapabilityRouter.build()
    with pytest.raises(ValueError, match="max_redacted_ratio"):
        OutputReviewer(router, max_redacted_ratio=0)


# ------------------------------------------------------------------ routing


def test_a_credential_in_code_is_blocked_but_the_same_bytes_as_prose_are_not() -> None:
    guard = SensitiveGuard()
    payload = 'API_KEY = "abcdef0123456789xyz"'

    as_code = guard.inspect(
        payload, destination="external_llm", caller_role="agent", purpose="tool_call", kind=ContentKind.CODE
    )
    as_text = guard.inspect(payload, destination="external_llm", caller_role="agent", purpose="tool_call")

    assert as_code.blocked
    assert not as_text.blocked


def test_ocr_confidence_changes_the_verdict_not_just_the_number() -> None:
    """A fact drawn from a scan is worth less, and the rules get to say so."""

    guard = SensitiveGuard()
    scanned = guard.inspect(
        "扫描件 手机 138.0013.8000",
        destination="external_llm",
        caller_role="agent",
        purpose="tool_call",
        kind=ContentKind.IMAGE_OCR,
    )

    (decision,) = scanned.decisions
    assert decision.confidence < 0.5
    assert decision.action is Action.REVIEW


# --------------------------------------------------------------- audit trail


def test_one_pass_explains_itself_from_fact_to_output(guard: SensitiveGuard) -> None:
    result = guard.inspect(CASE, destination="external_llm", caller_role="agent", purpose="tool_call")
    explanation = result.explain()

    assert result.ref in explanation
    assert "detection kind=text" in explanation
    assert "MATCH phone-external-egress" in explanation
    assert "disposition released" in explanation
    assert "review ok" in explanation
    assert PHONE not in explanation


def test_a_guard_reports_its_own_configuration(guard: SensitiveGuard) -> None:
    description = guard.describe()

    assert "default-egress-policy@" in description
    assert "capability routes:" in description
    assert "image_ocr" in description


def test_a_guard_runs_its_policys_expectations(guard: SensitiveGuard) -> None:
    assert guard.self_test() == []


def test_the_pipeline_seals_loose_text_on_the_way_in(guard: SensitiveGuard) -> None:
    result = guard.inspect(CASE, destination="external_llm", caller_role="agent", purpose="tool_call")

    assert result.ref.startswith("q-")
    assert result.kind == "text"


def test_review_can_be_turned_off_without_changing_the_verdict() -> None:
    guard = SensitiveGuard(review_output=False)
    result = guard.inspect(CASE, destination="external_llm", caller_role="agent", purpose="tool_call")

    assert result.review is None
    assert PHONE not in result.released_text


def test_a_shared_vault_lets_a_caller_own_the_session() -> None:
    vault = TokenVault()
    guard = SensitiveGuard(vault=vault)
    guard.inspect(CASE, destination="external_llm", caller_role="agent", purpose="round_trip")

    assert len(vault) == 2
    vault.clear()
    assert len(vault) == 0


def test_the_guard_and_its_dispatcher_can_never_hold_two_different_vaults() -> None:
    """Otherwise `restore` would look in the wrong place, one round trip later."""

    supplied = DispositionRouter(vault=TokenVault())
    guard = SensitiveGuard(vault=TokenVault(), dispatcher=supplied)

    assert guard.vault is supplied.vault

    result = guard.inspect(CASE, destination="external_llm", caller_role="agent", purpose="round_trip")
    token = result.released_text.split("手机 ")[1].split("，")[0]

    assert guard.restore(token).text == PHONE
