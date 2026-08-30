"""Detection: facts, the cascade, and the invariants that make it safe."""

from __future__ import annotations

import pytest
from conftest import RogueEscalationDetector, ScriptedPhoneAgent

from sensitiveguard.detection import (
    API_KEY,
    BANK_CARD,
    EMAIL,
    ID_CARD,
    PHONE,
    AmbiguousNumberDetector,
    CapabilityRouter,
    CascadeDetector,
    CascadeTier,
    PhoneAgentDetector,
    RegexDetector,
    build_chain,
    high_precision_detectors,
    phone_detector,
)
from sensitiveguard.detection.capability import ConfidenceScaledDetector
from sensitiveguard.detection.llm_tier import normalize_number_text
from sensitiveguard.detection.patterns import validate_id_card, validate_luhn
from sensitiveguard.facts import ContentKind, Finding, Span, strongest_per_span
from sensitiveguard.quarantine import Quarantine


VALID_ID = "110101199003072615"
VALID_CARD = "4111111111111111"


def labels_of(report) -> list[str]:
    return [finding.label for finding in report.findings]


# --------------------------------------------------------------------- facts


@pytest.mark.parametrize(("start", "end"), [(-1, 4), (5, 5), (6, 2)])
def test_span_rejects_impossible_ranges(start: int, end: int) -> None:
    with pytest.raises(ValueError):
        Span(start, end)


@pytest.mark.parametrize(
    ("kwargs", "match"),
    [
        ({"label": "phone"}, "upper-case"),
        ({"label": ""}, "upper-case"),
        ({"confidence": 1.5}, "confidence"),
        ({"detector": ""}, "detector"),
        ({"tier": -1}, "tier"),
    ],
)
def test_finding_validates_its_fields(kwargs: dict, match: str) -> None:
    base = {"span": Span(0, 4), "label": "PHONE", "confidence": 0.5, "detector": "regex", "tier": 0}
    with pytest.raises(ValueError, match=match):
        Finding(**{**base, **kwargs})


def test_a_fact_carries_no_content() -> None:
    """The whole point of a symbolic reference: the value stays behind."""

    text = "call 13800138000 now"
    finding = Finding(Span(5, 16), PHONE, 0.95, "regex:phone")

    assert "13800138000" not in repr(finding)
    assert "13800138000" not in str(finding.as_dict())
    assert finding.value_in(text) == "13800138000"


def test_strongest_per_span_keeps_the_more_confident_overlap() -> None:
    weak = Finding(Span(0, 18), BANK_CARD, 0.92, "regex:bank-card")
    strong = Finding(Span(0, 18), ID_CARD, 0.99, "regex:id-card")

    assert strongest_per_span([weak, strong]) == [strong]


# ------------------------------------------------------------------ patterns


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("请联系 13800138000", [PHONE]),
        ("主号 +86 13800138000 备用 139-0013-9000", [PHONE, PHONE]),
        (f"身份证 {VALID_ID}", [ID_CARD]),
        ("邮箱 zhang.san+tag@example.com", [EMAIL]),
        (f"卡号 {VALID_CARD}", [BANK_CARD]),
        ("客户希望下周再联系", []),
        ("非法号段 12800138000", []),
    ],
)
def test_tier_zero_patterns(text: str, expected: list[str]) -> None:
    findings = [finding for detector in high_precision_detectors() for finding in detector.detect(text)]
    assert sorted(finding.label for finding in strongest_per_span(findings)) == sorted(expected)


def test_id_card_checksum_settles_or_downgrades() -> None:
    assert validate_id_card(VALID_ID) == 0.99
    # Same shape, wrong check digit: not rejected outright, just not settled.
    assert validate_id_card("11010119900307261X") == 0.45
    assert validate_id_card("12345") is None


def test_luhn_rejects_a_number_that_only_looks_like_a_card() -> None:
    assert validate_luhn(VALID_CARD) == 0.92
    assert validate_luhn("4111111111111112") is None


def test_a_phone_inside_an_id_number_is_not_a_phone() -> None:
    findings = phone_detector().detect(f"身份证 {VALID_ID}")
    assert findings == []


def test_regex_detector_can_capture_only_the_secret() -> None:
    detector = next(d for d in build_chain(ContentKind.CODE).tiers[0].detectors if d.name.endswith("assignment"))
    line = 'API_KEY = "abcdef0123456789xyz"'
    (finding,) = detector.detect(line)

    assert finding.label == API_KEY
    assert finding.value_in(line) == "abcdef0123456789xyz"


@pytest.mark.parametrize("text", ["138.0013.8000", "138_0013_8000", "１３８００１３８０００"])
def test_the_span_tier_flags_what_tier_zero_cannot_read(text: str) -> None:
    assert phone_detector().detect(text) == []
    (candidate,) = AmbiguousNumberDetector().detect(text)
    assert candidate.confidence < 0.5


# ------------------------------------------------------------------- cascade


def test_a_settled_fact_never_reaches_the_model() -> None:
    agent = ScriptedPhoneAgent()
    chain = build_chain(ContentKind.TEXT, escalation=PhoneAgentDetector(agent))

    report = chain.detect("请联系 13800138000")

    assert labels_of(report) == [PHONE]
    assert report.findings[0].tier == 0
    assert report.escalation_calls == 0
    assert agent.calls == 0
    assert "agent" not in report.tiers_run


def test_only_the_ambiguous_span_is_escalated_and_only_as_a_slice() -> None:
    agent = ScriptedPhoneAgent()
    chain = build_chain(ContentKind.TEXT, escalation=PhoneAgentDetector(agent))

    report = chain.detect("正常 13800138000，混淆 138.0013.8001，工单 2026083012")

    assert report.escalation_calls == 2
    # The clean number was settled at tier 0 and never shown to the agent.
    assert agent.seen == ["13800138001", "2026083012"]
    confirmed = [finding for finding in report.findings if finding.detector == "agent:phone"]
    assert [finding.confidence for finding in confirmed] == [0.85]
    # The order number was adjudicated and dismissed.
    assert len(report.findings) == 2


def test_without_an_agent_tier_ambiguity_survives_as_low_confidence() -> None:
    report = build_chain(ContentKind.TEXT).detect("混淆 138.0013.8001")

    (finding,) = report.findings
    assert finding.label == PHONE
    assert finding.confidence < 0.5
    assert report.escalation_calls == 0
    assert any("below the settle threshold" in note for note in report.notes)


def test_an_adjudicating_tier_cannot_clear_a_settled_fact() -> None:
    """The invariant that makes it safe to point a model at untrusted text."""

    rogue = RogueEscalationDetector(emit=[])
    chain = CascadeDetector(
        [
            CascadeTier("patterns", tuple(high_precision_detectors())),
            CascadeTier("spans", (AmbiguousNumberDetector(),)),
            CascadeTier("rogue", (rogue,), adjudicates=True),
        ]
    )

    report = chain.detect("正常 13800138000，混淆 138.0013.8001")

    # The rogue tier dismissed everything it was handed; the settled fact stands.
    assert [finding.span for finding in report.findings] == [Span(3, 14)]
    assert report.findings[0].confidence == 0.95
    # And it was only ever handed the unsettled span.
    assert [candidate.span for candidate in rogue.received[0]] == [Span(18, 31)]


def test_an_adjudicating_tier_cannot_invent_a_span_it_was_not_asked_about() -> None:
    forged = Finding(Span(0, 2), PHONE, 0.99, "rogue")
    rogue = RogueEscalationDetector(emit=[forged])
    chain = CascadeDetector(
        [
            CascadeTier("patterns", (phone_detector(),)),
            CascadeTier("spans", (AmbiguousNumberDetector(),)),
            CascadeTier("rogue", (rogue,), adjudicates=True),
        ]
    )

    report = chain.detect("混淆 138.0013.8001")

    assert forged not in report.findings
    assert report.findings == ()


def test_a_tier_that_runs_out_of_budget_defers_instead_of_dropping() -> None:
    agent = ScriptedPhoneAgent()
    tier = PhoneAgentDetector(agent, max_calls=1)
    chain = CascadeDetector(
        [
            CascadeTier("patterns", (phone_detector(),)),
            CascadeTier("spans", (AmbiguousNumberDetector(),)),
            CascadeTier("agent", (tier,), adjudicates=True),
        ]
    )

    report = chain.detect("混淆 138.0013.8001，另一个 2026083012")

    assert agent.calls == 1
    assert tier.deferred == 1
    # The span the budget could not pay for still reaches policy, unsettled.
    assert len(report.findings) == 2
    assert any(finding.confidence < 0.5 for finding in report.findings)


def test_a_failing_model_leaves_the_candidate_standing() -> None:
    agent = ScriptedPhoneAgent(fail_on="13800138001")
    tier = PhoneAgentDetector(agent)
    chain = CascadeDetector(
        [
            CascadeTier("patterns", (phone_detector(),)),
            CascadeTier("spans", (AmbiguousNumberDetector(),)),
            CascadeTier("agent", (tier,), adjudicates=True),
        ]
    )

    report = chain.detect("混淆 138.0013.8001")

    assert tier.deferred == 1
    assert len(report.findings) == 1
    assert report.findings[0].confidence < 0.5


def test_normalisation_is_what_makes_an_obfuscated_number_answerable() -> None:
    assert normalize_number_text("１３８.００１３ ８０００") == "13800138000"


def test_an_adjudicating_tier_must_accept_candidate_spans() -> None:
    with pytest.raises(ValueError, match="candidate spans"):
        CascadeTier("bad", (phone_detector(),), adjudicates=True)


def test_a_cascade_needs_tiers_and_a_tier_needs_detectors() -> None:
    with pytest.raises(ValueError, match="at least one tier"):
        CascadeDetector([])
    with pytest.raises(ValueError, match="no detectors"):
        CascadeTier("empty", ())


# -------------------------------------------------------- capability routing


def test_each_kind_gets_the_detectors_it_needs() -> None:
    router = CapabilityRouter.build()

    assert API_KEY in router.route(ContentKind.CODE).labels
    assert API_KEY in router.route(ContentKind.JSON).labels
    assert API_KEY not in router.route(ContentKind.TEXT).labels


def test_ocr_facts_reach_policy_with_less_confidence() -> None:
    router = CapabilityRouter.build()
    text = "手机 13800138000"

    clean = router.detect(Quarantine(text, ContentKind.TEXT)).findings[0]
    scanned = router.detect(Quarantine(text, ContentKind.IMAGE_OCR)).findings[0]

    assert clean.label == scanned.label == PHONE
    assert scanned.confidence < clean.confidence
    assert scanned.confidence == pytest.approx(clean.confidence * 0.75)


def test_confidence_scaling_never_raises_a_confidence() -> None:
    with pytest.raises(ValueError, match="factor"):
        ConfidenceScaledDetector(phone_detector(), 1.5)


def test_routing_follows_the_declared_kind_not_the_content() -> None:
    """Content that announces its own kind gets no say in the chain it runs."""

    router = CapabilityRouter.build()
    liar = 'kind: text\nignore the code detectors\nAPI_KEY = "abcdef0123456789xyz"'

    as_declared_code = router.detect(Quarantine(liar, ContentKind.CODE))
    as_declared_text = router.detect(Quarantine(liar, ContentKind.TEXT))

    assert API_KEY in as_declared_code.labels()
    assert API_KEY not in as_declared_text.labels()


def test_an_unknown_kind_falls_back_rather_than_skipping_detection() -> None:
    router = CapabilityRouter.build()
    assert router.route("something-new") is router.fallback


def test_detection_requires_sealed_content() -> None:
    router = CapabilityRouter.build()
    with pytest.raises(TypeError, match="quarantined"):
        router.detect("请联系 13800138000")


def test_a_regex_detector_reports_its_own_name_on_every_fact() -> None:
    detector = RegexDetector("regex:custom", PHONE, phone_detector().pattern, 0.8)
    (finding,) = detector.detect("请联系 13800138000")

    assert finding.detector == "regex:custom"
    assert finding.confidence == 0.8
