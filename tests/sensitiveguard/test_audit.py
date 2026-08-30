"""The audit bus: it records where values went without becoming a place they go."""

from __future__ import annotations

from sensitiveguard import SensitiveGuard
from sensitiveguard.audit import FACT_ONLY_CHANNELS, AuditBus, Channel


def test_the_bus_records_a_digest_not_the_value() -> None:
    bus = AuditBus()
    secret = "13800138000"
    bus.record(Channel.C1_INGRESS, "t", values=[secret])
    event = bus.events[0]
    assert secret not in repr(event)
    assert secret not in str(event.as_dict())
    # But the digest is enough to answer the question a leak probe asks.
    assert bus.crossed(secret, Channel.C1_INGRESS)


def test_a_value_that_never_crossed_reads_as_absent() -> None:
    bus = AuditBus()
    bus.record(Channel.C6_EGRESS, "t", values=["something else"])
    assert bus.channels_carrying("13800138000") == ()


def test_short_values_are_not_tracked_to_avoid_collisions() -> None:
    bus = AuditBus(min_digest_length=4)
    bus.record(Channel.C1_INGRESS, "t", values=["ab", "abcd"])
    assert not bus.crossed("ab", Channel.C1_INGRESS)
    assert bus.crossed("abcd", Channel.C1_INGRESS)


def test_two_buses_do_not_share_a_digest_space() -> None:
    """Per-bus salt: a digest means something only inside the run that made it."""

    one, two = AuditBus(), AuditBus()
    assert one.digest("13800138000") != two.digest("13800138000")


def test_the_pipeline_records_every_internal_channel() -> None:
    bus = AuditBus()
    guard = SensitiveGuard().with_audit(bus)
    result = guard.inspect("call 13800138000", destination="external_llm", caller_role="agent", purpose="round_trip")
    assert result.released
    summary = bus.summary()
    assert summary[Channel.C1_INGRESS.value] == 1
    assert summary[Channel.C2_DETECTOR_TO_POLICY.value] == 1
    assert summary[Channel.C3_POLICY_TO_TRANSFORM.value] == 1
    # A round trip tokenises, so a restorable mapping is written on C4.
    assert summary[Channel.C4_VAULT_MAPPING.value] == 1


def test_a_facts_only_channel_never_reports_a_raw_value() -> None:
    """The structural claim, checked as a claim: C2/C3 carry no raw value."""

    bus = AuditBus()
    guard = SensitiveGuard().with_audit(bus)
    guard.inspect(
        "id 110101199003072615 phone 13800138000",
        destination="internal_log",
        caller_role="service",
        purpose="observability",
    )
    for channel in FACT_ONLY_CHANNELS:
        for event in bus.events_on(channel):
            assert not event.carries_raw
    assert bus.fact_only_violations() == ()


def test_each_run_gets_its_own_bus() -> None:
    guard = SensitiveGuard()
    a, b = AuditBus(), AuditBus()
    guard.with_audit(a).inspect(
        "call 13800138000", destination="external_llm", caller_role="agent", purpose="tool_call"
    )
    assert len(a) > 0
    assert len(b) == 0
