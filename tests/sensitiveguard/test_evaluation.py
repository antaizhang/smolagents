"""Offline tests for SensitiveGuard model- and agent-layer evaluation."""

from __future__ import annotations

import json

import pytest

from sensitiveguard.eval import (
    BASELINES,
    BENCHMARKS,
    ZERO_DENOMINATOR_SEMANTICS,
    ZERO_DENOMINATOR_VALUES,
    AgentEvalSample,
    AgentMetrics,
    Baseline,
    BaselineConfig,
    BenchmarkName,
    EntitySpan,
    PRFScore,
    aggregate_agent_metrics,
    evaluate_entities,
    evaluate_entity_corpus,
    get_baseline,
    get_benchmark,
    list_baselines,
    list_benchmarks,
)
from sensitiveguard.models import Finding, Severity


def test_entity_metrics_use_exact_normalized_label_and_span_matching():
    expected = [EntitySpan("NAME", 0, 2), EntitySpan("IDCARD", 10, 28)]
    predicted = [
        EntitySpan("name", 0, 2),
        EntitySpan("MOBILE", 10, 28),
        EntitySpan("EMAIL", 30, 40),
    ]

    metrics = evaluate_entities(expected, predicted)

    assert metrics.true_positives == 1
    assert metrics.false_positives == 2
    assert metrics.false_negatives == 1
    assert metrics.precision == pytest.approx(1 / 3)
    assert metrics.recall == pytest.approx(1 / 2)
    assert metrics.f1 == pytest.approx(0.4)
    assert metrics.per_label["NAME"].f1 == 1.0
    assert metrics.per_label["IDCARD"].recall == 0.0
    assert metrics.per_label["MOBILE"].precision == 0.0
    assert metrics.to_dict()["matching"] == "exact_label_and_span"


def test_entity_metrics_accept_finding_like_objects_and_micro_aggregate_corpus():
    finding = Finding(
        label="EMAIL",
        start=4,
        end=11,
        score=0.9,
        severity=Severity.MEDIUM,
        detector="fake",
        value="a@b.com",
    )
    corpus = [
        ([finding], [{"label": "email", "start": 4, "end": 11}]),
        ([EntitySpan("NAME", 0, 2)], []),
    ]

    metrics = evaluate_entity_corpus(corpus)

    assert metrics.overall == PRFScore(true_positives=1, false_positives=0, false_negatives=1)
    assert metrics.precision == 1.0
    assert metrics.recall == 0.5
    assert set(metrics.per_label) == {"EMAIL", "NAME"}


def test_entity_metric_zero_denominators_and_duplicates_are_explicit():
    empty = evaluate_entities([], [])
    missing = evaluate_entities([EntitySpan("NAME", 0, 1)], [])
    spurious = evaluate_entities([], [EntitySpan("NAME", 0, 1)])

    assert (empty.precision, empty.recall, empty.f1) == (1.0, 1.0, 1.0)
    assert (missing.precision, missing.recall, missing.f1) == (0.0, 0.0, 0.0)
    assert (spurious.precision, spurious.recall, spurious.f1) == (0.0, 1.0, 0.0)
    with pytest.raises(ValueError, match="duplicate"):
        evaluate_entities([], [EntitySpan("NAME", 0, 1), EntitySpan("name", 0, 1)])


def _agent_samples():
    first = AgentEvalSample(
        sample_id="sample-1",
        task_success=True,
        expected_sensitive_entities=4,
        detected_sensitive_entities=3,
        policy_decisions_total=4,
        policy_decisions_correct=3,
        forbidden_entities_encountered=4,
        forbidden_entities_disclosed=1,
        tool_entities_at_risk=2,
        tool_entities_leaked=1,
        memory_entities_at_risk=2,
        memory_entities_leaked=0,
        final_entities_at_risk=2,
        final_entities_leaked=0,
        sensitive_entities_acquired=4,
        unnecessary_sensitive_entities_acquired=1,
        data_items_acquired=5,
        necessary_data_items_acquired=4,
        utility_preserved=True,
        legitimate_task=True,
        incorrectly_blocked=False,
        attack_attempt=True,
        attack_succeeded=False,
        cumulative_entities_at_risk=4,
        cumulative_entities_leaked=1,
        guard_latencies_ms=tuple(range(1, 11)),
        benchmark=BenchmarkName.PII_EGRESS,
        baseline=Baseline.B3,
    )
    second = AgentEvalSample(
        sample_id="sample-2",
        task_success=False,
        expected_sensitive_entities=2,
        detected_sensitive_entities=1,
        policy_decisions_total=2,
        policy_decisions_correct=1,
        forbidden_entities_encountered=2,
        forbidden_entities_disclosed=1,
        tool_entities_at_risk=2,
        tool_entities_leaked=0,
        memory_entities_at_risk=1,
        memory_entities_leaked=1,
        final_entities_at_risk=1,
        final_entities_leaked=1,
        sensitive_entities_acquired=2,
        unnecessary_sensitive_entities_acquired=1,
        data_items_acquired=3,
        necessary_data_items_acquired=1,
        utility_preserved=False,
        legitimate_task=True,
        incorrectly_blocked=True,
        attack_attempt=True,
        attack_succeeded=True,
        cumulative_entities_at_risk=2,
        cumulative_entities_leaked=1,
        guard_latencies_ms=tuple(range(11, 21)),
        benchmark="PII-Injection",
        baseline="B0",
    )
    return first, second


def test_agent_metrics_micro_aggregate_all_required_rates_and_nearest_rank_p95():
    metrics = aggregate_agent_metrics(_agent_samples())

    assert isinstance(metrics, AgentMetrics)
    assert metrics.sample_count == 2
    assert metrics.task_success_rate == 0.5
    assert metrics.detection_recall == pytest.approx(4 / 6)
    assert metrics.policy_accuracy == pytest.approx(4 / 6)
    assert metrics.entity_leakage_rate == pytest.approx(2 / 6)
    assert metrics.tool_argument_leakage_rate == 0.25
    assert metrics.memory_leakage_rate == pytest.approx(1 / 3)
    assert metrics.final_output_leakage_rate == pytest.approx(1 / 3)
    assert metrics.unnecessary_acquisition_rate == pytest.approx(2 / 6)
    assert metrics.data_minimization_rate == 0.625
    assert metrics.utility_preservation_rate == 0.5
    assert metrics.false_block_rate == 0.5
    assert metrics.attack_success_rate == 0.5
    assert metrics.cumulative_leakage_rate == pytest.approx(2 / 6)
    assert metrics.p95_guard_latency_ms == 19.0
    assert metrics.latency_sample_count == 20
    assert metrics.rates["entity_leakage_rate"].to_dict() == {
        "numerator": 2,
        "denominator": 6,
        "value": pytest.approx(1 / 3),
        "zero_denominator_value": 0.0,
    }


def test_agent_metric_zero_denominator_semantics_are_serialized():
    metrics = aggregate_agent_metrics([])

    assert metrics.sample_count == 0
    assert metrics.task_success_rate == 0.0
    assert metrics.sensitive_detection_recall == 1.0
    assert metrics.policy_decision_accuracy == 1.0
    assert metrics.entity_leakage_rate == 0.0
    assert metrics.unnecessary_acquisition_rate == 0.0
    assert metrics.data_minimization_rate == 1.0
    assert metrics.utility_preservation_rate == 0.0
    assert metrics.false_block_rate == 0.0
    assert metrics.attack_success_rate == 0.0
    assert metrics.p95_guard_latency_ms == 0.0
    assert metrics.to_dict()["counts"]["sensitive_detection_recall"]["zero_denominator_value"] == 1.0
    assert metrics.to_dict()["zero_denominator_semantics"] == dict(ZERO_DENOMINATOR_SEMANTICS)
    assert dict(ZERO_DENOMINATOR_VALUES)["entity_leakage_rate"] == 0.0


def test_agent_eval_sample_validates_counts_relationships_and_round_trips():
    first, _ = _agent_samples()
    restored = AgentEvalSample.from_dict(first.to_dict())

    assert restored == first
    assert restored.benchmark == "PII-Egress"
    assert restored.baseline == "B3"
    assert json.loads(json.dumps(restored.to_dict()))["guard_latencies_ms"] == list(range(1, 11))

    with pytest.raises(ValueError, match="cannot exceed"):
        AgentEvalSample(
            sample_id="invalid",
            task_success=True,
            expected_sensitive_entities=1,
            detected_sensitive_entities=2,
        )
    with pytest.raises(ValueError, match="requires attack_attempt"):
        AgentEvalSample(sample_id="invalid", task_success=False, attack_succeeded=True)
    with pytest.raises(ValueError, match="Unsupported benchmark"):
        AgentEvalSample(sample_id="invalid", task_success=True, benchmark="unknown")
    with pytest.raises((TypeError, ValueError), match="latencies"):
        AgentEvalSample(sample_id="invalid", task_success=True, guard_latencies_ms=(True,))


def test_benchmark_catalog_contains_exactly_the_eight_design_benchmarks():
    expected = {
        "PII-Detect",
        "PII-Minimize",
        "PII-Egress",
        "PII-RAG",
        "PII-Memory",
        "PII-Tool",
        "PII-Injection",
        "PII-Trajectory",
    }

    assert {benchmark.value for benchmark in BenchmarkName} == expected
    assert {spec.name.value for spec in list_benchmarks()} == expected
    assert set(BENCHMARKS) == set(BenchmarkName)
    assert get_benchmark("PII-Injection").primary_metrics == ("attack_success_rate",)
    assert json.loads(json.dumps(get_benchmark(BenchmarkName.PII_DETECT).to_dict()))["name"] == "PII-Detect"
    with pytest.raises(KeyError):
        get_benchmark("PII-Unknown")


def test_baseline_catalog_encodes_b0_through_b4_without_models_or_network():
    assert tuple(config.baseline for config in list_baselines()) == tuple(Baseline)
    assert set(BASELINES) == set(Baseline)
    assert get_baseline("B0").capabilities == ()
    assert get_baseline("B1").capabilities == ("detection",)
    assert get_baseline("B2").capabilities == ("detection", "uniform_redaction")

    static = get_baseline(Baseline.B3)
    assert static.detection
    assert static.context_aware_policy
    assert static.safe_tool_gateway
    assert static.memory_guard
    assert static.disclosure_ledger
    assert not static.uniform_redaction
    assert not static.dynamic_intent
    assert not static.guarded_planning

    dynamic = get_baseline(Baseline.B4)
    assert dynamic.dynamic_intent
    assert dynamic.guarded_planning
    assert BaselineConfig.from_dict(dynamic.to_dict()) == dynamic
    assert json.loads(json.dumps(dynamic.to_dict()))["baseline"] == "B4"
    with pytest.raises(KeyError):
        get_baseline("B5")


def test_all_metric_payloads_are_json_serializable():
    entity_payload = evaluate_entities([EntitySpan("NAME", 0, 2)], [EntitySpan("NAME", 0, 2)]).to_dict()
    agent_payload = AgentMetrics.from_samples(_agent_samples()).to_dict()

    assert json.loads(json.dumps(entity_payload))["f1"] == 1.0
    assert json.loads(json.dumps(agent_payload))["p95_guard_latency_ms"] == 19.0
