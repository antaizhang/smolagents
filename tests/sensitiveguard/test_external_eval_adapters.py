"""Tests for third-party benchmark result normalization."""

from types import SimpleNamespace

import pytest

from sensitiveguard.eval.external import ExternalBenchmarkComparison, get_result_adapter, list_result_adapters
from sensitiveguard.eval.external.agentdojo import _build_agent_trace, _recipient_argument
from sensitiveguard.eval.external.tools import ExternalCallRecorder


def test_agentdojo_adapter_preserves_native_metrics_and_normalizes_scores() -> None:
    native = {
        "utility_results": {"a": True, "b": False, "c": True},
        "security_results": {"a": True, "b": True, "c": False},
        "extra_native_field": {"kept": True},
    }

    result = get_result_adapter("agentdojo").normalize(
        native,
        runtime="B3",
        model="qwen3.5:9b",
        benchmark_version="v1.2.2",
    )

    assert result.sample_count == 3
    assert result.utility_score == pytest.approx(2 / 3)
    assert result.security_score == pytest.approx(1 / 3)
    assert result.attack_success_rate == pytest.approx(2 / 3)
    assert result.native_metrics["extra_native_field"] == {"kept": True}


def test_external_comparison_reports_guarded_deltas() -> None:
    adapter = get_result_adapter("agentdojo")
    baseline = adapter.normalize(
        {"utility_results": [1, 1], "security_results": [1, 1]},
        runtime="B0",
        model="qwen3.5:9b",
    )
    guarded = adapter.normalize(
        {"utility_results": [1, 0], "security_results": [0, 0]},
        runtime="B3",
        model="qwen3.5:9b",
    )

    comparison = ExternalBenchmarkComparison(baseline=baseline, guarded=guarded)

    assert comparison.utility_delta == pytest.approx(-0.5)
    assert comparison.security_delta == pytest.approx(1.0)
    assert comparison.attack_success_delta == pytest.approx(-1.0)


def test_agentdojo_recipient_detection_supports_plural_recipients() -> None:
    assert _recipient_argument({"subject": {}, "recipients": {}, "body": {}}) == "recipients"


def test_agentdojo_trace_exposes_proposed_and_executed_calls() -> None:
    proposed_call = SimpleNamespace(name="send_email", arguments={"recipients": ["user@example.com"]}, id="call-1")
    step = SimpleNamespace(
        plan=None,
        model_output="I will send the result.",
        tool_calls=[proposed_call],
        observations="Email sent.",
        action_output=None,
        error=None,
    )
    agent = SimpleNamespace(memory=SimpleNamespace(steps=[step]), host_intent=None, active_intent=None)
    recorder = ExternalCallRecorder()
    recorder.record("send_email", {"recipients": ["user@example.com"]}, "ok")

    trace = _build_agent_trace(agent, recorder, runtime_label="B3", query="Send the result", answer="Done")

    assert trace["runtime"] == "B3"
    assert trace["proposed_calls"] == [
        {"name": "send_email", "arguments": {"recipients": ["user@example.com"]}, "id": "call-1"}
    ]
    assert trace["executed_calls"] == [
        {"name": "send_email", "arguments": {"recipients": ["user@example.com"]}, "result": "ok"}
    ]
    assert trace["final_answer"] == "Done"


def test_registry_contains_the_initial_external_benchmark_set() -> None:
    assert {adapter.name for adapter in list_result_adapters()} == {
        "agent-threat-bench",
        "agentdam",
        "agentdojo",
        "bfcl",
        "privacylens",
        "tau3",
    }
