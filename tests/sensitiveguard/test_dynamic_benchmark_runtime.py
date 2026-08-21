"""Regression coverage for the B3/B4 SensitiveGuard benchmark paths."""

from sensitiveguard.eval import Baseline, build_baseline_runtime, load_seed_suite, run_scenario


def _representative_scenario():
    return next(scenario for scenario in load_seed_suite() if scenario.legitimate)


def test_b4_benchmark_exercises_dynamic_intent_and_guarded_planning() -> None:
    result = run_scenario(_representative_scenario(), build_baseline_runtime(Baseline.B4))

    assert result.trace.dynamic_intent_bound
    assert result.trace.active_intent_id
    assert result.trace.planning_steps >= 1
    assert result.sample.task_success


def test_b3_is_full_static_guard_without_dynamic_planning() -> None:
    result = run_scenario(_representative_scenario(), build_baseline_runtime(Baseline.B3))

    assert not result.trace.dynamic_intent_bound
    assert result.trace.active_intent_id is None
    assert result.trace.planning_steps == 0
    assert result.sample.task_success


def test_weaker_baselines_do_not_report_dynamic_intent_or_planning() -> None:
    scenario = _representative_scenario()
    for baseline in (Baseline.B0, Baseline.B1, Baseline.B2):
        result = run_scenario(scenario, build_baseline_runtime(baseline))
        assert not result.trace.dynamic_intent_bound
        assert result.trace.active_intent_id is None
        assert result.trace.planning_steps == 0
