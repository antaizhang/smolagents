"""The eval command line: it lists, it runs, it lints, and it fails closed."""

from __future__ import annotations

import json

from sensitiveguard.eval.__main__ import main


def test_list_names_all_six(capsys) -> None:
    assert main(["list"]) == 0
    out = capsys.readouterr().out
    for name in ("airgap-agent-r", "privacylens", "agentdam", "agentleak", "agentdojo", "asb"):
        assert name in out


def test_run_a_single_benchmark(capsys) -> None:
    assert main(["run", "airgap-agent-r"]) == 0
    out = capsys.readouterr().out
    assert "airgap-agent-r" in out
    assert "no-defence" in out and "guarded" in out


def test_run_writes_json(tmp_path, capsys) -> None:
    target = tmp_path / "report.json"
    assert main(["run", "asb", "--json", str(target)]) == 0
    payload = json.loads(target.read_text())
    assert payload["results"], "the json report must carry results"


def test_lint_passes_on_the_bundled_policies(capsys) -> None:
    assert main(["lint"]) == 0
    out = capsys.readouterr().out
    assert "FAIL" not in out


def test_run_all_by_default(capsys) -> None:
    assert main(["run"]) == 0
    out = capsys.readouterr().out
    # The headline table lines every benchmark up in one place.
    assert "benchmark" in out and "runtime" in out
