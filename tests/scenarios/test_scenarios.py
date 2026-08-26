from pathlib import Path

import pytest

from ironveil.evaluation.scenarios import SCENARIOS, run_broken_seal, run_scenario


@pytest.mark.parametrize("scenario_id", [item.scenario_id for item in SCENARIOS])
def test_scenario_expected_decision(repo_root: Path, scenario_id: str) -> None:
    result = run_scenario(repo_root, scenario_id)
    assert result.passed, (
        f"{scenario_id}: expected {result.definition.expected_verification}, "
        f"got {result.full_decision}"
    )


def test_broken_seal_rejects_every_unauthorized_attempt(repo_root: Path) -> None:
    result = run_broken_seal(repo_root, write_result=False)
    assert result["unauthorized_releases_attempted"] == 17
    assert result["unauthorized_artifacts_installed"] == 0
    assert result["ironveil_unauthorized_acceptance_rate"] == 0.0
    assert result["scenario_pass_rate"] == 1.0
