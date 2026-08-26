from pathlib import Path

import yaml

from ironveil.evaluation.scenarios import SCENARIOS
from ironveil.standards.registry import load_registry, validate_registry


def test_registry_is_current_and_status_disciplined(repo_root: Path) -> None:
    path = repo_root / "standards" / "registry.yaml"
    assert validate_registry(path) == []
    registry = load_registry(path)
    entries = {(entry["name"], str(entry["version"])): entry for entry in registry["entries"]}
    assert entries[("NIST SSDF", "1.2")]["status"] == "DRAFT"
    assert entries[("CISA SBOM Minimum Elements", "2026")]["status"] == "PUBLISHED_GUIDANCE"


def test_scenario_catalog_matches_executable_suite(repo_root: Path) -> None:
    catalog = yaml.safe_load((repo_root / "scenarios" / "catalog.yaml").read_text())
    documented = {item["scenario_id"] for item in catalog["scenarios"]}
    executable = {item.scenario_id for item in SCENARIOS}
    assert documented == executable
