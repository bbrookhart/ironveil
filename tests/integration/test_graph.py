from pathlib import Path

from ironveil.graph.lineage import dependency_impact, trace_device
from ironveil.lab import create_golden_bundle


def test_trace_connects_reviewed_source_to_device(repo_root: Path) -> None:
    bundle, device = create_golden_bundle(repo_root)
    trace = trace_device(bundle, device)
    assert trace[0]["source"].startswith("COMMIT-")
    assert trace[-1]["target"] == "DEVICE-001"
    assert len(trace) == 4


def test_dependency_blast_radius_reaches_mission(repo_root: Path) -> None:
    bundle, device = create_golden_bundle(repo_root)
    impact = dependency_impact(bundle, device, "pkg:generic/edgeproto@1.2.3")
    assert impact["affected_releases"] == ["RELEASE-00001"]
    assert impact["affected_devices"] == ["DEVICE-001"]
    assert impact["affected_mission_functions"] == ["MISSION-TELEMETRY"]
