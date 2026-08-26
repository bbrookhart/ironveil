from pathlib import Path

from ironveil.lab import create_golden_bundle, load_ground_truth
from ironveil.sbom.verify import verify_sbom


def test_ground_truth_precision_and_recall(repo_root: Path) -> None:
    bundle, _ = create_golden_bundle(repo_root)
    assert bundle.sbom is not None
    valid, _, metrics = verify_sbom(
        bundle.sbom, bundle.artifact.digest, load_ground_truth(repo_root)
    )
    assert valid
    assert metrics.precision == 1.0
    assert metrics.recall == 1.0
