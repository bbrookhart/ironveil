from pathlib import Path

from ironveil.lab import create_golden_bundle, load_ground_truth, load_policy
from ironveil.models import Decision
from ironveil.policy.engine import evaluate_release


def evaluate(repo_root: Path):  # type: ignore[no-untyped-def]
    bundle, device = create_golden_bundle(repo_root)
    return evaluate_release(
        bundle,
        device,
        load_policy(repo_root),
        repo_root / ".ironveil" / "trust" / "LOCAL_TEST_ONLY.pub.pem",
        load_ground_truth(repo_root),
    )


def test_golden_release_is_allowed(repo_root: Path) -> None:
    report = evaluate(repo_root)
    assert report.decision == Decision.ALLOW
    assert all(check.state == "VERIFIED" for check in report.checks)


def test_missing_evidence_never_becomes_pass(repo_root: Path) -> None:
    bundle, device = create_golden_bundle(repo_root)
    bundle.sbom = None
    report = evaluate_release(
        bundle,
        device,
        load_policy(repo_root),
        repo_root / ".ironveil" / "trust" / "LOCAL_TEST_ONLY.pub.pem",
        load_ground_truth(repo_root),
    )
    assert report.decision == Decision.DENY
    assert not report.authorized
