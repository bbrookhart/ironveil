from pathlib import Path

from hypothesis import given
from hypothesis import strategies as st

from ironveil.evaluation.scenarios import run_scenario
from ironveil.lab import create_golden_bundle, load_ground_truth, load_policy
from ironveil.models import Decision
from ironveil.policy.engine import evaluate_release


@given(st.binary(min_size=1, max_size=64))
def test_inv_001_wrong_digest_never_authorized(repo_root: Path, value: bytes) -> None:
    bundle, device = create_golden_bundle(repo_root)
    observed = "sha256:" + value.hex().ljust(64, "0")[:64]
    if observed == bundle.artifact.digest:
        return
    report = evaluate_release(
        bundle,
        device,
        load_policy(repo_root),
        repo_root / ".ironveil" / "trust" / "LOCAL_TEST_ONLY.pub.pem",
        load_ground_truth(repo_root),
        artifact_digest_observed=observed,
    )
    assert report.decision != Decision.ALLOW


@given(
    st.sampled_from(
        ["SCN-003", "SCN-005", "SCN-009", "SCN-011", "SCN-012", "SCN-013", "SCN-017", "SCN-020"]
    )
)
def test_critical_invariants_fail_closed(repo_root: Path, scenario_id: str) -> None:
    assert run_scenario(repo_root, scenario_id).full_decision == Decision.DENY
