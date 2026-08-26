from pathlib import Path

from ironveil.lab import create_golden_bundle
from ironveil.signing.local import (
    verify_cryptographic_signature_only,
    verify_release_signature,
)


def test_local_signature_binds_full_evidence(repo_root: Path) -> None:
    bundle, _ = create_golden_bundle(repo_root)
    trusted = repo_root / ".ironveil" / "trust" / "LOCAL_TEST_ONLY.pub.pem"
    valid, _ = verify_release_signature(bundle, trusted)
    assert valid
    bundle.source.approved = False
    valid, detail = verify_release_signature(bundle, trusted)
    assert not valid
    assert "evidence envelope" in detail


def test_signature_only_does_not_evaluate_policy(repo_root: Path) -> None:
    bundle, _ = create_golden_bundle(repo_root)
    bundle.source.approved = False
    valid, detail = verify_cryptographic_signature_only(bundle)
    assert valid
    assert "policy not evaluated" in detail
