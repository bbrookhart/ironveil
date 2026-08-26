"""Evidence-package integrity manifest generation and verification."""

from __future__ import annotations

from ironveil.models import EvidenceManifest, ReleaseBundle
from ironveil.util import digest_object


def evidence_digests(bundle: ReleaseBundle) -> dict[str, str]:
    values: dict[str, object | None] = {
        "source": bundle.source,
        "provenance": bundle.provenance,
        "sbom": bundle.sbom,
        "security": bundle.security,
        "signature": bundle.signature,
        "authorization": bundle.authorization,
        "update": bundle.update,
    }
    return {name: digest_object(value) for name, value in values.items() if value is not None}


def build_manifest(bundle: ReleaseBundle) -> EvidenceManifest:
    digests = evidence_digests(bundle)
    return EvidenceManifest(
        release_id=bundle.release_id,
        evidence_digests=digests,
        package_digest=digest_object(digests),
    )


def verify_manifest(bundle: ReleaseBundle) -> tuple[bool, str]:
    if bundle.evidence_manifest is None:
        return False, "root evidence manifest is missing"
    expected = evidence_digests(bundle)
    if expected != bundle.evidence_manifest.evidence_digests:
        return False, "one or more evidence object digests changed"
    if digest_object(expected) != bundle.evidence_manifest.package_digest:
        return False, "evidence package digest mismatch"
    return True, "evidence package manifest verified"
