"""Fail-closed, deterministic full-chain release policy evaluator."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from ironveil.evidence.manifest import verify_manifest
from ironveil.models import (
    AssuranceState,
    CheckResult,
    Component,
    Decision,
    DeviceState,
    PolicyConfig,
    ReleaseBundle,
    VerificationReport,
)
from ironveil.sbom.verify import verify_sbom
from ironveil.signing.local import verify_release_signature
from ironveil.util import parse_semver


def _check(control: str, passed: bool, detail: str, ref: str) -> CheckResult:
    return CheckResult(
        control=control,
        state=AssuranceState.VERIFIED if passed else AssuranceState.FAILED,
        detail=detail,
        evidence_refs=[ref],
    )


def evaluate_release(
    bundle: ReleaseBundle,
    device: DeviceState,
    policy: PolicyConfig,
    trusted_public_key: Path,
    ground_truth: list[Component],
    *,
    artifact_digest_observed: str | None = None,
    now: datetime | None = None,
) -> VerificationReport:
    """Evaluate the assurance chain; any critical failure produces DENY."""
    now = now or datetime.now(UTC)
    checks: list[CheckResult] = []

    observed = artifact_digest_observed or bundle.artifact.digest
    artifact_ok = observed == bundle.artifact.digest
    checks.append(
        _check(
            "INV-001.artifact-digest",
            artifact_ok,
            "artifact digest matches" if artifact_ok else "observed artifact digest mismatch",
            "EV-ART-001",
        )
    )

    source = bundle.source
    independent = all(reviewer != source.author for reviewer in source.reviewers)
    source_ok = (
        source.repository == policy.expected_repository
        and source.branch in policy.protected_branches
        and source.protected_branch is True
        and source.approved
        and len(source.reviewers) >= policy.minimum_reviews
        and (policy.author_may_self_approve or independent)
        and all(source.status_checks.get(item, False) for item in policy.required_status_checks)
    )
    source_detail = (
        "authorized reviewed source revision" if source_ok else "source authorization policy failed"
    )
    checks.append(_check("source.authorization", source_ok, source_detail, source.evidence_id))

    provenance = bundle.provenance
    provenance_ok = (
        provenance.subject_digest == bundle.artifact.digest
        and provenance.source_revision == source.revision
        and provenance.repository == policy.expected_repository
        and provenance.builder_id == policy.expected_builder
        and provenance.workflow == policy.expected_workflow
    )
    checks.append(
        _check(
            "INV-001.provenance-binding",
            provenance_ok,
            "expected builder, source, workflow, and subject"
            if provenance_ok
            else "provenance identity or subject mismatch",
            provenance.evidence_id,
        )
    )

    if bundle.sbom is None:
        sbom_ok = not policy.require_sbom
        sbom_detail = "SBOM missing"
        sbom_ref = "EV-SBOM-MISSING"
    else:
        sbom_ok, sbom_detail, metrics = verify_sbom(
            bundle.sbom, bundle.artifact.digest, ground_truth
        )
        sbom_detail += f"; precision={metrics.precision:.3f}; recall={metrics.recall:.3f}"
        sbom_ref = bundle.sbom.evidence_id
        if any(
            component.license in policy.prohibited_licenses for component in bundle.sbom.components
        ):
            sbom_ok = False
            sbom_detail += "; prohibited license present"
    checks.append(_check("composition.sbom", sbom_ok, sbom_detail, sbom_ref))

    security = bundle.security
    tests_ok = security.artifact_digest == bundle.artifact.digest and all(security.tests.values())
    affected = [finding for finding in security.findings if finding.status == "AFFECTED"]
    unsupported_vex = [
        finding
        for finding in security.findings
        if finding.status == "NOT_AFFECTED" and not finding.justification
    ]
    security_ok = tests_ok and not affected and not unsupported_vex
    security_detail = "required security attestations passed"
    if affected:
        security_detail = (
            f"affected vulnerabilities: {', '.join(item.vulnerability_id for item in affected)}"
        )
    elif unsupported_vex:
        security_detail = "NOT_AFFECTED VEX statement lacks justification"
    elif not tests_ok:
        security_detail = "security evidence is incomplete, failed, or unbound"
    checks.append(
        _check("security.attestations", security_ok, security_detail, security.evidence_id)
    )

    signature_ok, signature_detail = verify_release_signature(bundle, trusted_public_key)
    if bundle.signature is not None:
        identity_ok = (
            bundle.signature.signer_identity == policy.expected_signer
            and bundle.signature.issuer == policy.expected_issuer
        )
        signature_detail += (
            "; expected identity" if identity_ok else "; unexpected signer identity or issuer"
        )
        signature_ok = signature_ok and identity_ok
        signature_ref = bundle.signature.evidence_id
    else:
        signature_ref = "EV-SIGN-MISSING"
    checks.append(
        _check("INV-002.signature-identity", signature_ok, signature_detail, signature_ref)
    )

    authorization = bundle.authorization
    required_set = {"source", "provenance", "sbom", "security", "signature"}
    authorization_ok = (
        authorization.approved
        and authorization.artifact_digest == bundle.artifact.digest
        and authorization.source_revision == source.revision
        and authorization.expires_at > now
        and device.target_group in authorization.target_groups
        and required_set.issubset(set(authorization.required_evidence))
    )
    checks.append(
        _check(
            "release.authorization",
            authorization_ok,
            "release authorization valid for target"
            if authorization_ok
            else "release authorization invalid, expired, or wrong target",
            authorization.evidence_id,
        )
    )

    update = bundle.update
    freshness_ok = (
        update.expires_at > now and update.role_authorized and update.metadata_version >= 1
    )
    update_ok = (
        freshness_ok
        and update.artifact_digest == bundle.artifact.digest
        and device.target_group in update.target_groups
        and update.version == bundle.artifact.version
    )
    checks.append(
        _check(
            "INV-006.update-metadata",
            update_ok,
            "fresh target-bound update metadata"
            if update_ok
            else "update metadata expired, unauthorized, or mismatched",
            update.evidence_id,
        )
    )

    version_ok = parse_semver(bundle.artifact.version) >= parse_semver(device.minimum_version)
    rollback = parse_semver(bundle.artifact.version) < parse_semver(device.installed_version)
    authorized_recovery = rollback and authorization.recovery
    target_ok = (
        device.hardware_model == "VEILNODE-GATEWAY"
        and device.maintenance_window
        and version_ok
        and (not rollback or authorized_recovery)
    )
    checks.append(
        _check(
            "INV-005.target-and-rollback",
            target_ok,
            "target and monotonic version policy satisfied"
            if target_ok
            else "wrong hardware, maintenance state, or unauthorized rollback",
            f"EV-DEVICE-{device.device_id}",
        )
    )

    manifest_ok, manifest_detail = verify_manifest(bundle)
    checks.append(
        _check("evidence.package-integrity", manifest_ok, manifest_detail, "EV-MANIFEST-001")
    )

    critical_ok = all(item.state == AssuranceState.VERIFIED for item in checks)
    review_needed = any(finding.status == "UNDER_INVESTIGATION" for finding in security.findings)
    if critical_ok and not bundle.health_check_passes and authorization.recovery:
        decision = Decision.RECOVER
    elif critical_ok:
        decision = Decision.ALLOW
    elif review_needed and all(
        item.state == AssuranceState.VERIFIED or item.control == "security.attestations"
        for item in checks
    ):
        decision = Decision.REVIEW_REQUIRED
    else:
        decision = Decision.DENY
    return VerificationReport(
        release_id=bundle.release_id,
        artifact=bundle.artifact.name,
        decision=decision,
        checks=checks,
        assumptions=[
            "The verifier, configured policy, trusted clock, and local trust root are "
            "uncompromised.",
            "Source-control properties are synthetic evidence unless independently captured "
            "from GitHub.",
            "Measured boot and update metadata are simulated; hardware root-of-trust and TUF "
            "conformance are not claimed.",
        ],
    )
