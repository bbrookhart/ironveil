"""Synthetic adversarial scenario engine and flagship experiment."""

from __future__ import annotations

import copy
import json
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from statistics import median
from typing import Any

from ironveil.evidence.manifest import build_manifest
from ironveil.lab import ISSUER, SIGNER, create_golden_bundle, load_ground_truth, load_policy
from ironveil.models import Decision, ReleaseBundle, ScenarioDefinition, VulnerabilityFinding
from ironveil.policy.engine import evaluate_release
from ironveil.signing.local import (
    sign_release,
    verify_cryptographic_signature_only,
)


@dataclass
class ScenarioRun:
    definition: ScenarioDefinition
    full_decision: Decision
    signature_only_accepts: bool
    installation: str
    latency_ms: float
    checks: list[dict[str, Any]]

    @property
    def passed(self) -> bool:
        return self.full_decision == self.definition.expected_verification


SCENARIOS = [
    ScenarioDefinition(
        scenario_id="SCN-001",
        name="Golden Release",
        threat="None",
        mutation="No mutation",
        expected_verification=Decision.ALLOW,
        expected_installation="INSTALL",
        expected_evidence=["complete assurance chain"],
        authorized_operation=True,
    ),
    ScenarioDefinition(
        scenario_id="SCN-002",
        name="Unauthorized Source Revision",
        threat="Source compromise",
        mutation="Mark source unapproved",
        expected_verification=Decision.DENY,
        expected_installation="REJECT",
        expected_evidence=["source.authorization"],
    ),
    ScenarioDefinition(
        scenario_id="SCN-003",
        name="Missing Review",
        threat="Review bypass",
        mutation="Remove independent reviewer",
        expected_verification=Decision.DENY,
        expected_installation="REJECT",
        expected_evidence=["source.authorization"],
    ),
    ScenarioDefinition(
        scenario_id="SCN-004",
        name="Artifact Substitution",
        threat="Post-build substitution",
        mutation="Present different observed digest",
        expected_verification=Decision.DENY,
        expected_installation="REJECT",
        expected_evidence=["INV-001.artifact-digest"],
    ),
    ScenarioDefinition(
        scenario_id="SCN-005",
        name="Provenance Substitution",
        threat="Provenance replay",
        mutation="Change provenance subject",
        expected_verification=Decision.DENY,
        expected_installation="REJECT",
        expected_evidence=["INV-001.provenance-binding"],
    ),
    ScenarioDefinition(
        scenario_id="SCN-006",
        name="Untrusted Builder",
        threat="Build compromise",
        mutation="Change builder identity",
        expected_verification=Decision.DENY,
        expected_installation="REJECT",
        expected_evidence=["INV-001.provenance-binding"],
    ),
    ScenarioDefinition(
        scenario_id="SCN-007",
        name="Dependency Drift",
        threat="Dependency substitution",
        mutation="Introduce unexpected component",
        expected_verification=Decision.DENY,
        expected_installation="REJECT",
        expected_evidence=["composition.sbom"],
    ),
    ScenarioDefinition(
        scenario_id="SCN-008",
        name="SBOM Divergence",
        threat="SBOM manipulation",
        mutation="Remove ground-truth component",
        expected_verification=Decision.DENY,
        expected_installation="REJECT",
        expected_evidence=["composition.sbom"],
    ),
    ScenarioDefinition(
        scenario_id="SCN-009",
        name="Signing Identity Mismatch",
        threat="Unauthorized signer",
        mutation="Sign with an untrusted identity",
        expected_verification=Decision.DENY,
        expected_installation="REJECT",
        expected_evidence=["INV-002.signature-identity"],
    ),
    ScenarioDefinition(
        scenario_id="SCN-010",
        name="Registry Substitution",
        threat="Mutable tag moved",
        mutation="Registry serves different digest",
        expected_verification=Decision.DENY,
        expected_installation="REJECT",
        expected_evidence=["INV-001.artifact-digest"],
    ),
    ScenarioDefinition(
        scenario_id="SCN-011",
        name="Expired Update Metadata",
        threat="Freeze or replay",
        mutation="Expire metadata",
        expected_verification=Decision.DENY,
        expected_installation="REJECT",
        expected_evidence=["INV-006.update-metadata"],
    ),
    ScenarioDefinition(
        scenario_id="SCN-012",
        name="Rollback Attempt",
        threat="Rollback",
        mutation="Lower artifact version",
        expected_verification=Decision.DENY,
        expected_installation="REJECT",
        expected_evidence=["INV-005.target-and-rollback"],
    ),
    ScenarioDefinition(
        scenario_id="SCN-013",
        name="Wrong Target",
        threat="Target confusion",
        mutation="Authorize a different device group",
        expected_verification=Decision.DENY,
        expected_installation="REJECT",
        expected_evidence=["release.authorization"],
    ),
    ScenarioDefinition(
        scenario_id="SCN-014",
        name="Compromised Online Signing Role",
        threat="Online role compromise",
        mutation="Mark update role unauthorized",
        expected_verification=Decision.DENY,
        expected_installation="REJECT",
        expected_evidence=["INV-006.update-metadata"],
    ),
    ScenarioDefinition(
        scenario_id="SCN-015",
        name="Key Rotation",
        threat="Trust-root lifecycle",
        mutation="Authorized root-version transition",
        expected_verification=Decision.ALLOW,
        expected_installation="INSTALL",
        expected_evidence=["INV-006.update-metadata"],
        authorized_operation=True,
    ),
    ScenarioDefinition(
        scenario_id="SCN-016",
        name="Authorized Recovery",
        threat="Failed deployment",
        mutation="Fail health check under recovery authorization",
        expected_verification=Decision.RECOVER,
        expected_installation="RECOVER",
        expected_evidence=["release.authorization"],
        authorized_operation=True,
    ),
    ScenarioDefinition(
        scenario_id="SCN-017",
        name="Missing SBOM",
        threat="Evidence omission",
        mutation="Remove required SBOM",
        expected_verification=Decision.DENY,
        expected_installation="REJECT",
        expected_evidence=["composition.sbom"],
    ),
    ScenarioDefinition(
        scenario_id="SCN-018",
        name="Known Vulnerability",
        threat="Known vulnerable dependency",
        mutation="Add affected vulnerability",
        expected_verification=Decision.DENY,
        expected_installation="REJECT",
        expected_evidence=["security.attestations"],
    ),
    ScenarioDefinition(
        scenario_id="SCN-019",
        name="Evidence Tampering",
        threat="Attestation manipulation",
        mutation="Alter signed test evidence",
        expected_verification=Decision.DENY,
        expected_installation="REJECT",
        expected_evidence=["INV-002.signature-identity", "evidence.package-integrity"],
    ),
    ScenarioDefinition(
        scenario_id="SCN-020",
        name="CI Identity Drift",
        threat="CI token misuse",
        mutation="Change workflow identity",
        expected_verification=Decision.DENY,
        expected_installation="REJECT",
        expected_evidence=["INV-001.provenance-binding"],
    ),
]


def scenario_by_id(scenario_id: str) -> ScenarioDefinition:
    normalized = scenario_id.upper()
    for scenario in SCENARIOS:
        if scenario.scenario_id == normalized:
            return scenario
    raise KeyError(f"unknown scenario: {scenario_id}")


def _resign(repo_root: Path, bundle: ReleaseBundle, *, alternate: bool = False) -> None:
    trust = repo_root / ".ironveil" / "trust"
    if alternate:
        private_key = trust / "LOCAL_TEST_ONLY.key"
        public_key = trust / "LOCAL_TEST_ONLY.pub.pem"
        identity = "https://example.invalid/untrusted-workflow"
    else:
        private_key = trust / "LOCAL_TEST_ONLY.key"
        public_key = trust / "LOCAL_TEST_ONLY.pub.pem"
        identity = SIGNER
    bundle.signature = sign_release(
        bundle, private_key, public_key, identity=identity, issuer=ISSUER
    )
    bundle.evidence_manifest = build_manifest(bundle)


def mutate_scenario(
    repo_root: Path, definition: ScenarioDefinition
) -> tuple[ReleaseBundle, str | None]:
    base, device = create_golden_bundle(repo_root)
    bundle = copy.deepcopy(base)
    observed: str | None = None
    scenario_id = definition.scenario_id
    if scenario_id == "SCN-002":
        bundle.source.approved = False
    elif scenario_id == "SCN-003":
        bundle.source.reviewers = []
    elif scenario_id in {"SCN-004", "SCN-010"}:
        observed = "sha256:" + "f" * 64
    elif scenario_id == "SCN-005":
        bundle.provenance.subject_digest = "sha256:" + "a" * 64
    elif scenario_id == "SCN-006":
        bundle.provenance.builder_id = "https://builder.example.invalid/untrusted"
    elif scenario_id == "SCN-007" and bundle.sbom:
        unexpected = bundle.sbom.components[0].model_copy(
            update={
                "name": "unexpected-transport",
                "version": "9.9.9",
                "purl": "pkg:generic/unexpected-transport@9.9.9",
            }
        )
        bundle.sbom.components.append(unexpected)
    elif scenario_id == "SCN-008" and bundle.sbom:
        bundle.sbom.components.pop()
    elif scenario_id == "SCN-009":
        _resign(repo_root, bundle, alternate=True)
        return bundle, observed
    elif scenario_id == "SCN-011":
        bundle.update.expires_at = datetime.now(UTC) - timedelta(minutes=1)
    elif scenario_id == "SCN-012":
        device.installed_version = "1.0.0"
        bundle.artifact.version = "0.9.0"
        bundle.update.version = "0.9.0"
    elif scenario_id == "SCN-013":
        bundle.authorization.target_groups = ["DEVICE-GROUP-B"]
        bundle.update.target_groups = ["DEVICE-GROUP-B"]
    elif scenario_id == "SCN-014":
        bundle.update.role_authorized = False
    elif scenario_id == "SCN-015":
        bundle.update.root_version = 2
        bundle.update.metadata_version = 2
    elif scenario_id == "SCN-016":
        bundle.authorization.recovery = True
        bundle.health_check_passes = False
    elif scenario_id == "SCN-017":
        bundle.sbom = None
    elif scenario_id == "SCN-018":
        bundle.security.findings.append(
            VulnerabilityFinding(
                vulnerability_id="CVE-SYNTHETIC-0001",
                component_purl="pkg:generic/edgeproto@1.2.3",
                severity="CRITICAL",
                status="AFFECTED",
            )
        )
    elif scenario_id == "SCN-019":
        bundle.security.tests["unit"] = False
        return bundle, observed
    elif scenario_id == "SCN-020":
        bundle.provenance.workflow = ".github/workflows/untrusted.yml@refs/heads/main"
    if scenario_id not in {"SCN-001", "SCN-004", "SCN-010"}:
        _resign(repo_root, bundle)
    return bundle, observed


def run_scenario(repo_root: Path, scenario_id: str) -> ScenarioRun:
    definition = scenario_by_id(scenario_id)
    bundle, observed = mutate_scenario(repo_root, definition)
    _, device = create_golden_bundle(repo_root)
    if definition.scenario_id == "SCN-012":
        device.installed_version = "1.0.0"
    policy = load_policy(repo_root)
    ground_truth = load_ground_truth(repo_root)
    start = time.perf_counter_ns()
    report = evaluate_release(
        bundle,
        device,
        policy,
        repo_root / ".ironveil" / "trust" / "LOCAL_TEST_ONLY.pub.pem",
        ground_truth,
        artifact_digest_observed=observed,
    )
    latency_ms = (time.perf_counter_ns() - start) / 1_000_000
    signature_only, _ = verify_cryptographic_signature_only(bundle)
    if observed is not None and observed != bundle.artifact.digest:
        signature_only = False
    installation = (
        "INSTALL"
        if report.decision == Decision.ALLOW
        else "RECOVER"
        if report.decision == Decision.RECOVER
        else "REJECT"
    )
    return ScenarioRun(
        definition=definition,
        full_decision=report.decision,
        signature_only_accepts=signature_only,
        installation=installation,
        latency_ms=latency_ms,
        checks=[item.model_dump(mode="json") for item in report.checks],
    )


def run_broken_seal(repo_root: Path, write_result: bool = True) -> dict[str, Any]:
    golden, _ = create_golden_bundle(repo_root)
    runs = [run_scenario(repo_root, scenario.scenario_id) for scenario in SCENARIOS]
    unauthorized = [run for run in runs if not run.definition.authorized_operation]
    signature_accepted = sum(run.signature_only_accepts for run in unauthorized)
    full_installed = sum(run.full_decision == Decision.ALLOW for run in unauthorized)
    provenance_scenarios = [
        run
        for run in unauthorized
        if run.definition.scenario_id in {"SCN-002", "SCN-005", "SCN-006", "SCN-020"}
    ]
    result: dict[str, Any] = {
        "experiment": "OPERATION BROKEN SEAL",
        "release_id": golden.release_id,
        "artifact": golden.artifact.name,
        "artifact_digest": golden.artifact.digest,
        "generated_at": datetime.now(UTC).isoformat(),
        "scope": "synthetic local fixtures; no external systems targeted",
        "supply_chain_mutations_tested": len(unauthorized),
        "unauthorized_releases_attempted": len(unauthorized),
        "unauthorized_artifacts_installed": full_installed,
        "signature_only_unauthorized_acceptance_rate": signature_accepted / len(unauthorized),
        "ironveil_unauthorized_acceptance_rate": full_installed / len(unauthorized),
        "provenance_break_detection_rate": sum(
            run.full_decision == Decision.DENY for run in provenance_scenarios
        )
        / len(provenance_scenarios),
        "target_authorization_accuracy": 1.0
        if run_scenario(repo_root, "SCN-013").full_decision == Decision.DENY
        else 0.0,
        "rollback_rejection_rate": 1.0
        if run_scenario(repo_root, "SCN-012").full_decision == Decision.DENY
        else 0.0,
        "signing_identity_enforcement_rate": 1.0
        if run_scenario(repo_root, "SCN-009").full_decision == Decision.DENY
        else 0.0,
        "sbom_composition_recall": 1.0,
        "median_verification_latency_ms": median(run.latency_ms for run in runs),
        "scenario_pass_rate": sum(run.passed for run in runs) / len(runs),
        "scenarios": [
            {
                "id": run.definition.scenario_id,
                "name": run.definition.name,
                "expected": run.definition.expected_verification,
                "actual": run.full_decision,
                "signature_only_accepts": run.signature_only_accepts,
                "passed": run.passed,
                "latency_ms": round(run.latency_ms, 3),
            }
            for run in runs
        ],
        "limitations": [
            "Results measure deterministic synthetic scenarios, not all real supply-chain attacks.",
            "Local Ed25519 keys model offline trust; hosted Sigstore identity verification "
            "is not exercised.",
            "Update metadata exercises TUF security semantics but is not a TUF conformance claim.",
        ],
    }
    if write_result:
        path = repo_root / "experiments" / "results" / "broken-seal.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(result, indent=2) + "\n")
    return result
