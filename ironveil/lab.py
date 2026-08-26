"""Reproducible synthetic VEILNODE-1 assurance-lab construction."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import yaml

from ironveil.evidence.manifest import build_manifest
from ironveil.models import (
    Artifact,
    Component,
    DeviceState,
    PolicyConfig,
    ProvenanceEvidence,
    ReleaseAuthorization,
    ReleaseBundle,
    SbomEvidence,
    SecurityEvidence,
    SourceEvidence,
    UpdateMetadata,
)
from ironveil.signing.local import generate_test_key, sign_release
from ironveil.util import canonical_json, sha256_bytes

REPOSITORY = "https://github.com/bbrookhart/ironveil"
BUILDER = "https://github.com/bbrookhart/ironveil/.github/workflows/release.yml"
WORKFLOW = ".github/workflows/release.yml@refs/heads/main"
SIGNER = "https://github.com/bbrookhart/ironveil/.github/workflows/release.yml@refs/heads/main"
ISSUER = "https://token.actions.githubusercontent.com"


def workspace_path(repo_root: Path) -> Path:
    return repo_root / ".ironveil"


def load_ground_truth(repo_root: Path) -> list[Component]:
    raw = json.loads((repo_root / "standards" / "dependency-ground-truth.json").read_text())
    return [Component.model_validate(item) for item in raw["components"]]


def load_policy(repo_root: Path) -> PolicyConfig:
    raw = yaml.safe_load((repo_root / "policies" / "release-policy.yaml").read_text())
    return PolicyConfig.model_validate(raw)


def _source_revision(repo_root: Path) -> str:
    inputs = [
        (repo_root / "veilnode" / "application" / "main.py").read_bytes(),
        (repo_root / "veilnode" / "firmware" / "manifest.json").read_bytes(),
    ]
    return sha256_bytes(b"\n".join(inputs)).split(":", 1)[1]


def build_veilnode(repo_root: Path, output: Path) -> Artifact:
    """Build a deterministic research artifact from explicit source inputs."""
    revision = _source_revision(repo_root)
    firmware = json.loads((repo_root / "veilnode" / "firmware" / "manifest.json").read_text())
    build_object: dict[str, Any] = {
        "schema": "dev.ironveil.veilnode.artifact/v1",
        "name": "veilnode",
        "version": firmware["version"],
        "source_revision": revision,
        "hardware_model": firmware["hardware_model"],
        "entrypoint": "veilnode.application.main:run_cycle",
        "build": {
            "language": "python",
            "interpreter": "CPython 3.12",
            "normalization": "RFC-8785-inspired sorted compact JSON",
            "timestamp_in_artifact": False,
        },
    }
    content = canonical_json(build_object)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(content)
    return Artifact(
        name="veilnode-1.0.0",
        version="1.0.0",
        digest=sha256_bytes(content),
        size=len(content),
    )


def create_golden_bundle(
    repo_root: Path, now: datetime | None = None
) -> tuple[ReleaseBundle, DeviceState]:
    now = now or datetime.now(UTC)
    workspace = workspace_path(repo_root)
    artifact = build_veilnode(repo_root, workspace / "artifacts" / "veilnode-1.0.0.json")
    revision = _source_revision(repo_root)
    components = load_ground_truth(repo_root)
    source = SourceEvidence(
        evidence_id="EV-SOURCE-001",
        revision=revision,
        repository=REPOSITORY,
        branch="main",
        author="developer@ironveil.local",
        reviewers=["reviewer@ironveil.local"],
        protected_branch=True,
        status_checks={"ci": True, "security": True},
        approved=True,
    )
    provenance = ProvenanceEvidence(
        evidence_id="EV-PROV-001",
        subject_digest=artifact.digest,
        source_revision=revision,
        repository=REPOSITORY,
        builder_id=BUILDER,
        workflow=WORKFLOW,
        build_definition="supply-chain/build/veilnode.build.json",
        build_image="python:3.12.11-slim@sha256:SIMULATED-PIN-NOT-PULLED",
        parameters={"target": "VEILNODE-GATEWAY", "network": "disabled"},
        environment={"SOURCE_DATE_EPOCH": "0", "mode": "synthetic-local-lab"},
    )
    sbom = SbomEvidence(
        evidence_id="EV-SBOM-001",
        serial_number="urn:uuid:6614b9e8-25dd-4f92-92b1-66130fb6b27f",
        artifact_digest=artifact.digest,
        components=components,
        dependencies={
            "pkg:generic/veilnode@1.0.0": [item.purl for item in components],
            **{item.purl: [] for item in components},
        },
        timestamp=now,
    )
    security = SecurityEvidence(
        evidence_id="EV-SEC-001",
        artifact_digest=artifact.digest,
        tests={
            "unit": True,
            "integration": True,
            "static_analysis": True,
            "sbom_validation": True,
            "provenance_validation": True,
        },
        findings=[],
        database_timestamp=now,
    )
    authorization = ReleaseAuthorization(
        evidence_id="EV-RELEASE-001",
        artifact_digest=artifact.digest,
        source_revision=revision,
        target_groups=["DEVICE-GROUP-A"],
        approver="release-authority@ironveil.local",
        approved=True,
        expires_at=now + timedelta(days=30),
        required_evidence=["source", "provenance", "sbom", "security", "signature"],
    )
    update = UpdateMetadata(
        evidence_id="EV-UPDATE-001",
        artifact_digest=artifact.digest,
        version=artifact.version,
        metadata_version=1,
        target_groups=["DEVICE-GROUP-A"],
        expires_at=now + timedelta(days=7),
    )
    bundle = ReleaseBundle(
        release_id="RELEASE-00001",
        artifact=artifact,
        source=source,
        provenance=provenance,
        sbom=sbom,
        security=security,
        signature=None,
        authorization=authorization,
        update=update,
    )
    trust = workspace / "trust"
    private_key = trust / "LOCAL_TEST_ONLY.key"
    public_key = trust / "LOCAL_TEST_ONLY.pub.pem"
    if not private_key.exists() or not public_key.exists():
        generate_test_key(private_key, public_key)
    bundle.signature = sign_release(bundle, private_key, public_key, identity=SIGNER, issuer=ISSUER)
    bundle.evidence_manifest = build_manifest(bundle)
    device = DeviceState(
        device_id="DEVICE-001",
        hardware_model="VEILNODE-GATEWAY",
        target_group="DEVICE-GROUP-A",
        installed_version="0.9.0",
        artifact_digest="sha256:" + "0" * 64,
        sbom_digest="sha256:" + "0" * 64,
        minimum_version="0.9.0",
        last_known_good_digest="sha256:" + "0" * 64,
        installation_time=now,
    )
    return bundle, device


def write_evidence_package(repo_root: Path, bundle: ReleaseBundle) -> Path:
    root = workspace_path(repo_root) / "evidence" / bundle.release_id
    objects = {
        "source/revision.json": bundle.source,
        "build/provenance.json": bundle.provenance,
        "composition/bom.cdx.json": bundle.sbom,
        "security/tests.json": bundle.security,
        "signing/bundle.json": bundle.signature,
        "release/authorization.json": bundle.authorization,
        "update/tuf-metadata/targets.json": bundle.update,
        "manifest.json": bundle.evidence_manifest,
    }
    for relative, value in objects.items():
        if value is None:
            continue
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value.model_dump_json(indent=2) + "\n")
    return root


def bootstrap_lab(repo_root: Path) -> tuple[ReleaseBundle, DeviceState]:
    workspace = workspace_path(repo_root)
    workspace.mkdir(parents=True, exist_ok=True)
    bundle, device = create_golden_bundle(repo_root)
    releases = workspace / "releases"
    devices = workspace / "devices"
    releases.mkdir(parents=True, exist_ok=True)
    devices.mkdir(parents=True, exist_ok=True)
    (releases / f"{bundle.release_id}.json").write_text(bundle.model_dump_json(indent=2) + "\n")
    (devices / f"{device.device_id}.json").write_text(device.model_dump_json(indent=2) + "\n")
    write_evidence_package(repo_root, bundle)
    (workspace / "lab.json").write_text(
        json.dumps({"status": "READY", "mode": "SYNTHETIC_LOCAL_RESEARCH"}, indent=2) + "\n"
    )
    return bundle, device


def load_bundle(repo_root: Path, release_id: str = "RELEASE-00001") -> ReleaseBundle:
    path = workspace_path(repo_root) / "releases" / f"{release_id}.json"
    if not path.exists():
        bootstrap_lab(repo_root)
    return ReleaseBundle.model_validate_json(path.read_text())


def load_device(repo_root: Path, device_id: str = "DEVICE-001") -> DeviceState:
    path = workspace_path(repo_root) / "devices" / f"{device_id}.json"
    if not path.exists():
        bootstrap_lab(repo_root)
    return DeviceState.model_validate_json(path.read_text())
