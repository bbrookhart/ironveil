"""Typed evidence and policy models for the IRONVEIL research lab."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


def utc_now() -> datetime:
    return datetime.now(UTC)


class AssuranceState(StrEnum):
    VERIFIED = "VERIFIED"
    FAILED = "FAILED"
    UNKNOWN = "UNKNOWN"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    NOT_EVALUATED = "NOT_EVALUATED"


class Decision(StrEnum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"
    RECOVER = "RECOVER"


class CheckResult(BaseModel):
    control: str
    state: AssuranceState
    detail: str
    evidence_refs: list[str] = Field(default_factory=list)


class VerificationReport(BaseModel):
    release_id: str
    artifact: str
    decision: Decision
    checks: list[CheckResult]
    evaluated_at: datetime = Field(default_factory=utc_now)
    assumptions: list[str] = Field(default_factory=list)

    @property
    def authorized(self) -> bool:
        return self.decision == Decision.ALLOW


class Artifact(BaseModel):
    name: str
    version: str
    digest: str
    media_type: str = "application/vnd.ironveil.firmware+json"
    size: int


class SourceEvidence(BaseModel):
    evidence_id: str
    revision: str
    repository: str
    branch: str
    author: str
    reviewers: list[str]
    protected_branch: bool | None
    status_checks: dict[str, bool]
    approved: bool
    simulated: bool = True


class ProvenanceEvidence(BaseModel):
    evidence_id: str
    statement_type: str = "https://in-toto.io/Statement/v1"
    predicate_type: str = "https://slsa.dev/provenance/v1"
    subject_digest: str
    source_revision: str
    repository: str
    builder_id: str
    workflow: str
    build_definition: str
    build_image: str
    parameters: dict[str, Any]
    environment: dict[str, str]
    simulated: bool = True


class Component(BaseModel):
    name: str
    version: str
    purl: str
    sha256: str
    scope: str
    license: str


class SbomEvidence(BaseModel):
    evidence_id: str
    bom_format: str = "CycloneDX"
    spec_version: str = "1.7"
    serial_number: str
    artifact_digest: str
    components: list[Component]
    dependencies: dict[str, list[str]]
    generated_by: str = "ironveil-lab/0.1.0"
    generation_context: str = "synthetic-ground-truth"
    timestamp: datetime = Field(default_factory=utc_now)


class VulnerabilityFinding(BaseModel):
    vulnerability_id: str
    component_purl: str
    severity: str
    status: str
    justification: str | None = None


class SecurityEvidence(BaseModel):
    evidence_id: str
    artifact_digest: str
    tests: dict[str, bool]
    findings: list[VulnerabilityFinding] = Field(default_factory=list)
    scanner: str = "IRONVEIL synthetic fixture"
    database_timestamp: datetime = Field(default_factory=utc_now)


class SignatureBundle(BaseModel):
    evidence_id: str
    artifact_digest: str
    evidence_digest: str
    signer_identity: str
    issuer: str
    public_key_hint: str
    public_key_pem: str
    signature: str
    signed_at: datetime = Field(default_factory=utc_now)
    mode: str = "LOCAL_TEST_ONLY"


class ReleaseAuthorization(BaseModel):
    evidence_id: str
    artifact_digest: str
    source_revision: str
    target_groups: list[str]
    approver: str
    approved: bool
    expires_at: datetime
    required_evidence: list[str]
    recovery: bool = False


class UpdateMetadata(BaseModel):
    evidence_id: str
    artifact_digest: str
    version: str
    metadata_version: int
    target_groups: list[str]
    expires_at: datetime
    role: str = "targets"
    role_authorized: bool = True
    root_version: int = 1
    spec_reference: str = "TUF 1.0.36"
    implementation: str = "SIMULATED_TUF_SEMANTICS"


class DeviceState(BaseModel):
    device_id: str
    hardware_model: str
    target_group: str
    installed_version: str
    artifact_digest: str
    sbom_digest: str
    minimum_version: str
    release_channel: str = "stable"
    maintenance_window: bool = True
    verification_status: str = "VERIFIED"
    boot_measurement: str = "SIMULATED"
    installation_time: datetime = Field(default_factory=utc_now)
    last_known_good_digest: str | None = None


class EvidenceManifest(BaseModel):
    schema_version: str = "1.0"
    release_id: str
    evidence_digests: dict[str, str]
    package_digest: str


class ReleaseBundle(BaseModel):
    release_id: str
    artifact: Artifact
    source: SourceEvidence
    provenance: ProvenanceEvidence
    sbom: SbomEvidence | None
    security: SecurityEvidence
    signature: SignatureBundle | None
    authorization: ReleaseAuthorization
    update: UpdateMetadata
    health_check_passes: bool = True
    evidence_manifest: EvidenceManifest | None = None


class PolicyConfig(BaseModel):
    protected_branches: list[str]
    minimum_reviews: int = 1
    author_may_self_approve: bool = False
    required_status_checks: list[str]
    expected_repository: str
    expected_builder: str
    expected_workflow: str
    expected_signer: str
    expected_issuer: str
    require_sbom: bool = True
    require_security_evidence: bool = True
    prohibited_licenses: list[str] = Field(default_factory=list)
    vulnerability_action: str = "REVIEW_REQUIRED"


class ScenarioDefinition(BaseModel):
    scenario_id: str
    name: str
    threat: str
    mutation: str
    expected_verification: Decision
    expected_installation: str
    expected_evidence: list[str]
    authorized_operation: bool = False
