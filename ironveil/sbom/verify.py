"""CycloneDX-shaped SBOM validation and synthetic ground-truth measurement."""

from __future__ import annotations

from dataclasses import dataclass

from ironveil.models import Component, SbomEvidence


@dataclass(frozen=True)
class SbomMetrics:
    precision: float
    recall: float
    unknown_components: tuple[str, ...]
    missing_components: tuple[str, ...]


def measure_composition(sbom: SbomEvidence, ground_truth: list[Component]) -> SbomMetrics:
    declared = {component.purl for component in sbom.components}
    expected = {component.purl for component in ground_truth}
    true_positive = len(declared & expected)
    precision = true_positive / len(declared) if declared else (1.0 if not expected else 0.0)
    recall = true_positive / len(expected) if expected else 1.0
    return SbomMetrics(
        precision=precision,
        recall=recall,
        unknown_components=tuple(sorted(declared - expected)),
        missing_components=tuple(sorted(expected - declared)),
    )


def verify_sbom(
    sbom: SbomEvidence,
    artifact_digest: str,
    ground_truth: list[Component],
) -> tuple[bool, str, SbomMetrics]:
    metrics = measure_composition(sbom, ground_truth)
    problems: list[str] = []
    if sbom.bom_format != "CycloneDX" or sbom.spec_version != "1.7":
        problems.append("unsupported or stale SBOM schema")
    if sbom.artifact_digest != artifact_digest:
        problems.append("SBOM is not bound to the artifact digest")
    if not sbom.serial_number.startswith("urn:uuid:"):
        problems.append("SBOM serial number is invalid")
    for component in sbom.components:
        if not component.purl or not component.sha256 or not component.license:
            problems.append(f"component metadata incomplete: {component.name}")
    if metrics.precision != 1.0 or metrics.recall != 1.0:
        problems.append(
            f"composition differs from ground truth (precision={metrics.precision:.3f}, "
            f"recall={metrics.recall:.3f})"
        )
    return not problems, "; ".join(problems) if problems else "SBOM and ground truth agree", metrics
