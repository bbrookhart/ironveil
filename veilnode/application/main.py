"""Fictional VEILNODE-1 process telemetry application."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class TelemetrySample:
    pressure_kpa: float
    temperature_c: float
    flow_lpm: float


def aggregate(samples: list[TelemetrySample]) -> dict[str, float]:
    if not samples:
        raise ValueError("at least one telemetry sample is required")
    count = len(samples)
    return {
        "pressure_kpa": sum(item.pressure_kpa for item in samples) / count,
        "temperature_c": sum(item.temperature_c for item in samples) / count,
        "flow_lpm": sum(item.flow_lpm for item in samples) / count,
    }


def run_cycle() -> dict[str, float]:
    """Run one deterministic synthetic telemetry cycle."""
    return aggregate(
        [
            TelemetrySample(101.2, 22.1, 14.8),
            TelemetrySample(101.4, 22.0, 14.9),
            TelemetrySample(101.3, 22.2, 14.7),
        ]
    )
