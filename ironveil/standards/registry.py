"""Machine-readable standards-registry validation."""

from __future__ import annotations

from datetime import date
from pathlib import Path
from typing import Any

import yaml


def load_registry(path: Path) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text())
    if not isinstance(data, dict) or not isinstance(data.get("entries"), list):
        raise ValueError("standards registry must contain an entries list")
    return data


def validate_registry(path: Path) -> list[str]:
    data = load_registry(path)
    errors: list[str] = []
    retrieved = date.fromisoformat(str(data["retrieved_at"]))
    if retrieved > date.today():
        errors.append("retrieval date is in the future")
    required = {"name", "version", "status", "source", "used_by"}
    for index, entry in enumerate(data["entries"]):
        missing = required - set(entry)
        if missing:
            errors.append(f"entry {index} missing: {', '.join(sorted(missing))}")
        if "draft" in str(entry.get("source", "")).lower() and entry.get("status") != "DRAFT":
            errors.append(f"entry {index} draft source not labeled DRAFT")
    current = {(entry["name"], str(entry["version"])): entry["status"] for entry in data["entries"]}
    expected = {
        ("SLSA", "1.2"): "APPROVED",
        ("CycloneDX", "1.7"): "CURRENT_STABLE",
        ("NIST SSDF", "1.2"): "DRAFT",
        ("CISA SBOM Minimum Elements", "2026"): "PUBLISHED_GUIDANCE",
    }
    for key, status in expected.items():
        if current.get(key) != status:
            errors.append(f"required status mismatch for {key[0]} {key[1]}")
    return errors
