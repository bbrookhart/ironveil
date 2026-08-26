"""Canonical serialization, hashing, and version helpers."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel


def jsonable(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json", exclude_none=False)
    return value


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        jsonable(value), sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def sha256_bytes(data: bytes) -> str:
    return f"sha256:{hashlib.sha256(data).hexdigest()}"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return f"sha256:{digest.hexdigest()}"


def digest_object(value: Any) -> str:
    return sha256_bytes(canonical_json(value))


def parse_semver(value: str) -> tuple[int, int, int]:
    try:
        parts = value.split(".")
        if len(parts) != 3:
            raise ValueError
        return tuple(int(part) for part in parts)  # type: ignore[return-value]
    except (TypeError, ValueError) as exc:
        raise ValueError(f"invalid semantic version: {value}") from exc
