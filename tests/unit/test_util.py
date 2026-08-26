from pathlib import Path

import pytest

from ironveil.lab import build_veilnode
from ironveil.util import digest_object, parse_semver


def test_canonical_object_digest_is_order_independent() -> None:
    assert digest_object({"a": 1, "b": 2}) == digest_object({"b": 2, "a": 1})


def test_semver_is_strict() -> None:
    assert parse_semver("1.2.3") == (1, 2, 3)
    with pytest.raises(ValueError):
        parse_semver("1.2")


def test_build_is_reproducible(repo_root: Path, tmp_path: Path) -> None:
    first = build_veilnode(repo_root, tmp_path / "a.json")
    second = build_veilnode(repo_root, tmp_path / "b.json")
    assert first.digest == second.digest
    assert (tmp_path / "a.json").read_bytes() == (tmp_path / "b.json").read_bytes()
