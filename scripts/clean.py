"""Remove only generated IRONVEIL lab state and caches."""

from pathlib import Path
from shutil import rmtree

ROOT = Path(__file__).resolve().parents[1]
for relative in (".ironveil", ".pytest_cache", ".mypy_cache", ".ruff_cache", ".hypothesis"):
    target = ROOT / relative
    if target.exists() and target.parent == ROOT:
        rmtree(target)
print("generated IRONVEIL state removed")
