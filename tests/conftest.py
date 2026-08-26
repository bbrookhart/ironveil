from pathlib import Path

import pytest

from ironveil.lab import bootstrap_lab


@pytest.fixture(scope="session")
def repo_root() -> Path:
    root = Path(__file__).resolve().parents[1]
    bootstrap_lab(root)
    return root
