"""Run targeted security-logic mutations and require the scenario suite to kill each one."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MUTANTS: dict[str, list[tuple[str, str]]] = {
    "ignore artifact digest": [
        ("artifact_ok = observed == bundle.artifact.digest", "artifact_ok = True"),
    ],
    "ignore provenance subject": [
        (
            "provenance.subject_digest == bundle.artifact.digest",
            "True  # mutated provenance subject check",
        ),
    ],
    "ignore signer identity": [
        (
            "identity_ok = (\n            bundle.signature.signer_identity == "
            "policy.expected_signer\n"
            "            and bundle.signature.issuer == policy.expected_issuer\n        )",
            "identity_ok = True  # mutated identity check",
        ),
    ],
    "ignore update freshness and role": [
        (
            "freshness_ok = (\n        update.expires_at > now and update.role_authorized "
            "and update.metadata_version >= 1\n    )",
            "freshness_ok = True  # mutated freshness check",
        ),
    ],
    "ignore target binding": [
        ("and device.target_group in authorization.target_groups", "and True"),
        ("and device.target_group in update.target_groups", "and True"),
    ],
    "ignore rollback": [
        (
            "rollback = parse_semver(bundle.artifact.version) < "
            "parse_semver(device.installed_version)",
            "rollback = False  # mutated rollback check",
        ),
    ],
    "accept missing SBOM": [
        ("sbom_ok = not policy.require_sbom", "sbom_ok = True"),
    ],
    "deny becomes allow": [
        ("decision = Decision.DENY", "decision = Decision.ALLOW  # mutated fail-closed path"),
    ],
}


def copy_fixture(destination: Path) -> None:
    for directory in ("ironveil", "tests", "standards", "policies", "veilnode"):
        shutil.copytree(ROOT / directory, destination / directory)
    shutil.copy2(ROOT / "pyproject.toml", destination / "pyproject.toml")


def main() -> int:
    survived: list[str] = []
    for name, replacements in MUTANTS.items():
        with tempfile.TemporaryDirectory(prefix="ironveil-mutant-") as temporary:
            target = Path(temporary)
            copy_fixture(target)
            engine = target / "ironveil" / "policy" / "engine.py"
            source = engine.read_text()
            for old, new in replacements:
                if old not in source:
                    raise SystemExit(f"mutation anchor changed: {name}")
                source = source.replace(old, new, 1)
            engine.write_text(source)
            environment = dict(os.environ)
            environment["PYTHONPATH"] = str(target)
            result = subprocess.run(
                [sys.executable, "-m", "pytest", "tests/scenarios/test_scenarios.py", "-q"],
                cwd=target,
                env=environment,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
            if result.returncode == 0:
                survived.append(name)
            else:
                print(f"KILLED: {name}")
    if survived:
        print("SURVIVED: " + ", ".join(survived))
        return 1
    print(f"targeted mutation score: 100% ({len(MUTANTS)}/{len(MUTANTS)} killed)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
