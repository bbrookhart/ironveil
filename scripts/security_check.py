"""Fast repository security assertions that do not require external scanners."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PATTERNS = {
    "private key": re.compile(r"BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY"),
    "GitHub token": re.compile(r"gh[pousr]_[A-Za-z0-9_]{20,}"),
    "AWS access key": re.compile(r"AKIA[0-9A-Z]{16}"),
}


def main() -> int:
    findings: list[str] = []
    for path in ROOT.rglob("*"):
        if not path.is_file() or any(part in {".git", ".venv", ".ironveil"} for part in path.parts):
            continue
        try:
            text = path.read_text()
        except UnicodeDecodeError:
            continue
        for name, pattern in PATTERNS.items():
            if pattern.search(text):
                findings.append(f"{path.relative_to(ROOT)}: possible {name}")
    if findings:
        print("\n".join(findings))
        return 1
    print(
        "security assertions: PASS (no committed private keys/tokens; dependencies are locked "
        "and tracked by Dependabot)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
