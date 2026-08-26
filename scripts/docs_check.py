"""Validate required reviewer documentation, local links, and original visuals."""

import re
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REQUIRED = [
    "README.md",
    "docs/architecture.md",
    "docs/threat-model.md",
    "docs/assurance-case.md",
    "docs/reviewer-guide.md",
    "docs/IRONVEIL-whitepaper.md",
    "assets/ironveil-hero.svg",
    "assets/trust-chain.svg",
    "assets/provenance-graph.svg",
    "assets/update-verification.svg",
    "assets/blast-radius.svg",
    "assets/broken-seal-results.svg",
]


missing = [item for item in REQUIRED if not (ROOT / item).is_file()]
if missing:
    raise SystemExit("missing documentation artifacts: " + ", ".join(missing))
for svg in (ROOT / "assets").glob("*.svg"):
    # These are repository-owned, size-bounded assets rather than untrusted XML input.
    ET.parse(svg)  # noqa: S314

link_errors: list[str] = []
for markdown in [ROOT / "README.md", *sorted((ROOT / "docs").glob("*.md"))]:
    for destination in re.findall(r"!?(?:\[[^]]*\])\(([^)]+)\)", markdown.read_text()):
        if destination.startswith(("http://", "https://", "#")):
            continue
        path_text = destination.split("#", 1)[0]
        if path_text and not (markdown.parent / path_text).resolve().exists():
            link_errors.append(f"{markdown.relative_to(ROOT)} -> {destination}")
if link_errors:
    raise SystemExit("broken local documentation links: " + ", ".join(link_errors))
print(
    f"documentation assertions: PASS ({len(REQUIRED)} required artifacts, "
    f"{len(list((ROOT / 'assets').glob('*.svg')))} valid SVGs)"
)
