#!/usr/bin/env python3
from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "src" / "findings" / "catalog.rs"
OUTPUT = ROOT / "FINDING_AUDIT_MATRIX.md"


def load_catalog():
    text = CATALOG.read_text()
    pattern = re.compile(
        r'id: "([^"]+)",\n'
        r'\s+title: "([^"]+)",\n'
        r'\s+protocol: Protocol::(\w+),\n'
        r'\s+severity: Severity::(\w+),'
        r'.*?references: &\[(.*?)\],\n'
        r'\s+cvss_vector: "([^"]+)"',
        re.S,
    )
    entries = []
    for match in pattern.finditer(text):
        finding_id, title, protocol, severity, refs, vector = match.groups()
        refs = [item.strip().strip('"') for item in refs.split(",") if item.strip()]
        basis = (
            "; ".join(refs)
            if refs
            else "Internal calibration from standards/best-practice guidance documented in FINDING_INDEX.MD"
        )
        entries.append((finding_id, protocol, severity, title, vector, basis))
    return sorted(entries)


def render(entries):
    lines = [
        "# Finding Audit Matrix",
        "",
        "Compact mapping of each finding to its current severity/CVSS basis after the 68-finding audit.",
        "",
        "Primary source of truth: `src/findings/catalog.rs`",
        "",
        "| ID | Protocol | Severity | Title | CVSS Vector | External Source Basis |",
        "|----|----------|----------|-------|-------------|-----------------------|",
    ]
    for finding_id, protocol, severity, title, vector, basis in entries:
        lines.append(
            f"| {finding_id} | {protocol} | {severity} | {title} | `{vector}` | {basis} |"
        )
    return "\n".join(lines) + "\n"


def main():
    OUTPUT.write_text(render(load_catalog()))
    print(f"[audit-matrix] wrote {OUTPUT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
