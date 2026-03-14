#!/usr/bin/env python3
from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "src" / "findings" / "catalog.rs"
INDEX = ROOT / "FINDING_INDEX.MD"
AUDIT_MATRIX = ROOT / "FINDING_AUDIT_MATRIX.md"


def load_catalog():
    text = CATALOG.read_text()
    entries = {}
    pattern = re.compile(
        r'id: "([^"]+)",\n'
        r'\s+title: "([^"]+)",\n'
        r'\s+protocol: Protocol::(\w+),\n'
        r'\s+severity: Severity::(\w+),'
        r'.*?references: &\[(.*?)\],\n'
        r'\s+cvss_vector: "([^"]+)"',
        re.S,
    )
    for match in pattern.finditer(text):
        finding_id, title, protocol, severity, refs, vector = match.groups()
        ref_list = [item.strip().strip('"') for item in refs.split(",") if item.strip()]
        entries[finding_id] = {
            "title": title,
            "protocol": protocol,
            "severity": severity,
            "refs": ref_list,
            "vector": vector,
        }
    return entries


def load_index():
    text = INDEX.read_text()
    summary = {}
    detail = {}

    summary_pattern = re.compile(
        r"^\| (HS-[^|]+) \| ([^|]+) \| ([^|]+) \| ([0-9.]+) \| `([^`]+)` \|",
        re.M,
    )
    for match in summary_pattern.finditer(text):
        finding_id, title, severity, score, vector = match.groups()
        summary[finding_id] = {
            "title": title.strip(),
            "severity": severity.strip(),
            "score": score.strip(),
            "vector": vector.strip(),
        }

    general_summary_pattern = re.compile(
        r"^\| (HS-GENERAL-[^|]+) \| ([^|]+) \| ([^|]+) \| ([0-9.]+) \|",
        re.M,
    )
    for match in general_summary_pattern.finditer(text):
        finding_id, title, severity, score = match.groups()
        summary[finding_id] = {
            "title": title.strip(),
            "severity": severity.strip(),
            "score": score.strip(),
            "vector": "N/A",
        }

    detail_pattern = re.compile(
        r"^### (HS-[^\s]+) .*?\n\n"
        r"\*\*Severity:\*\* ([^|]+) \| \*\*CVSS Score:\*\* ([0-9.]+) \| \*\*Vector:\*\* `([^`]+)`",
        re.M,
    )
    for match in detail_pattern.finditer(text):
        finding_id, severity, score, vector = match.groups()
        detail[finding_id] = {
            "severity": severity.strip(),
            "score": score.strip(),
            "vector": vector.strip(),
        }

    general_detail_pattern = re.compile(
        r"^### (HS-GENERAL-[^\s]+) .*?\n\n"
        r"\*\*Severity:\*\* ([^|]+) \| \*\*CVSS Score:\*\* ([0-9.]+) \| \*\*Vector:\*\* N/A",
        re.M,
    )
    for match in general_detail_pattern.finditer(text):
        finding_id, severity, score = match.groups()
        detail[finding_id] = {
            "severity": severity.strip(),
            "score": score.strip(),
            "vector": "N/A",
        }

    return summary, detail


def fail(message: str):
    print(f"[sync-check] {message}", file=sys.stderr)
    raise SystemExit(1)


def build_expected_audit_matrix(catalog):
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
    for finding_id, meta in sorted(catalog.items()):
        basis = (
            "; ".join(meta["refs"])
            if meta["refs"]
            else "Internal calibration from standards/best-practice guidance documented in FINDING_INDEX.MD"
        )
        lines.append(
            f"| {finding_id} | {meta['protocol']} | {meta['severity']} | {meta['title']} | "
            f"`{meta['vector']}` | {basis} |"
        )
    return "\n".join(lines) + "\n"


def main():
    catalog = load_catalog()
    summary, detail = load_index()

    if len(catalog) != 68:
        fail(f"expected 68 catalog entries, found {len(catalog)}")

    missing_summary = sorted(set(catalog) - set(summary))
    if missing_summary:
        fail(f"missing summary rows for: {', '.join(missing_summary[:5])}")

    missing_detail = sorted(set(catalog) - set(detail))
    if missing_detail:
        fail(f"missing detail sections for: {', '.join(missing_detail[:5])}")

    for finding_id, meta in catalog.items():
        for section_name, section in [("summary", summary[finding_id]), ("detail", detail[finding_id])]:
            if section["severity"] != meta["severity"]:
                fail(
                    f"{section_name} severity mismatch for {finding_id}: "
                    f"{section['severity']} != {meta['severity']}"
                )
            if not finding_id.startswith("HS-GENERAL-") and section["vector"] != meta["vector"]:
                fail(
                    f"{section_name} vector mismatch for {finding_id}: "
                    f"{section['vector']} != {meta['vector']}"
                )

    expected_audit_matrix = build_expected_audit_matrix(catalog)
    if AUDIT_MATRIX.read_text() != expected_audit_matrix:
        fail("FINDING_AUDIT_MATRIX.md is out of date; run scripts/generate_finding_audit_matrix.py")

    print("[sync-check] FINDING_INDEX.MD and FINDING_AUDIT_MATRIX.md match src/findings/catalog.rs")


if __name__ == "__main__":
    main()
