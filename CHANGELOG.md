# Changelog

All notable changes to this project will be documented in this file.

## [7.3.0] - 2026-03-13

### Added
- `FINDING_INDEX.MD` — comprehensive finding reference document at project root
  - All 68 security findings across TLS (51), SSH (10), RDP (5), and General (2) protocols
  - Each finding entry includes: ID, title, severity, CVSS 3.1 score, CVSS vector, and description
  - Testssl-class coverage matrix mapping testssl.sh check categories to Handshaker finding IDs and implementation files
  - Policy profile cross-reference table showing which findings are enforced under Default, PCI-DSS, NIST 800-52r2, and CIS-Like compliance profiles

## [7.2.0] - 2026-03-13

### Added
- `handshaker help [<cmd>]` subcommand — man-page-style documentation for all 7 subcommands with NAME, SYNOPSIS, DESCRIPTION, OPTIONS, and EXAMPLES sections
- Triple-slash doc comments on every `#[arg]` field in `src/cli.rs` — all flags now show descriptions in `handshaker <cmd> --help` output
- `make ci` Makefile target that runs `fmt + test + build` for use in CI pipelines
- Per-subcommand `#[command(about = ...)]` annotations for improved `--help` top-level descriptions

### Changed
- `Cargo.toml` license corrected from `MIT OR Apache-2.0` to `GPL-3.0` (matches LICENSE file)
- Version bumped to 7.2.0
- `README.md` fully rewritten: 13-section structure covering features, installation (binaries/cargo/source/scripts), per-subcommand flag tables, usage examples, Docker, Makefile, contributing workflow, and GPL-3.0 license

## [7.1.0] - 2026-03-08

### Fixed
- SSH host-key size check no longer false-positives on Ed25519/ECDSA keys; guard is now RSA-only (RFC-compliant)
- RDP NLA finding `HS-RDP-TLS-0201` only fires when plain TLS succeeds without CredSSP (was unconditional)
- `find_by_id` upgraded from O(n) linear scan to O(1) `OnceLock<HashMap>` lookup
- `secure_renegotiation_supported` inverted logic fixed; now correctly calls `SSL_ctrl(SSL_CTRL_GET_RI_SUPPORT=76)` instead of `SSL_renegotiate`
- `read_line` in STARTTLS parser now enforces 8 KB max to prevent DoS from adversarial servers
- Wildcard SAN matching now enforces single-label only per RFC 6125 §6.4.3
- nmap XML parser handles both `Event::Empty` (self-closing) and `Event::Start` elements; MAC address entries filtered out
- `write_explain` now displays the computed CVSS score alongside the vector string

### Changed
- SQLite schema: added `UNIQUE (run_id, target, finding_id)` on `findings` table and `REFERENCES` foreign-key constraints with `PRAGMA foreign_keys = ON`
- Dependency updates: `thiserror` 1→2, `rand` 0.8→0.9 (renamed `thread_rng` → `rng`), `quick-xml` 0.31→0.37 (API update: `config_mut().trim_text()`), `rusqlite` 0.31→0.32

### Added
- Comprehensive test suite: 47 tests across 10 test binaries covering catalog, CVSS, scoring, policy evaluation, diff, benchmarking, target parsing, and input parsers
- `tempfile` dev-dependency for integration test file I/O

## [4.0.1] - 2025-10-01
- Add cross-platform install scripts for Linux/macOS (bash) and Windows (PowerShell)
- Update CI to produce predictable asset names per OS/arch
- Update README with one-line installers and install notes

## [4.0.0] - 2025-10-01
- Rewrite tooling in Rust as a zero-dependency CLI.
- Preserve legacy shell scripts in `legacy/`.
- Add Makefile and Dockerfile for builds.
- Add GitHub Actions to build on Linux/macOS/Windows (x64 + arm64).
- Generate simple HTML reports without requiring `aha`.
- Publish release artifacts on tagged builds.
