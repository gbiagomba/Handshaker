# Changelog

All notable changes to this project will be documented in this file.

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
