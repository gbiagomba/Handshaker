# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Added
- `FINDING_AUDIT_MATRIX.md` — generated 68-row audit matrix mapping each finding to protocol, severity, CVSS vector, and external source basis
- `scripts/generate_finding_audit_matrix.py` — regenerates `FINDING_AUDIT_MATRIX.md` from `src/findings/catalog.rs`
- `scripts/check_finding_index_sync.py` — verifies `FINDING_INDEX.MD` and `FINDING_AUDIT_MATRIX.md` stay aligned with `src/findings/catalog.rs`
- `make verify-docs` and `make generate-audit-matrix`
- 32 additional test scenarios, bringing the suite to 101 tests total
  - `tests/input_edge_cases.rs`
  - `tests/cvss_edges.rs`
  - `tests/catalog_audit.rs`
  - `tests/runtime_edges.rs`
  - `tests/finding_index_sync.rs`

### Changed
- `handshaker scan --file` now auto-detects plain target files, nmap grep, nmap XML, nuclei JSON(L), and testssl JSON
- Full 68-finding audit completed across `src/findings/catalog.rs` and `FINDING_INDEX.MD`
  - CVSS vectors, scores, severities, and references recalibrated against external sources where applicable
  - Original reasoning in `FINDING_INDEX.MD` preserved and augmented with vendor/source calibration notes
- CVSS calculator now rounds up according to CVSS v3.1 rules
- Catalog/document sync is now enforced by test coverage

## [7.3.3] - 2026-03-14

### Fixed
- `ci.yml`: added `macos-13` (Intel x64) and `windows-11-arm` (ARM64) to build matrix so both architectures appear in GitHub Releases
  - `macos-latest` builds macOS ARM64 (Apple Silicon); `macos-13` builds macOS x64 (Intel)
  - `windows-latest` builds Windows x64; `windows-11-arm` builds Windows ARM64

## [7.3.2] - 2026-03-14

### Added
- `FINDING_INDEX.MD` Section 7: Finding Details — standards enrichment blocks for all 68 findings
  - CVE references, CWE IDs, OWASP category, WASC identifier, and CVSS vector component explanations
  - Severity reasoning with industry source citations (NVD, Tenable, RFC references)
  - Attack prerequisites for each finding
- Logo image in `README.md` header

### Changed
- CVSS severity label alignment across `FINDING_INDEX.MD` and `src/findings/catalog.rs`:
  - **Critical→High**: HS-TLS-PROTOCOL-0002 (SSLv3/8.6), HS-TLS-CIPHER-0002 (aNULL/8.6), HS-TLS-CIPHER-0003 (EXPORT→7.4 after vector fix)
  - **Critical→kept Critical** with vector corrected: HS-TLS-PROTOCOL-0001 and HS-TLS-CERT-0001 vectors updated to `A:H` (score 9.8)
  - **Medium→High**: HS-TLS-CIPHER-0005 (SWEET32) vector updated to `AV:N/AC:L/C:H` per CVE-2016-2183 NVD 7.5
  - **High→Medium** (13 findings): HS-TLS-PROTOCOL-0003, 0007; HS-TLS-CIPHER-0004; HS-TLS-CERT-0005, 0006; HS-TLS-SCENARIO-0002, 0004; HS-SSH-KEX-0101, 0102; HS-SSH-HOSTKEY-0104, 0105; HS-SSH-CIPHER-0107; HS-RDP-TLS-0202
  - **3.7→4.8** vector updates (add `I:L`): All Medium findings that had `C:L/I:N/A:N` vectors updated to `C:L/I:L/A:N` for score alignment with Medium severity range
- FINDING_INDEX.MD protocol counts corrected: TLS (48), General (5)
- Finding statistics updated: Critical 3, High 10, Medium 38, Low 12, Info 5

## [7.3.1] - 2026-03-13

### Fixed
- Removed `Cargo.lock` from `.gitignore` — binary projects must commit the lock file; `--locked` flag was failing on all CI platforms
- `ci.yml`: replaced deprecated `actions-rs/toolchain@v1` with `dtolnay/rust-toolchain@stable`
- `ci.yml`: replaced unavailable `macos-13` runner with `macos-latest`
- `ci.yml`: replaced invalid `ubuntu-22.04-arm64` runner with `ubuntu-24.04-arm` (correct GitHub-hosted ARM runner name)
- `ci.yml`: corrected binary name from `weakssl`/`weakssl.exe` to `handshaker`/`handshaker.exe` in Package steps and artifact names
- `ci.yml`: added dedicated `test` job (`cargo test --locked`) that gates all build jobs
- Deleted `release.yml` stub — redundant with `ci.yml`'s `release` job; both triggered on `v*` tags causing conflicts

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
