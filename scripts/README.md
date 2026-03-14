# Scripts

Install helpers for Handshaker across platforms.

- install.sh: Linux/macOS installer.
  - Downloads the latest release binary when available, falling back to `cargo build --release`.
  - Installs to `/usr/local/bin/handshaker` (uses `sudo` if not root).
  - Optional env vars:
    - `HANDSHAKER_VERSION`: pin a specific tag (e.g., `v0.1.0`).
    - `HANDSHAKER_USE_SOURCE=1`: force source build instead of binary download.
  - Run locally: `bash install.sh`

- install.ps1: Windows installer (PowerShell).
  - Downloads the latest release binary when available, falling back to source build with `cargo`.
  - Installs to `%ProgramFiles%\handshaker.exe` and updates PATH if needed.
  - Parameters:
    - `-Version <tag>`: pin a specific release (e.g., `v0.1.0`).
    - `-UseSource`: force source build.
  - Run locally (PowerShell): `./install.ps1` or `./install.ps1 -Version v0.1.0`

- check_finding_index_sync.py: Verifies `FINDING_INDEX.MD` stays aligned with `src/findings/catalog.rs`.
  - Checks that every catalog finding appears in both the summary tables and the detailed sections.
  - Checks severity and CVSS vector equality between source and documentation.
  - Checks that `FINDING_AUDIT_MATRIX.md` is current.
  - Run locally: `python3 scripts/check_finding_index_sync.py`

- generate_finding_audit_matrix.py: Regenerates `FINDING_AUDIT_MATRIX.md` from `src/findings/catalog.rs`.
  - Run locally: `python3 scripts/generate_finding_audit_matrix.py`
