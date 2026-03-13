# Handshaker

**Version:** v7.2.0 | **Author:** Gilles Biagomba | **License:** GPL-3.0

Handshaker is a native Rust secure-transport posture engine that probes TLS, SSH, and RDP endpoints without shelling out to external tools. It produces stable, machine-parseable finding IDs, SSL Labs–style grades, CVSS v3.1 risk scores, and supports compliance evaluation, benchmarking, longitudinal diffing, and AI-powered analysis.

---

## Table of Contents

1. [Features](#features)
2. [Installation](#installation)
3. [Flags](#flags)
4. [Usage](#usage)
5. [Testssl-Class Coverage Matrix](#testssl-class-coverage-matrix)
6. [Running Tests](#running-tests)
7. [Using Docker](#using-docker)
8. [Using the Makefile](#using-the-makefile)
9. [Contributing](#contributing)
10. [License](#license)

---

## Features

- **Native protocol probing** for TLS (all versions), STARTTLS (SMTP/IMAP/POP3/FTP/LDAP), SSH, and RDP — no `openssl` CLI or external binaries required
- **Stable finding IDs** (`HS-{PROTOCOL}-{CATEGORY}-{NNNN}`) for reliable CI gating and longitudinal tracking
- **SSL Labs–style scoring** — Certificate, Protocol, Key Exchange, Cipher Strength categories and A+/A/B/C/D/F grades
- **CVSS v3.1 configuration risk scoring** — max and weighted aggregate scores across all findings
- **Compliance evaluation** against YAML policies (PCI-DSS, NIST 800-52r2, CIS-like profiles)
- **Benchmarking and diffing** across scan runs to track remediation progress and detect regressions
- **Multiple output formats**: JSON, Text, Table, HTML, CSV, SQLite — with optional file output and database persistence

---

## Installation

### Pre-built Binaries (GitHub Releases)

Download the binary for your platform from the [Releases page](https://github.com/gbiagomba/WeakSSL/releases):

| OS      | Arch    | Asset name                          |
|---------|---------|-------------------------------------|
| Linux   | x86_64  | `handshaker-linux-x86_64`           |
| Linux   | aarch64 | `handshaker-linux-aarch64`          |
| macOS   | x86_64  | `handshaker-macos-x86_64`           |
| macOS   | aarch64 | `handshaker-macos-aarch64`          |
| Windows | x86_64  | `handshaker-windows-x86_64.exe`     |

### Install via Cargo

```bash
cargo install --git https://github.com/gbiagomba/WeakSSL
```

### Compile from Source

```bash
git clone https://github.com/gbiagomba/WeakSSL.git
cd WeakSSL
cargo build --release
# Binary at: target/release/handshaker
```

### Install Scripts

```bash
# Linux / macOS
bash scripts/install.sh

# Windows (PowerShell)
.\scripts\install.ps1
```

---

## Flags

### `scan`

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--target` | `-t` | string | — | Single target: hostname, IP, host:port, or URL |
| `--file` | `-f` | string | — | File with one target per line |
| `--nmap-grep` | — | string | — | Path to `.gnmap` file (nmap `-oG` output) |
| `--nmap-xml` | — | string | — | Path to nmap XML output file (`-oX`) |
| `--nuclei-json` | — | string | — | Path to nuclei JSONL output file |
| `--stdin` | — | bool | false | Read targets from stdin (one per line) |
| `--ports` | `-p` | list | — | Comma-separated port list (e.g. `443,8443,25`) |
| `--output` | — | enum | `json` | Output format: `json\|text\|table\|html\|csv\|sqlite` |
| `--out` | `-o` | string | — | Write output to file instead of stdout |
| `--concurrency` | — | number | `32` | Max parallel scans |
| `--timeout-secs` | — | number | `10` | Per-target connection timeout in seconds |
| `--policy` | — | string | — | YAML policy file for compliance evaluation |
| `--fail-on-noncompliant` | — | bool | false | Exit non-zero when any policy finding fails |
| `--benchmark` | — | string | — | YAML benchmark profile to evaluate results against |
| `--db` | — | string | — | SQLite database path to persist results |

### `explain`

| Argument | Description |
|----------|-------------|
| `<ID>` | Finding ID to look up (e.g. `HS-TLS-PROTOCOL-0003`) |

### `score`

| Flag | Type | Description |
|------|------|-------------|
| `--input` | string | Path to JSON results file |

### `benchmark`

| Flag | Type | Description |
|------|------|-------------|
| `--input` | string | Path to JSON results file |
| `--profile` | string | Path to benchmark YAML profile |

### `diff`

| Flag | Type | Description |
|------|------|-------------|
| `--left` | string | Baseline JSON results file |
| `--right` | string | New JSON results file to compare against baseline |

### `ai`

| Flag | Type | Description |
|------|------|-------------|
| `--input` | string | Path to JSON results file |
| `--provider` | string | AI provider name (default: built-in) |

### `db`

| Subcommand | Flag | Type | Description |
|------------|------|------|-------------|
| `init` | `--path` | string | Path to SQLite database file to initialize |
| `list` | `--path` | string | Path to SQLite database file |
| `export` | `--path` | string | Path to SQLite database file |
| `export` | `--run-id` | string | Run ID to export (from `db list`) |

---

## Usage

### Quick help

```bash
handshaker --help
handshaker scan --help
handshaker db init --help
```

### Detailed manual

```bash
handshaker help
handshaker help scan
handshaker help db
```

### Scan examples

```bash
# Single HTTPS target
handshaker scan --target example.com --ports 443

# Multiple ports including STARTTLS
handshaker scan --target mail.example.com --ports 25,587,465,993

# Scan a list of hosts and write an HTML report
handshaker scan --file hosts.txt --output html --out report.html

# Import targets from nmap XML output
handshaker scan --nmap-xml scan.xml --output json --out results.json

# Import targets from nuclei JSONL output
handshaker scan --nuclei-json nuclei.jsonl

# Read targets from stdin
cat hosts.txt | handshaker scan --stdin

# Compliance check with CI gate
handshaker scan --target example.com --policy pci.yaml --fail-on-noncompliant

# Scan and benchmark simultaneously
handshaker scan --target example.com --policy pci.yaml --benchmark profile.yaml --db results.db
```

### Explain a finding

```bash
handshaker explain HS-TLS-PROTOCOL-0003
handshaker explain HS-SSH-HOSTKEY-0105
handshaker explain HS-TLS-CIPHER-0001
```

### Score results

```bash
handshaker score --input results.json
```

### Benchmark results

```bash
handshaker benchmark --input results.json --profile default.yaml
handshaker benchmark --input results.json --profile pci-dss.yaml
```

### Diff two scans

```bash
# Track remediation progress
handshaker diff --left before.json --right after.json

# Detect weekly regressions
handshaker diff --left week1.json --right week2.json
```

### AI-powered analysis

```bash
handshaker ai --input results.json
handshaker ai --input results.json --provider openai
```

### Database workflow

```bash
# Initialize a new database
handshaker db init --path handshaker.db

# Store scan results
handshaker scan --target example.com --db handshaker.db

# List stored runs
handshaker db list --path handshaker.db

# Export a specific run as JSON
handshaker db export --path handshaker.db --run-id <RUN-ID>
```

---

## Testssl-Class Coverage Matrix

| testssl class | Handshaker implementation |
|---|---|
| protocol enumeration | TLS version probing in `src/protocols/tls/versions.rs` |
| cipher enumeration | Cipher list probing in `src/protocols/tls/ciphers.rs` |
| weak ciphers | NULL/aNULL/EXPORT/RC4/3DES/MEDIUM checks |
| certificate validation | Expired/not-yet-valid/self-signed/hostname/SHA1/RSA size checks |
| hostname mismatch | `HS-TLS-CERT-0004` |
| RSA key size | `HS-TLS-CERT-0006` |
| SHA1 signature | `HS-TLS-CERT-0005` |
| forward secrecy indicators | `HS-TLS-CIPHER-0009` |
| renegotiation posture | `HS-TLS-PROTOCOL-0008` |
| TLS compression | `HS-TLS-PROTOCOL-0009` |
| session resumption indicators | `HS-TLS-SCENARIO-0003` |
| downgrade resilience testing | `HS-TLS-SCENARIO-0001`/`0002` |
| SWEET32 exposure | `HS-TLS-SCENARIO-0005` |
| BEAST exposure | `HS-TLS-SCENARIO-0006` |
| Logjam weak DH | `HS-TLS-SCENARIO-0004` |

---

## Running Tests

```bash
# Run the full test suite
make test
# or
cargo test --all

# Run with CI lint + format check
make ci
# equivalent to: cargo fmt --all && cargo test --all && cargo build --release
```

---

## Using Docker

```bash
# Build the image
docker build -t handshaker .

# Scan a target
docker run --rm handshaker scan --target example.com --ports 443

# Scan a local file (mount current directory)
docker run --rm -v "$(pwd)":/data handshaker scan --file /data/hosts.txt --output html --out /data/report.html
```

---

## Using the Makefile

| Target | Description |
|--------|-------------|
| `make build` | Compile release binary (`target/release/handshaker`) |
| `make debug` | Compile debug binary |
| `make run ARGS="..."` | Build and run with arguments |
| `make install` | Run install script (`scripts/install.sh`) |
| `make test` | Run the full test suite |
| `make fmt` | Format all Rust source files |
| `make ci` | Run fmt + test + build (for CI pipelines) |
| `make clean` | Remove build artifacts |

---

## Contributing

1. Fork the repository on GitHub
2. Create a feature branch: `git checkout -b feature/my-change`
3. Make your changes and add tests
4. Ensure `make ci` passes without errors
5. Commit with a descriptive message following [Conventional Commits](https://www.conventionalcommits.org/)
6. Open a pull request against `main` describing the change and its motivation

Please report bugs and request features via [GitHub Issues](https://github.com/gbiagomba/WeakSSL/issues).

---

## License

Handshaker is released under the **GNU General Public License v3.0 (GPL-3.0)**. See the [LICENSE](LICENSE) file for the full terms.

For commercial use cases that require a different licensing arrangement, contact the author.
