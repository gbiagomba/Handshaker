# Handshaker

Handshaker is a native Rust secure-transport posture engine that performs TLS, SSH, and RDP scanning without shelling out to external tools. It provides stable finding IDs, SSL Labs–style scoring, CVSS v3.1 configuration risk scoring, compliance evaluation, benchmarking, diffing, and multiple output formats.

## Features
- Native protocol probing for TLS/STARTTLS, SSH, and RDP
- Stable findings catalog with machine-parseable IDs
- SSL Labs–style category scoring and grading
- CVSS v3.1 configuration risk scoring
- Compliance policies (PCI-DSS, NIST 800-52r2, CIS-like)
- Benchmarking and diffing across runs
- Outputs: JSON, Text, Table, HTML, CSV, SQLite

## Install
Build from source:
```bash
cargo build --release
```

## Usage
```bash
handshaker scan --target example.com --ports 443,8443 --output json
handshaker explain HS-TLS-PROTOCOL-0003
handshaker score --input results.json
handshaker benchmark --input results.json --profile default
handshaker diff --left old.json --right new.json
handshaker db init --path handshaker.db
```

### Inputs
- `--target` single target (host, host:port, or URL)
- `--file` file with targets
- `--stdin` read targets from stdin
- `--nmap-grep` parse `*.gnmap`
- `--nmap-xml` parse `nmap` XML
- `--nuclei-json` parse nuclei JSONL

### STARTTLS Targets
STARTTLS is supported for SMTP (25/587), IMAP (143), POP3 (110), FTP (21), and LDAP (389). Implicit TLS is used for SMTPS (465), IMAPS (993), POP3S (995), FTPS (990), and LDAPS (636).

## Findings
All findings are in `src/findings/catalog.rs` and follow:
```
HS-{PROTOCOL}-{CATEGORY}-{4_DIGIT_ID}
```

## Testssl-Class Coverage Matrix
| testssl class | Handshaker implementation |
| --- | --- |
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

## Development
```bash
cargo fmt
cargo clippy --all-targets --all-features -D warnings
cargo test
```

## License
MIT OR Apache-2.0
