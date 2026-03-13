# Handshaker Finding Index

This document is the authoritative reference for all security findings that Handshaker can detect.
It maps every finding to its severity, CVSS score, description, testssl-class equivalent, and
applicable compliance policy profiles.

## Overview

| Attribute | Value |
|-----------|-------|
| ID scheme | `HS-{PROTOCOL}-{CATEGORY}-{NNNN}` |
| CLI lookup | `handshaker help <ID>` |
| Source of truth | `src/findings/catalog.rs` |
| Total findings | 68 |
| Protocols | TLS (51), SSH (10), RDP (5), General (2) |

## Finding Statistics

| Total | Critical | High | Medium | Low | Info |
|-------|:--------:|:----:|:------:|:---:|:----:|
| 68 | 6 | 19 | 28 | 13 | 2 |

---

## 1. TLS Findings (51)

### 1.1 Protocol (10) — `HS-TLS-PROTOCOL-0001..0010`

| ID | Title | Severity | CVSS Score | CVSS Vector | Description |
|----|-------|----------|:----------:|-------------|-------------|
| HS-TLS-PROTOCOL-0001 | SSLv2 supported | Critical | 9.8 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` | Obsolete protocol with severe cryptographic weaknesses; all data is at risk |
| HS-TLS-PROTOCOL-0002 | SSLv3 supported | Critical | 8.6 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` | SSLv3 is vulnerable to POODLE and other attacks; must be disabled |
| HS-TLS-PROTOCOL-0003 | TLS 1.0 enabled | High | 5.3 | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N` | TLS 1.0 is deprecated (PCI-DSS 3.2+) and lacks modern cipher support |
| HS-TLS-PROTOCOL-0004 | TLS 1.1 enabled | Medium | 3.7 | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N` | TLS 1.1 lacks AEAD suites and is deprecated by RFC 8996 |
| HS-TLS-PROTOCOL-0005 | TLS 1.2 not supported | High | 7.3 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L` | Absence of TLS 1.2 forces clients onto weaker legacy protocol versions |
| HS-TLS-PROTOCOL-0006 | TLS 1.3 not supported | Low | 0.0 | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N` | TLS 1.3 removes legacy features and provides 0-RTT; its absence is a missed hardening opportunity |
| HS-TLS-PROTOCOL-0007 | Insecure renegotiation allowed | High | 6.5 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N` | Insecure renegotiation enables injection of plaintext by an active MITM (CVE-2009-3555) |
| HS-TLS-PROTOCOL-0008 | Secure renegotiation not supported | Medium | 3.7 | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N` | Without RFC 5746, clients fall back to insecure renegotiation |
| HS-TLS-PROTOCOL-0009 | TLS compression enabled (CRIME) | Medium | 3.7 | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N` | TLS-layer compression enables the CRIME attack to recover secrets from encrypted streams |
| HS-TLS-PROTOCOL-0010 | HTTP/2 over weak TLS | Medium | 3.7 | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N` | Offering HTTP/2 alongside deprecated TLS versions widens the downgrade attack surface |

### 1.2 Cipher (12) — `HS-TLS-CIPHER-0001..0012`

| ID | Title | Severity | CVSS Score | CVSS Vector | Description |
|----|-------|----------|:----------:|-------------|-------------|
| HS-TLS-CIPHER-0001 | NULL cipher suite | Critical | 9.8 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` | No encryption; all traffic transmitted in cleartext and trivially intercepted or modified |
| HS-TLS-CIPHER-0002 | Anonymous (aNULL) cipher | Critical | 8.6 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` | No server authentication; any attacker can impersonate the server without a certificate |
| HS-TLS-CIPHER-0003 | EXPORT cipher suite | Critical | 8.6 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` | 40/56-bit export-grade ciphers are trivially breakable with modern hardware (FREAK attack) |
| HS-TLS-CIPHER-0004 | RC4 cipher suite | High | 5.9 | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N` | RC4 has well-documented statistical biases that allow plaintext recovery in high-volume sessions |
| HS-TLS-CIPHER-0005 | 3DES cipher (SWEET32) | Medium | 3.7 | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N` | 3DES uses 64-bit blocks; birthday attacks after ~32 GB of traffic can recover plaintext (CVE-2016-2183) |
| HS-TLS-CIPHER-0006 | CBC-only with TLS 1.0 (BEAST) | Medium | 3.7 | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N` | Predictable IV in TLS 1.0 CBC mode enables the BEAST attack against certain session data |
| HS-TLS-CIPHER-0007 | Weak medium-strength ciphers | Medium | 3.7 | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N` | Ciphers with 64–112 bit effective strength are susceptible to brute-force in targeted attacks |
| HS-TLS-CIPHER-0008 | No AEAD suites available | Medium | 3.7 | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N` | Without AEAD (e.g. AES-GCM), the server is exposed to padding oracle and ciphertext tampering attacks |
| HS-TLS-CIPHER-0009 | No forward secrecy suites | Medium | 3.7 | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N` | Static RSA key exchange means compromise of the private key allows decryption of all recorded past sessions |
| HS-TLS-CIPHER-0010 | Legacy RSA key exchange | Medium | 3.7 | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N` | Non-ephemeral RSA exchange provides no forward secrecy; sessions can be retroactively decrypted |
| HS-TLS-CIPHER-0011 | Weak elliptic curve supported | Medium | 3.7 | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N` | Small or weak curves (e.g. secp192r1) reduce the effective security of ECDHE key exchange |
| HS-TLS-CIPHER-0012 | No ChaCha20-Poly1305 | Low | 0.0 | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N` | Absence of ChaCha20 limits cipher agility and degrades performance on non-AES-NI hardware |

### 1.3 Certificate (13) — `HS-TLS-CERT-0001..0013`

| ID | Title | Severity | CVSS Score | CVSS Vector | Description |
|----|-------|----------|:----------:|-------------|-------------|
| HS-TLS-CERT-0001 | Certificate expired | Critical | 8.6 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` | An expired certificate cannot be trusted; compliant clients reject the connection or warn users |
| HS-TLS-CERT-0002 | Certificate not yet valid | High | 8.6 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` | Certificate validity has not started; indicates misconfiguration or clock skew |
| HS-TLS-CERT-0003 | Self-signed certificate | High | 8.6 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` | No third-party CA validates identity; any attacker can present a matching self-signed cert (MITM) |
| HS-TLS-CERT-0004 | Hostname mismatch (SAN/CN) | High | 8.6 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` | The certificate does not cover the hostname being connected to; RFC 6125 validation fails |
| HS-TLS-CERT-0005 | Weak signature algorithm (SHA1) | High | 5.9 | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N` | SHA-1 is cryptographically broken (SHAttered); certificates must use SHA-256 or stronger |
| HS-TLS-CERT-0006 | RSA key < 2048 bits | High | 5.9 | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N` | Keys shorter than 2048 bits are factorable with commodity hardware; NIST SP 800-131A requires ≥2048 |
| HS-TLS-CERT-0007 | Incomplete certificate chain | Medium | 4.2 | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N` | Missing intermediate CAs prevent path validation; strict clients may reject the connection |
| HS-TLS-CERT-0008 | Weak public key type/params | Medium | 3.7 | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N` | Non-standard key parameters or deprecated key types reduce effective cryptographic strength |
| HS-TLS-CERT-0009 | Long-lived certificate validity | Low | 0.0 | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N` | Certificates valid for >398 days extend the window of exposure following a key compromise |
| HS-TLS-CERT-0010 | OCSP stapling not supported | Low | 0.0 | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N` | Without stapling, clients must contact the CA OCSP responder in-band, leaking connection metadata |
| HS-TLS-CERT-0011 | OCSP Must-Staple missing | Low | 0.0 | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N` | Without the Must-Staple extension, clients cannot enforce that stapled OCSP responses are provided |
| HS-TLS-CERT-0012 | Certificate transparency SCT missing | Low | 0.0 | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N` | No Signed Certificate Timestamps; cert cannot be audited via Certificate Transparency logs (Chrome policy) |
| HS-TLS-CERT-0013 | RSA key below 3072 bits | Low | 0.0 | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N` | NIST recommends ≥3072-bit RSA post-2030; informational for forward-looking compliance postures |

### 1.4 Scenario (11) — `HS-TLS-SCENARIO-0001..0011`

| ID | Title | Severity | CVSS Score | CVSS Vector | Description |
|----|-------|----------|:----------:|-------------|-------------|
| HS-TLS-SCENARIO-0001 | No TLS_FALLBACK_SCSV | Medium | 3.7 | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N` | Without FALLBACK_SCSV (RFC 7507), an active attacker can force a version downgrade by interfering with ClientHello |
| HS-TLS-SCENARIO-0002 | Forced downgrade to TLS 1.0 | High | 5.3 | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N` | Server accepts a forged low-version ClientHello despite advertising higher protocol support |
| HS-TLS-SCENARIO-0003 | Session tickets without rotation | Low | 0.0 | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N` | Static TLS session ticket keys undermine forward secrecy; compromise of the key decrypts all resumable sessions |
| HS-TLS-SCENARIO-0004 | Weak DH parameters (Logjam) | High | 5.9 | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N` | 512/768/1024-bit DH parameters are susceptible to precomputation attacks (Logjam, CVE-2015-4000) |
| HS-TLS-SCENARIO-0005 | SWEET32 exposure | Medium | 3.7 | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N` | High-volume TLS sessions using 3DES hit the 64-bit birthday bound after ~32 GB, leaking plaintext blocks |
| HS-TLS-SCENARIO-0006 | BEAST exposure (TLS1.0 + CBC) | Medium | 3.7 | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N` | TLS 1.0 CBC mode with predictable IVs enables the BEAST chosen-plaintext attack against session cookies |
| HS-TLS-SCENARIO-0007 | Insecure record fragmentation | Medium | 3.7 | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N` | Non-standard record fragmentation may bypass IDS/firewall inspection or trigger implementation bugs |
| HS-TLS-SCENARIO-0008 | Weak cipher preference (server) | Medium | 3.7 | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N` | Server selects a weak cipher when both strong and weak options are offered by the client |
| HS-TLS-SCENARIO-0009 | TLS 1.3 0-RTT enabled | Low | 0.0 | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N` | 0-RTT data lacks replay protection; applications must handle replayed early data to prevent logical attacks |
| HS-TLS-SCENARIO-0010 | STARTTLS downgrade possible | Medium | 3.7 | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N` | An active MITM can strip the STARTTLS offer, forcing cleartext communication on SMTP/IMAP/POP3 |
| HS-TLS-SCENARIO-0011 | STARTTLS without policy | Medium | 3.7 | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N` | No MTA-STS/DANE/STARTTLS policy allows opportunistic cleartext fallback on email delivery |

### 1.5 Extensions (2) — `HS-TLS-EXTENSION-0011..0012`

| ID | Title | Severity | CVSS Score | CVSS Vector | Description |
|----|-------|----------|:----------:|-------------|-------------|
| HS-TLS-EXTENSION-0011 | ALPN hardening missing for HTTP/2 | Low | 0.0 | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N` | Server offers HTTP/2 via ALPN alongside weak TLS settings; RFC 7540 §9.2 cipher restrictions may be violated |
| HS-TLS-EXTENSION-0012 | ALPN not advertised | Low | 0.0 | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N` | Without ALPN the server cannot negotiate HTTP/2 or other modern application protocols in the TLS handshake |

---

## 2. SSH Findings (10)

### 2.1 KEX (3) — `HS-SSH-KEX-0101..0103`

| ID | Title | Severity | CVSS Score | CVSS Vector | Description |
|----|-------|----------|:----------:|-------------|-------------|
| HS-SSH-KEX-0101 | diffie-hellman-group1-sha1 | High | 5.9 | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N` | 768/1024-bit Group 1 DH is equivalent to Logjam-vulnerable TLS; session keys are at risk of precomputation |
| HS-SSH-KEX-0102 | diffie-hellman-group-exchange-sha1 | High | 5.9 | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N` | SHA-1 based group exchange is deprecated by IETF; use curve25519-sha256 or ecdh-sha2-nistp256 |
| HS-SSH-KEX-0103 | gss-* SHA1 KEX enabled | Medium | 3.7 | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N` | GSSAPI key exchange using SHA-1 as the hash is deprecated; SHA-256 variants should be required |

### 2.2 Host Key (2) — `HS-SSH-HOSTKEY-0104..0105`

| ID | Title | Severity | CVSS Score | CVSS Vector | Description |
|----|-------|----------|:----------:|-------------|-------------|
| HS-SSH-HOSTKEY-0104 | ssh-rsa (SHA1) hostkey | High | 5.9 | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N` | RSA host keys signed with SHA-1 are deprecated; clients should require rsa-sha2-256/512 or Ed25519 |
| HS-SSH-HOSTKEY-0105 | RSA hostkey < 2048 bits | High | 5.9 | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N` | RSA host keys below 2048 bits are factorable with modern hardware; minimum 3072 bits recommended (NIST) |

### 2.3 Cipher (2) — `HS-SSH-CIPHER-0106..0107`

| ID | Title | Severity | CVSS Score | CVSS Vector | Description |
|----|-------|----------|:----------:|-------------|-------------|
| HS-SSH-CIPHER-0106 | CBC ciphers enabled | Medium | 3.7 | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N` | SSH CBC mode is vulnerable to plaintext recovery via a padding oracle when combined with certain implementation flaws |
| HS-SSH-CIPHER-0107 | arcfour/RC4 cipher enabled | High | 5.9 | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N` | RC4 (arcfour) is cryptographically broken with known keystream biases; prohibited by RFC 8758 |

### 2.4 MAC (2) — `HS-SSH-MAC-0108..0109`

| ID | Title | Severity | CVSS Score | CVSS Vector | Description |
|----|-------|----------|:----------:|-------------|-------------|
| HS-SSH-MAC-0108 | hmac-sha1 enabled | Medium | 3.7 | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N` | HMAC-SHA1 is deprecated for integrity; use hmac-sha2-256 or hmac-sha2-512 per current SSH hardening guides |
| HS-SSH-MAC-0109 | umac-64 enabled | Medium | 3.7 | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N` | UMAC-64 provides only 64-bit tags; umac-128 or HMAC-SHA2 variants provide stronger integrity guarantees |

### 2.5 Config (1) — `HS-SSH-CONFIG-0110`

| ID | Title | Severity | CVSS Score | CVSS Vector | Description |
|----|-------|----------|:----------:|-------------|-------------|
| HS-SSH-CONFIG-0110 | SSH banner exposes legacy version | Low | 0.0 | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N` | Advertising SSH-1.x or an old OpenSSH version enables targeted exploit enumeration based on known CVEs |

---

## 3. RDP Findings (5)

### 3.1 TLS (4) — `HS-RDP-TLS-0201..0204`

| ID | Title | Severity | CVSS Score | CVSS Vector | Description |
|----|-------|----------|:----------:|-------------|-------------|
| HS-RDP-TLS-0201 | RDP does not require NLA | High | 7.3 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L` | Without Network Level Authentication, RDP presents a full Windows login screen pre-authentication, exposing it to credential spray and pre-auth exploits (e.g. BlueKeep) |
| HS-RDP-TLS-0202 | RDP accepts TLS 1.0 | High | 5.3 | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N` | TLS 1.0 in RDP is deprecated; subject to the same BEAST and downgrade risks as in HTTPS |
| HS-RDP-TLS-0203 | RDP accepts TLS 1.1 | Medium | 3.7 | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N` | TLS 1.1 is deprecated by RFC 8996; RDP should require TLS 1.2+ |
| HS-RDP-TLS-0204 | RDP certificate invalid/expired | High | 8.6 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` | An invalid or expired RDP certificate cannot authenticate the server identity; MITM trivially possible |

### 3.2 Config (1) — `HS-RDP-CONFIG-0205`

| ID | Title | Severity | CVSS Score | CVSS Vector | Description |
|----|-------|----------|:----------:|-------------|-------------|
| HS-RDP-CONFIG-0205 | RDP weak cipher suites | Medium | 3.7 | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N` | RDP negotiated cipher suites below FIPS 140-2 level; encryption strength inadequate for sensitive sessions |

---

## 4. General / Diagnostic Findings (2)

> These findings are emitted when the scan infrastructure itself encounters issues. They carry no
> CVSS score because they represent operational conditions, not vulnerabilities.

| ID | Title | Severity | CVSS Score | Description |
|----|-------|----------|:----------:|-------------|
| HS-GENERAL-CONFIG-0900 | Target normalization ambiguity | Info | 0.0 | Supplied target string resolves to multiple interpretations; scan may target unintended host or port |
| HS-GENERAL-CONFIG-0901 | DNS resolution failed | Info | 0.0 | The hostname could not be resolved; endpoint is unreachable and posture cannot be determined |
| HS-GENERAL-CONFIG-0902 | Connection timeout | Info | 0.0 | TCP connection to the target exceeded the configured timeout; firewall or host is unresponsive |
| HS-GENERAL-CONFIG-0903 | Protocol auto-detect mismatch | Info | 0.0 | Port is reachable but does not speak the expected protocol; results may be incomplete or incorrect |
| HS-GENERAL-CONFIG-0904 | Policy profile missing/invalid | Info | 0.0 | The referenced YAML policy file cannot be loaded; compliance evaluation was skipped |

---

## 5. Testssl-Class Coverage Matrix

Maps [testssl.sh](https://testssl.sh) check categories to equivalent Handshaker finding IDs and
their implementation files.

| testssl.sh Class | Handshaker Finding ID(s) | Implementation File |
|-----------------|--------------------------|---------------------|
| Protocol enumeration | HS-TLS-PROTOCOL-0001..0006 | `src/protocols/tls/versions.rs` |
| Cipher enumeration | HS-TLS-CIPHER-0001..0012 | `src/protocols/tls/ciphers.rs` |
| Weak ciphers (NULL/aNULL/EXPORT/RC4) | HS-TLS-CIPHER-0001, 0002, 0003, 0004 | `src/protocols/tls/ciphers.rs` |
| Medium-strength ciphers | HS-TLS-CIPHER-0007 | `src/protocols/tls/ciphers.rs` |
| 3DES / SWEET32 | HS-TLS-CIPHER-0005, HS-TLS-SCENARIO-0005 | `src/protocols/tls/ciphers.rs`, `scenarios.rs` |
| BEAST (CBC + TLS1.0) | HS-TLS-CIPHER-0006, HS-TLS-SCENARIO-0006 | `src/protocols/tls/ciphers.rs`, `scenarios.rs` |
| Forward secrecy indicators | HS-TLS-CIPHER-0009 | `src/protocols/tls/ciphers.rs` |
| Certificate validation | HS-TLS-CERT-0001..0008 | `src/protocols/tls/certs.rs` |
| Hostname mismatch | HS-TLS-CERT-0004 | `src/protocols/tls/certs.rs` |
| RSA key size | HS-TLS-CERT-0006, 0013 | `src/protocols/tls/certs.rs` |
| SHA-1 signature | HS-TLS-CERT-0005 | `src/protocols/tls/certs.rs` |
| OCSP stapling | HS-TLS-CERT-0010, 0011 | `src/protocols/tls/certs.rs` |
| Certificate transparency | HS-TLS-CERT-0012 | `src/protocols/tls/certs.rs` |
| Renegotiation posture | HS-TLS-PROTOCOL-0007, 0008 | `src/protocols/tls/scenarios.rs` |
| TLS compression (CRIME) | HS-TLS-PROTOCOL-0009 | `src/protocols/tls/scenarios.rs` |
| Downgrade resilience | HS-TLS-SCENARIO-0001, 0002 | `src/protocols/tls/scenarios.rs` |
| Logjam weak DH | HS-TLS-SCENARIO-0004 | `src/protocols/tls/scenarios.rs` |
| Session resumption | HS-TLS-SCENARIO-0003 | `src/protocols/tls/scenarios.rs` |
| STARTTLS downgrade | HS-TLS-SCENARIO-0010, 0011 | `src/protocols/tls/starttls.rs` |
| ALPN negotiation | HS-TLS-EXTENSION-0011, 0012 | `src/protocols/tls/` |
| SSH KEX algorithms | HS-SSH-KEX-0101..0103 | `src/protocols/ssh/algos.rs` |
| SSH host key | HS-SSH-HOSTKEY-0104, 0105 | `src/protocols/ssh/algos.rs` |
| SSH ciphers | HS-SSH-CIPHER-0106, 0107 | `src/protocols/ssh/algos.rs` |
| SSH MACs | HS-SSH-MAC-0108, 0109 | `src/protocols/ssh/algos.rs` |
| RDP NLA enforcement | HS-RDP-TLS-0201 | `src/protocols/rdp/` |
| RDP TLS version | HS-RDP-TLS-0202, 0203 | `src/protocols/rdp/` |
| RDP certificate | HS-RDP-TLS-0204 | `src/protocols/rdp/` |

---

## 6. Policy Profile Cross-Reference

Shows which findings are **forbidden** (i.e. flagged as a compliance failure) under each policy
profile. A check mark means the finding triggers a policy violation when detected.

| Finding ID | Default | PCI-DSS | NIST 800-52r2 | CIS-Like |
|------------|:-------:|:-------:|:-------------:|:--------:|
| HS-TLS-PROTOCOL-0001 | ✓ | ✓ | ✓ | ✓ |
| HS-TLS-PROTOCOL-0002 | ✓ | ✓ | ✓ | ✓ |
| HS-TLS-PROTOCOL-0003 | ✓ | ✓ | ✓ | ✓ |
| HS-TLS-PROTOCOL-0004 | ✓ | ✓ | ✓ | ✓ |
| HS-TLS-PROTOCOL-0005 | | ✓ | ✓ | ✓ |
| HS-TLS-PROTOCOL-0006 | | | | ✓ |
| HS-TLS-PROTOCOL-0007 | | ✓ | ✓ | ✓ |
| HS-TLS-PROTOCOL-0008 | | ✓ | ✓ | ✓ |
| HS-TLS-PROTOCOL-0009 | | ✓ | ✓ | ✓ |
| HS-TLS-PROTOCOL-0010 | | | | ✓ |
| HS-TLS-CIPHER-0001 | ✓ | ✓ | ✓ | ✓ |
| HS-TLS-CIPHER-0002 | ✓ | ✓ | ✓ | ✓ |
| HS-TLS-CIPHER-0003 | ✓ | ✓ | ✓ | ✓ |
| HS-TLS-CIPHER-0004 | | ✓ | ✓ | ✓ |
| HS-TLS-CIPHER-0005 | | ✓ | ✓ | ✓ |
| HS-TLS-CIPHER-0006 | | | ✓ | ✓ |
| HS-TLS-CIPHER-0007 | | | | ✓ |
| HS-TLS-CIPHER-0008 | | ✓ | ✓ | ✓ |
| HS-TLS-CIPHER-0009 | | ✓ | ✓ | ✓ |
| HS-TLS-CIPHER-0010 | | | ✓ | ✓ |
| HS-TLS-CIPHER-0011 | | | | ✓ |
| HS-TLS-CIPHER-0012 | | | | ✓ |
| HS-TLS-CERT-0001 | ✓ | ✓ | ✓ | ✓ |
| HS-TLS-CERT-0002 | ✓ | ✓ | ✓ | ✓ |
| HS-TLS-CERT-0003 | ✓ | ✓ | ✓ | ✓ |
| HS-TLS-CERT-0004 | ✓ | ✓ | ✓ | ✓ |
| HS-TLS-CERT-0005 | ✓ | ✓ | ✓ | ✓ |
| HS-TLS-CERT-0006 | ✓ | ✓ | ✓ | ✓ |
| HS-TLS-CERT-0007 | | ✓ | ✓ | ✓ |
| HS-TLS-CERT-0008 | | | ✓ | ✓ |
| HS-TLS-CERT-0009 | | | | ✓ |
| HS-TLS-CERT-0010 | | | ✓ | ✓ |
| HS-TLS-CERT-0011 | | | ✓ | ✓ |
| HS-TLS-CERT-0012 | | | | ✓ |
| HS-TLS-CERT-0013 | | | | ✓ |
| HS-TLS-SCENARIO-0001 | | ✓ | ✓ | ✓ |
| HS-TLS-SCENARIO-0002 | | ✓ | ✓ | ✓ |
| HS-TLS-SCENARIO-0003 | | | ✓ | ✓ |
| HS-TLS-SCENARIO-0004 | | ✓ | ✓ | ✓ |
| HS-TLS-SCENARIO-0005 | | ✓ | ✓ | ✓ |
| HS-TLS-SCENARIO-0006 | | | ✓ | ✓ |
| HS-TLS-SCENARIO-0007 | | | | ✓ |
| HS-TLS-SCENARIO-0008 | | ✓ | ✓ | ✓ |
| HS-TLS-SCENARIO-0009 | | | | ✓ |
| HS-TLS-SCENARIO-0010 | | ✓ | ✓ | ✓ |
| HS-TLS-SCENARIO-0011 | | ✓ | ✓ | ✓ |
| HS-TLS-EXTENSION-0011 | | | | ✓ |
| HS-TLS-EXTENSION-0012 | | | | ✓ |
| HS-SSH-KEX-0101 | ✓ | | ✓ | ✓ |
| HS-SSH-KEX-0102 | | | ✓ | ✓ |
| HS-SSH-KEX-0103 | | | | ✓ |
| HS-SSH-HOSTKEY-0104 | ✓ | | ✓ | ✓ |
| HS-SSH-HOSTKEY-0105 | ✓ | | ✓ | ✓ |
| HS-SSH-CIPHER-0106 | | | ✓ | ✓ |
| HS-SSH-CIPHER-0107 | | | ✓ | ✓ |
| HS-SSH-MAC-0108 | | | | ✓ |
| HS-SSH-MAC-0109 | | | | ✓ |
| HS-SSH-CONFIG-0110 | | | | ✓ |
| HS-RDP-TLS-0201 | ✓ | | ✓ | ✓ |
| HS-RDP-TLS-0202 | | ✓ | ✓ | ✓ |
| HS-RDP-TLS-0203 | | | ✓ | ✓ |
| HS-RDP-TLS-0204 | | ✓ | ✓ | ✓ |
| HS-RDP-CONFIG-0205 | | | ✓ | ✓ |
| HS-GENERAL-CONFIG-0900..0904 | | | | |

> Policy profile YAML files are located in `policies/` at the project root.
> Load a profile with: `handshaker scan --policy policies/pci-dss.yml <target>`

---

*Generated for Handshaker v7.3.0 — Source: `src/findings/catalog.rs`*
