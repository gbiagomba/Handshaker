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
| Protocols | TLS (48), SSH (10), RDP (5), General (5) |

## Finding Statistics

| Total | Critical | High | Medium | Low | Info |
|-------|:--------:|:----:|:------:|:---:|:----:|
| 68 | 2 | 4 | 33 | 9 | 20 |

---

## 1. TLS Findings (48)

### 1.1 Protocol (10) — `HS-TLS-PROTOCOL-0001..0010`

| ID | Title | Severity | CVSS Score | CVSS Vector | Description |
|----|-------|----------|:----------:|-------------|-------------|
| HS-TLS-PROTOCOL-0001 | SSLv2 supported | Critical | 9.8 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` | Obsolete protocol with severe cryptographic weaknesses; all data is at risk |
| HS-TLS-PROTOCOL-0002 | SSLv3 supported | High | 8.6 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L` | SSLv3 is vulnerable to POODLE and other attacks; must be disabled (CVE-2014-3566) |
| HS-TLS-PROTOCOL-0003 | TLS 1.0 enabled | Medium | 6.5 | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:N` | TLS 1.0 is deprecated (PCI-DSS 3.2+) and lacks modern cipher support |
| HS-TLS-PROTOCOL-0004 | TLS 1.1 enabled | Medium | 6.5 | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:N` | TLS 1.1 lacks AEAD suites and is deprecated by RFC 8996 |
| HS-TLS-PROTOCOL-0005 | TLS 1.2 not supported | High | 7.3 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L` | Absence of TLS 1.2 forces clients onto weaker legacy protocol versions |
| HS-TLS-PROTOCOL-0006 | TLS 1.3 not supported | Info | 0.0 | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N` | TLS 1.3 removes legacy features and provides 0-RTT; its absence is a missed hardening opportunity |
| HS-TLS-PROTOCOL-0007 | Insecure renegotiation allowed | Medium | 6.5 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N` | Insecure renegotiation enables injection of plaintext by an active MITM (CVE-2009-3555) |
| HS-TLS-PROTOCOL-0008 | Secure renegotiation not supported | Medium | 4.8 | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N` | Without RFC 5746, clients fall back to insecure renegotiation |
| HS-TLS-PROTOCOL-0009 | TLS compression enabled (CRIME) | Medium | 4.8 | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N` | TLS-layer compression enables the CRIME attack to recover secrets from encrypted streams |
| HS-TLS-PROTOCOL-0010 | HTTP/2 over weak TLS | Medium | 4.8 | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N` | Offering HTTP/2 alongside deprecated TLS versions widens the downgrade attack surface |

### 1.2 Cipher (12) — `HS-TLS-CIPHER-0001..0012`

| ID | Title | Severity | CVSS Score | CVSS Vector | Description |
|----|-------|----------|:----------:|-------------|-------------|
| HS-TLS-CIPHER-0001 | NULL cipher suite | Critical | 9.8 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` | No encryption; all traffic transmitted in cleartext and trivially intercepted or modified |
| HS-TLS-CIPHER-0002 | Anonymous (aNULL) cipher | Medium | 5.9 | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N` | No server authentication; any attacker can impersonate the server without a certificate |
| HS-TLS-CIPHER-0003 | EXPORT cipher suite | High | 7.4 | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N` | 40/56-bit export-grade ciphers are trivially breakable with modern hardware (FREAK — CVE-2015-0204) |
| HS-TLS-CIPHER-0004 | RC4 cipher suite | Medium | 5.9 | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N` | RC4 has well-documented statistical biases that allow plaintext recovery in high-volume sessions |
| HS-TLS-CIPHER-0005 | 3DES cipher (SWEET32) | High | 7.5 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` | 3DES uses 64-bit blocks; birthday attacks after ~32 GB of traffic can recover plaintext (CVE-2016-2183) |
| HS-TLS-CIPHER-0006 | CBC-only with TLS 1.0 (BEAST) | Medium | 4.8 | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N` | Predictable IV in TLS 1.0 CBC mode enables the BEAST attack against certain session data |
| HS-TLS-CIPHER-0007 | Weak medium-strength ciphers | Medium | 4.8 | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N` | Ciphers with 64–112 bit effective strength are susceptible to brute-force in targeted attacks |
| HS-TLS-CIPHER-0008 | No AEAD suites available | Medium | 4.8 | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N` | Without AEAD (e.g. AES-GCM), the server is exposed to padding oracle and ciphertext tampering attacks |
| HS-TLS-CIPHER-0009 | No forward secrecy suites | Medium | 4.8 | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N` | Static RSA key exchange means compromise of the private key allows decryption of all recorded past sessions |
| HS-TLS-CIPHER-0010 | Legacy RSA key exchange | Medium | 4.8 | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N` | Non-ephemeral RSA exchange provides no forward secrecy; sessions can be retroactively decrypted |
| HS-TLS-CIPHER-0011 | Weak elliptic curve supported | Medium | 4.8 | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N` | Small or weak curves (e.g. secp192r1) reduce the effective security of ECDHE key exchange |
| HS-TLS-CIPHER-0012 | No ChaCha20-Poly1305 | Info | 0.0 | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N` | Absence of ChaCha20 limits cipher agility and degrades performance on non-AES-NI hardware |

### 1.3 Certificate (13) — `HS-TLS-CERT-0001..0013`

| ID | Title | Severity | CVSS Score | CVSS Vector | Description |
|----|-------|----------|:----------:|-------------|-------------|
| HS-TLS-CERT-0001 | Certificate expired | Medium | 5.3 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N` | An expired certificate cannot be trusted; compliant clients reject the connection, causing outage |
| HS-TLS-CERT-0002 | Certificate not yet valid | Info | 0.0 | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N` | Certificate validity has not started; indicates misconfiguration or clock skew |
| HS-TLS-CERT-0003 | Self-signed certificate | Medium | 6.5 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N` | No third-party CA validates identity; any attacker can present a matching self-signed cert (MITM) |
| HS-TLS-CERT-0004 | Hostname mismatch (SAN/CN) | Medium | 4.8 | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N` | The certificate does not cover the hostname being connected to; RFC 6125 validation fails, enabling MITM |
| HS-TLS-CERT-0005 | Weak signature algorithm (SHA1) | Medium | 5.3 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N` | SHA-1 is cryptographically broken (SHAttered); certificates must use SHA-256 or stronger |
| HS-TLS-CERT-0006 | RSA key < 2048 bits | Low | 3.7 | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N` | Keys shorter than 2048 bits are factorable with commodity hardware; NIST SP 800-131A requires ≥2048 |
| HS-TLS-CERT-0007 | Incomplete certificate chain | Medium | 5.3 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N` | Missing intermediate CAs prevent path validation; strict clients may reject the connection |
| HS-TLS-CERT-0008 | Weak public key type/params | Medium | 5.3 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N` | Non-standard key parameters or deprecated key types reduce effective cryptographic strength |
| HS-TLS-CERT-0009 | Long-lived certificate validity | Info | 0.0 | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N` | Certificates valid for >398 days extend the window of exposure following a key compromise |
| HS-TLS-CERT-0010 | OCSP stapling not supported | Info | 0.0 | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N` | Without stapling, clients must contact the CA OCSP responder in-band, leaking connection metadata |
| HS-TLS-CERT-0011 | OCSP Must-Staple missing | Info | 0.0 | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N` | Without the Must-Staple extension, clients cannot enforce that stapled OCSP responses are provided |
| HS-TLS-CERT-0012 | Certificate transparency SCT missing | Info | 0.0 | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N` | No Signed Certificate Timestamps; cert cannot be audited via Certificate Transparency logs (Chrome policy) |
| HS-TLS-CERT-0013 | RSA key below 3072 bits | Info | 0.0 | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N` | NIST recommends ≥3072-bit RSA post-2030; informational for forward-looking compliance postures |

### 1.4 Scenario (11) — `HS-TLS-SCENARIO-0001..0011`

| ID | Title | Severity | CVSS Score | CVSS Vector | Description |
|----|-------|----------|:----------:|-------------|-------------|
| HS-TLS-SCENARIO-0001 | No TLS_FALLBACK_SCSV | Medium | 4.8 | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N` | Without FALLBACK_SCSV (RFC 7507), an active attacker can force a version downgrade by interfering with ClientHello |
| HS-TLS-SCENARIO-0002 | Forced downgrade to TLS 1.0 | Medium | 4.8 | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N` | Server accepts a forged low-version ClientHello despite advertising higher protocol support |
| HS-TLS-SCENARIO-0003 | Session tickets without rotation | Info | 0.0 | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N` | Static TLS session ticket keys undermine forward secrecy; compromise of the key decrypts all resumable sessions |
| HS-TLS-SCENARIO-0004 | Weak DH parameters (Logjam) | Low | 3.7 | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N` | 512/768/1024-bit DH parameters are susceptible to precomputation attacks (Logjam, CVE-2015-4000) |
| HS-TLS-SCENARIO-0005 | SWEET32 exposure | Medium | 4.8 | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N` | High-volume TLS sessions using 3DES hit the 64-bit birthday bound after ~32 GB, leaking plaintext blocks |
| HS-TLS-SCENARIO-0006 | BEAST exposure (TLS1.0 + CBC) | Medium | 4.8 | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N` | TLS 1.0 CBC mode with predictable IVs enables the BEAST chosen-plaintext attack against session cookies |
| HS-TLS-SCENARIO-0007 | Insecure record fragmentation | Medium | 4.8 | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N` | Non-standard record fragmentation may bypass IDS/firewall inspection or trigger implementation bugs |
| HS-TLS-SCENARIO-0008 | Weak cipher preference (server) | Medium | 4.8 | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N` | Server selects a weak cipher when both strong and weak options are offered by the client |
| HS-TLS-SCENARIO-0009 | TLS 1.3 0-RTT enabled | Info | 0.0 | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N` | 0-RTT data lacks replay protection; applications must handle replayed early data to prevent logical attacks |
| HS-TLS-SCENARIO-0010 | STARTTLS downgrade possible | Medium | 4.8 | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N` | An active MITM can strip the STARTTLS offer, forcing cleartext communication on SMTP/IMAP/POP3 |
| HS-TLS-SCENARIO-0011 | STARTTLS without policy | Medium | 4.8 | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N` | No MTA-STS/DANE/STARTTLS policy allows opportunistic cleartext fallback on email delivery |

### 1.5 Extensions (2) — `HS-TLS-EXTENSION-0011..0012`

| ID | Title | Severity | CVSS Score | CVSS Vector | Description |
|----|-------|----------|:----------:|-------------|-------------|
| HS-TLS-EXTENSION-0011 | ALPN hardening missing for HTTP/2 | Info | 0.0 | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N` | Server offers HTTP/2 via ALPN alongside weak TLS settings; RFC 7540 §9.2 cipher restrictions may be violated |
| HS-TLS-EXTENSION-0012 | ALPN not advertised | Info | 0.0 | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N` | Without ALPN the server cannot negotiate HTTP/2 or other modern application protocols in the TLS handshake |

---

## 2. SSH Findings (10)

### 2.1 KEX (3) — `HS-SSH-KEX-0101..0103`

| ID | Title | Severity | CVSS Score | CVSS Vector | Description |
|----|-------|----------|:----------:|-------------|-------------|
| HS-SSH-KEX-0101 | diffie-hellman-group1-sha1 | Low | 3.7 | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N` | 768/1024-bit Group 1 DH is equivalent to Logjam-vulnerable TLS; session keys are at risk of precomputation |
| HS-SSH-KEX-0102 | diffie-hellman-group-exchange-sha1 | Low | 3.7 | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N` | SHA-1 based group exchange is deprecated by IETF; use curve25519-sha256 or ecdh-sha2-nistp256 |
| HS-SSH-KEX-0103 | gss-* SHA1 KEX enabled | Low | 3.7 | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N` | GSSAPI key exchange using SHA-1 as the hash is deprecated; SHA-256 variants should be required |

### 2.2 Host Key (2) — `HS-SSH-HOSTKEY-0104..0105`

| ID | Title | Severity | CVSS Score | CVSS Vector | Description |
|----|-------|----------|:----------:|-------------|-------------|
| HS-SSH-HOSTKEY-0104 | ssh-rsa (SHA1) hostkey | Low | 3.7 | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N` | RSA host keys signed with SHA-1 are deprecated; clients should require rsa-sha2-256/512 or Ed25519 |
| HS-SSH-HOSTKEY-0105 | RSA hostkey < 2048 bits | Low | 3.7 | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N` | RSA host keys below 2048 bits are factorable with modern hardware; minimum 3072 bits recommended (NIST) |

### 2.3 Cipher (2) — `HS-SSH-CIPHER-0106..0107`

| ID | Title | Severity | CVSS Score | CVSS Vector | Description |
|----|-------|----------|:----------:|-------------|-------------|
| HS-SSH-CIPHER-0106 | CBC ciphers enabled | Low | 3.7 | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N` | SSH CBC mode is vulnerable to plaintext recovery via a padding oracle when combined with certain implementation flaws |
| HS-SSH-CIPHER-0107 | arcfour/RC4 cipher enabled | Medium | 5.9 | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N` | RC4 (arcfour) is cryptographically broken with known keystream biases; prohibited by RFC 8758 |

### 2.4 MAC (2) — `HS-SSH-MAC-0108..0109`

| ID | Title | Severity | CVSS Score | CVSS Vector | Description |
|----|-------|----------|:----------:|-------------|-------------|
| HS-SSH-MAC-0108 | hmac-sha1 enabled | Info | 0.0 | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N` | HMAC-SHA1 is deprecated for integrity; use hmac-sha2-256 or hmac-sha2-512 per current SSH hardening guides |
| HS-SSH-MAC-0109 | umac-64 enabled | Low | 3.7 | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N` | UMAC-64 provides only 64-bit tags; umac-128 or HMAC-SHA2 variants provide stronger integrity guarantees |

### 2.5 Config (1) — `HS-SSH-CONFIG-0110`

| ID | Title | Severity | CVSS Score | CVSS Vector | Description |
|----|-------|----------|:----------:|-------------|-------------|
| HS-SSH-CONFIG-0110 | SSH banner exposes legacy version | Info | 0.0 | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N` | Advertising SSH-1.x or an old OpenSSH version enables targeted exploit enumeration based on known CVEs |

---

## 3. RDP Findings (5)

### 3.1 TLS (4) — `HS-RDP-TLS-0201..0204`

| ID | Title | Severity | CVSS Score | CVSS Vector | Description |
|----|-------|----------|:----------:|-------------|-------------|
| HS-RDP-TLS-0201 | RDP does not require NLA | Medium | 4.0 | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:L/I:N/A:N` | Without Network Level Authentication, RDP presents a full Windows login screen pre-authentication, exposing it to credential spray and pre-auth exploits (e.g. BlueKeep) |
| HS-RDP-TLS-0202 | RDP accepts TLS 1.0 | Medium | 4.8 | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N` | TLS 1.0 in RDP is deprecated; subject to the same BEAST and downgrade risks as in HTTPS |
| HS-RDP-TLS-0203 | RDP accepts TLS 1.1 | Medium | 4.8 | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N` | TLS 1.1 is deprecated by RFC 8996; RDP should require TLS 1.2+ |
| HS-RDP-TLS-0204 | RDP certificate invalid/expired | Medium | 5.3 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N` | An invalid or expired RDP certificate cannot authenticate the server identity; MITM trivially possible |

### 3.2 Config (1) — `HS-RDP-CONFIG-0205`

| ID | Title | Severity | CVSS Score | CVSS Vector | Description |
|----|-------|----------|:----------:|-------------|-------------|
| HS-RDP-CONFIG-0205 | RDP weak cipher suites | Medium | 5.3 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` | RDP negotiated cipher suites below FIPS 140-2 level; encryption strength inadequate for sensitive sessions |

---

## 4. General / Diagnostic Findings (5)

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

## 7. Finding Details

Standards references, CVSS vector explanations, severity reasoning, and attack prerequisites for each finding.

---

### HS-TLS-PROTOCOL-0001 — SSLv2 Supported

**Severity:** Critical | **CVSS Score:** 9.8 | **Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`

**CVE References:** No single CVE; SSLv2 design flaws documented in RFC 6176 (prohibits SSLv2)
**CWE:** CWE-326 (Inadequate Encryption Strength)
**OWASP:** A02:2021 – Cryptographic Failures
**WASC:** WASC-4 – Insufficient Transport Layer Protection

**CVSS Vector Explanation:**
- AV:N — Exploitable over the network
- AC:L — No special conditions required; any client can negotiate SSLv2
- PR:N — No privileges required
- UI:N — No user interaction required
- S:U — Scope unchanged
- C:H — Full confidentiality breach (session plaintext recovery)
- I:H — Full integrity breach (data manipulation possible)
- A:H — Availability impact (compliant clients may refuse to connect)

**Severity Reasoning:** SSLv2 uses 40-bit export ciphers, MD5 for MAC, and has no protection against protocol rollback. RFC 6176 prohibits all use. Any exploitation leads to full compromise of confidentiality and integrity. Availability impact added because modern compliant clients and proxies will abort connections negotiating SSLv2, causing service disruption.

**Attack Prerequisites:**
- Network path between attacker and target (passive or active)
- Client that can be induced to negotiate SSLv2

---

### HS-TLS-PROTOCOL-0002 — SSLv3 Supported

**Severity:** High | **CVSS Score:** 8.6 | **Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L`

**CVE References:** CVE-2014-3566 (POODLE)
**CWE:** CWE-326 (Inadequate Encryption Strength)
**OWASP:** A02:2021 – Cryptographic Failures
**WASC:** WASC-4 – Insufficient Transport Layer Protection

**CVSS Vector Explanation:**
- AV:N — Network exploitable
- AC:L — Low complexity; attacker forces downgrade via connection interference
- PR:N — No privileges required
- UI:N — No user interaction required
- C:H — Confidentiality fully compromised via POODLE decryption
- I:L — Integrity impact is limited to negotiated-session tampering or downgrade-assisted manipulation
- A:L — Some compliant clients will fail closed, creating limited availability impact

**Severity Reasoning:** SSLv3 is broken by the POODLE attack (CVE-2014-3566), allowing an active MITM to decrypt cookies and session tokens via adaptive chosen-ciphertext. NVD rates POODLE at 3.1 (specific exploit path), but the protocol weakness itself warrants High as it enables full session hijacking. Tenable Plugin 58571 rates as High.

**Attack Prerequisites:**
- Active MITM position on the network path
- Ability to force client to fall back to SSLv3 (JavaScript injection or network-level attack)
- Repeated request capability (JavaScript or keep-alive session)

---

### HS-TLS-PROTOCOL-0003 — TLS 1.0 Enabled

**Severity:** Medium | **CVSS Score:** 6.5 | **Vector:** `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:N`

**CVE References:** CVE-2011-3389 (BEAST)
**CWE:** CWE-326 (Inadequate Encryption Strength)
**OWASP:** A02:2021 – Cryptographic Failures
**WASC:** WASC-4 – Insufficient Transport Layer Protection

**CVSS Vector Explanation:**
- AV:N — Network exploitable
- AC:H — High complexity; requires specific conditions (JavaScript injection + CBC ciphers)
- C:H — Strong confidentiality impact because deprecated TLS 1.0 commonly exposes sessions to downgrade and legacy-cipher attacks
- I:L — Partial integrity impact (downgrade to weaker cipher suites possible)
- A:N — Service remains available

**Severity Reasoning:** Tenable Plugin 104743 rates TLS 1.0 as Medium. PCI DSS 3.2+ prohibits TLS 1.0 for payment data. The BEAST attack (CVE-2011-3389) requires high complexity conditions. NVD rates BEAST at 3.7 but the broader TLS 1.0 deprecation with all associated risks warrants Medium.

**Attack Prerequisites:**
- Active MITM network position for downgrade scenarios
- JavaScript injection capability for BEAST
- Target using CBC mode ciphers with TLS 1.0

---

### HS-TLS-PROTOCOL-0004 — TLS 1.1 Enabled

**Severity:** Medium | **CVSS Score:** 6.5 | **Vector:** `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:N`

**CVE References:** RFC 8996 (deprecation)
**CWE:** CWE-326 (Inadequate Encryption Strength)
**OWASP:** A02:2021 – Cryptographic Failures
**WASC:** WASC-4 – Insufficient Transport Layer Protection

**CVSS Vector Explanation:**
- AV:N — Network exploitable
- AC:H — Exploitation requires active downgrade attack
- C:H — Strong confidentiality impact via downgrade to weaker cipher suites
- I:L — Partial integrity impact
- A:N — Service available

**Severity Reasoning:** TLS 1.1 does not support AEAD cipher suites (GCM, ChaCha20) and is deprecated by RFC 8996. Tenable Plugin 157288 rates as Medium. No direct critical CVE exists; risk stems from missing modern cipher and MAC features.

**Attack Prerequisites:**
- Active MITM to force TLS 1.1 negotiation when TLS 1.2+ is available
- Client that can be induced to downgrade

---

### HS-TLS-PROTOCOL-0005 — TLS 1.2 Not Supported

**Severity:** High | **CVSS Score:** 7.3 | **Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L`

**CVE References:** None specific; systemic risk from forced legacy protocol use
**CWE:** CWE-326 (Inadequate Encryption Strength)
**OWASP:** A02:2021 – Cryptographic Failures
**WASC:** WASC-4 – Insufficient Transport Layer Protection

**CVSS Vector Explanation:**
- AV:N — Network exploitable
- AC:L — Trivially triggered: any modern client that requires TLS 1.2 may fail or fall back
- C:L / I:L / A:L — All CIA impacts: clients forced to use weak protocols or fail to connect

**Severity Reasoning:** Absence of TLS 1.2 forces all connections onto TLS 1.0/1.1 or causes connection failures. NIST SP 800-52r2 mandates TLS 1.2 support. Availability impact included because strict clients will refuse connections.

**Attack Prerequisites:**
- Passive observation only; the vulnerability exists by server configuration alone

---

### HS-TLS-PROTOCOL-0006 — TLS 1.3 Not Supported

**Severity:** Info | **CVSS Score:** 0.0 | **Vector:** `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N`

**CVE References:** None
**CWE:** CWE-326 (informational — missed hardening)
**OWASP:** A02:2021 – Cryptographic Failures (informational)

**CVSS Vector Explanation:**
- C:N / I:N / A:N — No direct impact; scored 0.0

**Severity Reasoning:** TLS 1.3 support is best practice (removes CBC, RSA key exchange, compression, and renegotiation) but its absence alone is not exploitable. Rated informational per industry consensus.

**Attack Prerequisites:** None (informational finding only)

---

### HS-TLS-PROTOCOL-0007 — Insecure Renegotiation Allowed

**Severity:** Medium | **CVSS Score:** 6.5 | **Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N`

**CVE References:** CVE-2009-3555
**CWE:** CWE-295 (Improper Certificate Validation), CWE-264
**OWASP:** A02:2021 – Cryptographic Failures
**WASC:** WASC-4 – Insufficient Transport Layer Protection

**CVSS Vector Explanation:**
- AV:N — Network exploitable
- AC:L — Requires only active MITM, no special cryptographic conditions
- C:L — Partial confidentiality via injected data
- I:L — Partial integrity via plaintext injection into negotiated session
- A:N — Service available

**Severity Reasoning:** CVE-2009-3555 allows an active MITM to inject arbitrary plaintext at the start of a renegotiated TLS session. NVD CVSS 3.1 = 6.5 Medium. RFC 5746 provides the fix (secure renegotiation extension).

**Attack Prerequisites:**
- Active MITM position on the TCP connection
- Server must accept renegotiation (not disabled)
- Protocol-level ability to inject data before renegotiation handshake completes

---

### HS-TLS-PROTOCOL-0008 — Secure Renegotiation Not Supported

**Severity:** Medium | **CVSS Score:** 4.8 | **Vector:** `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N`

**CVE References:** CVE-2009-3555 (related)
**CWE:** CWE-295 (Improper Certificate Validation)
**OWASP:** A02:2021 – Cryptographic Failures

**CVSS Vector Explanation:**
- AV:N — Network exploitable
- AC:H — Requires MITM and specific conditions (old client, renegotiation in progress)
- C:L / I:L — Partial CIA impacts via injection during renegotiation window

**Severity Reasoning:** Without RFC 5746 secure renegotiation, clients initiating renegotiation may be vulnerable. Lower than HS-TLS-PROTOCOL-0007 because this is passive (server does not initiate insecure renegotiation) vs. active acceptance.

**Attack Prerequisites:**
- Client that initiates renegotiation
- MITM position to intercept renegotiation handshake
- Server that allows renegotiation without RFC 5746

---

### HS-TLS-PROTOCOL-0009 — TLS Compression Enabled (CRIME)

**Severity:** Medium | **CVSS Score:** 4.8 | **Vector:** `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N`

**CVE References:** CVE-2012-4929 (CRIME)
**CWE:** CWE-311 (Missing Encryption of Sensitive Data)
**OWASP:** A02:2021 – Cryptographic Failures

**CVSS Vector Explanation:**
- AV:N — Network exploitable
- AC:H — Requires JavaScript injection capability to force known-plaintext requests
- C:L — Partial confidentiality; session cookies or tokens can be recovered
- I:L — Partial integrity; recovered tokens enable session hijacking

**Severity Reasoning:** CVE-2012-4929 (CRIME) exploits TLS compression to recover HTTP session cookies by observing ciphertext length changes under attacker-controlled input. Modern browsers disable TLS compression; server-side risk is low but nonzero for non-browser clients.

**Attack Prerequisites:**
- Active MITM with ability to inject JavaScript or force repeated requests
- Target session using HTTPS with TLS-level compression enabled
- Attacker can observe ciphertext lengths

---

### HS-TLS-PROTOCOL-0010 — HTTP/2 Over Weak TLS Settings

**Severity:** Medium | **CVSS Score:** 4.8 | **Vector:** `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N`

**CVE References:** None specific
**CWE:** CWE-326 (Inadequate Encryption Strength)
**OWASP:** A02:2021 – Cryptographic Failures

**CVSS Vector Explanation:**
- AV:N — Network exploitable
- AC:H — Requires downgrade to weak cipher on H2 connection
- C:L / I:L — Partial impacts via RFC 7540 §9.2 violations

**Severity Reasoning:** RFC 7540 §9.2 prohibits HTTP/2 over TLS 1.0/1.1 or with blacklisted cipher suites. Offering HTTP/2 over deprecated TLS versions violates the spec and can enable downgrade attacks.

**Attack Prerequisites:**
- Client that negotiates HTTP/2 over weak TLS
- Active MITM to force cipher downgrade

---

### HS-TLS-CIPHER-0001 — NULL Cipher Suite

**Severity:** Critical | **CVSS Score:** 9.8 | **Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`

**CVE References:** None (configuration vulnerability)
**CWE:** CWE-312 (Cleartext Storage of Sensitive Information), CWE-319 (Cleartext Transmission)
**OWASP:** A02:2021 – Cryptographic Failures
**WASC:** WASC-4 – Insufficient Transport Layer Protection

**CVSS Vector Explanation:**
- AC:L — No special conditions; NULL cipher is selected automatically if offered
- C:H / I:H / A:H — All traffic visible and modifiable; service may be unusable

**Severity Reasoning:** NULL cipher suites provide no encryption whatsoever. Any on-path attacker can read and modify all session data without any cryptographic work. This is equivalent to plain HTTP/TCP.

**Attack Prerequisites:**
- Passive observation capability (any network path)
- No cryptographic prerequisites

---

### HS-TLS-CIPHER-0002 — Anonymous (aNULL) Cipher Suite

**Severity:** Medium | **CVSS Score:** 5.9 | **Vector:** `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N`

**CVE References:** None (configuration vulnerability)
**CWE:** CWE-345 (Insufficient Verification of Data Authenticity), CWE-306
**OWASP:** A07:2021 – Identification and Authentication Failures
**WASC:** WASC-4 – Insufficient Transport Layer Protection

**CVSS Vector Explanation:**
- AC:H — Exploitation still requires an active MITM and a client stack willing to negotiate aNULL
- C:H — Confidentiality can be fully compromised by an active MITM
- I:N — The industry baseline usually scores this as confidentiality-focused rather than broad integrity loss
- A:N — Service generally remains available

**Severity Reasoning:** aNULL cipher suites authenticate neither party. Any attacker can impersonate the server or intercept the session entirely. While encryption exists, without authentication it provides no security. Downgraded from Critical to High because the exploit still requires an active MITM (not passive sniffing alone). Tenable classifies anonymous cipher-suite support in the Medium range, which is why the calibrated CVSS vector is now less aggressive than the original estimate.

**Attack Prerequisites:**
- Active MITM network position
- Client that accepts aNULL cipher suites (many TLS stacks reject by default)

---

### HS-TLS-CIPHER-0003 — EXPORT Cipher Suite

**Severity:** High | **CVSS Score:** 7.4 | **Vector:** `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N`

**CVE References:** CVE-2015-0204 (FREAK), CVE-2015-1637 (FREAK on Windows)
**CWE:** CWE-326 (Inadequate Encryption Strength)
**OWASP:** A02:2021 – Cryptographic Failures
**WASC:** WASC-4 – Insufficient Transport Layer Protection

**CVSS Vector Explanation:**
- AC:H — Requires active downgrade to force EXPORT cipher negotiation
- C:H / I:H — Full session compromise once 512-bit RSA key is factored (hours with cloud compute)
- A:N — Service available

**Severity Reasoning:** FREAK (CVE-2015-0204) forces downgrade to 512-bit RSA EXPORT key exchange, which can be factored in hours. NVD rates FREAK at 5.9 Medium (AC:H for active downgrade), but the full session compromise once factored justifies High. Vector updated from AC:L to AC:H per NVD guidance.

**Attack Prerequisites:**
- Active MITM to force EXPORT cipher negotiation
- Compute resources to factor 512-bit RSA key (~7 hours on 2024 hardware)
- Client that accepts EXPORT cipher suites

---

### HS-TLS-CIPHER-0004 — RC4 Cipher Suite

**Severity:** Medium | **CVSS Score:** 5.9 | **Vector:** `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N`

**CVE References:** CVE-2013-2566, CVE-2015-2808 (Bar Mitzvah)
**CWE:** CWE-327 (Use of a Broken or Risky Cryptographic Algorithm)
**OWASP:** A02:2021 – Cryptographic Failures
**WASC:** WASC-4 – Insufficient Transport Layer Protection

**CVSS Vector Explanation:**
- AV:N — Network exploitable (passive traffic capture)
- AC:H — Requires sustained traffic capture and statistical analysis (~128M+ encrypted records)
- C:H — Full confidentiality breach possible after sufficient traffic accumulation
- I:N — No direct integrity impact
- A:N — Service remains available

**Severity Reasoning:** NVD rates CVE-2013-2566 and CVE-2015-2808 at 5.9 Medium. RC4 has known keystream biases (Fluhrer-Mantin-Shamir, Bar Mitzvah) enabling partial plaintext recovery after sufficient encrypted data. High complexity requirement limits practical exploitability. Tenable Plugin 73683 rates as Medium.

**Attack Prerequisites:**
- Passive network access to observe encrypted traffic
- Session must carry ~128 million+ encrypted records for statistical attack
- Attacker offline analysis capability

---

### HS-TLS-CIPHER-0005 — 3DES Cipher Suite (SWEET32)

**Severity:** High | **CVSS Score:** 7.5 | **Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`

**CVE References:** CVE-2016-2183 (SWEET32)
**CWE:** CWE-327 (Use of a Broken or Risky Cryptographic Algorithm)
**OWASP:** A02:2021 – Cryptographic Failures
**WASC:** WASC-4 – Insufficient Transport Layer Protection

**CVSS Vector Explanation:**
- AV:N — Network exploitable (passive observation sufficient)
- AC:L — Low complexity; birthday attack triggers after ~32 GB of traffic in long-lived sessions
- C:H — Full HTTP session cookie recovery possible
- I:N — Integrity not directly affected
- A:N — Service available

**Severity Reasoning:** NVD rates CVE-2016-2183 at 7.5 High with `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`. The 64-bit block size of 3DES means birthday collisions occur after ~32 GB of traffic, recovering session cookies in long-lived HTTPS sessions. Vector updated to match NVD (AC:L instead of AC:H) and severity elevated to High per CVE consensus.

**Attack Prerequisites:**
- Passive network observation position
- Long-lived TLS session (HTTPS with keep-alive) carrying ~32 GB of traffic
- Ability to induce repeated requests (JavaScript or API polling)

---

### HS-TLS-CIPHER-0006 — CBC-Only Suites with TLS 1.0 (BEAST)

**Severity:** Medium | **CVSS Score:** 4.8 | **Vector:** `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N`

**CVE References:** CVE-2011-3389 (BEAST)
**CWE:** CWE-327 (Use of a Broken or Risky Cryptographic Algorithm)
**OWASP:** A02:2021 – Cryptographic Failures

**CVSS Vector Explanation:**
- AC:H — Requires JavaScript injection and specific cipher+protocol conditions
- C:L — Partial confidentiality; session cookie recovery possible in narrow conditions
- I:L — Recovered cookie enables partial session control

**Severity Reasoning:** CVE-2011-3389 NVD CVSS 3.1 = 3.7. However, considering the active MITM component and partial session hijack capability, Medium is appropriate per Tenable and industry consensus. Modern browsers mitigate BEAST via 1/n-1 record splitting.

**Attack Prerequisites:**
- Active MITM with JavaScript injection capability
- TLS 1.0 with CBC ciphers (no AES-GCM or ChaCha20)
- Browser-based client (BEAST does not apply to most non-browser TLS)

---

### HS-TLS-CIPHER-0007 — Weak Medium-Strength Ciphers (64–112-bit)

**Severity:** Medium | **CVSS Score:** 4.8 | **Vector:** `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N`

**CVE References:** None specific; Tenable Plugin 42873
**CWE:** CWE-326 (Inadequate Encryption Strength)
**OWASP:** A02:2021 – Cryptographic Failures

**CVSS Vector Explanation:**
- AC:H — Brute-force of 64-bit key requires significant compute resources
- C:L / I:L — Partial session decryption/modification possible with sufficient compute

**Severity Reasoning:** 64-bit effective strength ciphers (e.g., DES, RC2-40) are brute-forceable with modern hardware. 112-bit (3DES) is more resistant but deprecated. Tenable Plugin 42873 rates medium-strength ciphers as Medium.

**Attack Prerequisites:**
- Network position to capture ciphertext
- Compute resources (hours to days for 64-bit, academic for 112-bit)

---

### HS-TLS-CIPHER-0008 — No AEAD Suites Available

**Severity:** Medium | **CVSS Score:** 4.8 | **Vector:** `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N`

**CVE References:** None specific
**CWE:** CWE-326 (Inadequate Encryption Strength)
**OWASP:** A02:2021 – Cryptographic Failures

**CVSS Vector Explanation:**
- AC:H — Padding oracle attacks require specific conditions and multiple oracle queries
- C:L / I:L — Partial decryption or modification via padding oracle

**Severity Reasoning:** Without AEAD cipher suites (AES-GCM, ChaCha20-Poly1305), the server is susceptible to padding oracle attacks (LUCKY13, POODLE-style) that can decrypt session data or modify ciphertext without detection.

**Attack Prerequisites:**
- Active MITM to intercept and modify TLS records
- Ability to observe server behavior to padding errors (timing or error responses)
- Multiple oracle queries (hundreds to thousands of modified packets)

---

### HS-TLS-CIPHER-0009 — No Forward Secrecy Suites

**Severity:** Medium | **CVSS Score:** 4.8 | **Vector:** `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N`

**CVE References:** None specific
**CWE:** CWE-326 (Inadequate Encryption Strength)
**OWASP:** A02:2021 – Cryptographic Failures

**CVSS Vector Explanation:**
- AC:H — Requires prior recording of encrypted sessions AND future private key compromise
- C:L / I:L — Partial retroactive decryption of recorded sessions

**Severity Reasoning:** Without (EC)DHE forward secrecy, all recorded TLS sessions can be decrypted if the server's RSA private key is later compromised. This is a systemic risk, not an immediate exploit. NIST and PCI DSS recommend forward secrecy.

**Attack Prerequisites:**
- Ability to record encrypted network traffic (passive)
- Future acquisition of server private key (theft, legal order, compromise)

---

### HS-TLS-CIPHER-0010 — Legacy RSA Key Exchange

**Severity:** Medium | **CVSS Score:** 4.8 | **Vector:** `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N`

**CVE References:** None specific
**CWE:** CWE-326 (Inadequate Encryption Strength)
**OWASP:** A02:2021 – Cryptographic Failures

**CVSS Vector Explanation:**
- AC:H — Requires private key compromise AND recorded traffic
- C:L / I:L — Partial retroactive session decryption

**Severity Reasoning:** Same risk profile as HS-TLS-CIPHER-0009 but focused on static RSA key exchange without any ephemeral component. This directly contradicts PFS best practices.

**Attack Prerequisites:**
- Recorded historical ciphertext
- Server RSA private key

---

### HS-TLS-CIPHER-0011 — Weak Elliptic Curve Supported

**Severity:** Medium | **CVSS Score:** 4.8 | **Vector:** `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N`

**CVE References:** None specific; NSA Suite B guidance
**CWE:** CWE-326 (Inadequate Encryption Strength)
**OWASP:** A02:2021 – Cryptographic Failures

**CVSS Vector Explanation:**
- AC:H — Active downgrade to weak curve required
- C:L / I:L — Partial session compromise if weak curve is forced and attacked

**Severity Reasoning:** Curves below 192-bit (e.g., secp160r1) provide insufficient security. NIST recommends P-256 (secp256r1) or stronger. ECDLP against 160-bit curves is feasible with modern compute.

**Attack Prerequisites:**
- Active MITM to force weak curve negotiation
- Significant compute resources to solve ECDLP for small curves

---

### HS-TLS-CIPHER-0012 — No ChaCha20-Poly1305 Suites

**Severity:** Info | **CVSS Score:** 0.0 | **Vector:** `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N`

**CVE References:** None
**CWE:** CWE-326 (informational)
**OWASP:** A02:2021 – Cryptographic Failures (informational)

**Severity Reasoning:** ChaCha20-Poly1305 absence is not a vulnerability but a missed performance and resilience opportunity, especially on platforms without AES-NI acceleration. Informational finding.

**Attack Prerequisites:** None (informational only)

---

### HS-TLS-CERT-0001 — Certificate Expired

**Severity:** Medium | **CVSS Score:** 5.3 | **Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N`

**CVE References:** None (operational issue)
**CWE:** CWE-295 (Improper Certificate Validation)
**OWASP:** A02:2021 – Cryptographic Failures; A07:2021 – Identification and Authentication Failures
**WASC:** WASC-4 – Insufficient Transport Layer Protection

**CVSS Vector Explanation:**
- AC:L — No special conditions; certificate is verifiably expired
- C:N — Most scanner baselines treat this primarily as a trust/availability defect rather than direct data disclosure
- I:L — Users who bypass warnings can be exposed to impersonation or modified content
- A:N — Availability impact is operational, but not usually encoded in the base score

**Severity Reasoning:** An expired certificate is both a MITM enabler (browsers warn users who may bypass) and a direct availability issue (strict clients reject). Availability impact added per CERT guidance on certificate expiry causing service outages. Nessus-class scanners usually score this family as Medium rather than Critical, so the calibrated vector now reflects the vendor baseline while preserving the original operational concern.

**Attack Prerequisites:**
- Network MITM position (optional; users may bypass browser warnings voluntarily)
- For availability: client with strict certificate validation (standard browsers/apps)

---

### HS-TLS-CERT-0002 — Certificate Not Yet Valid

**Severity:** Info | **CVSS Score:** 0.0 | **Vector:** `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N`

**CVE References:** None (misconfiguration)
**CWE:** CWE-295 (Improper Certificate Validation)
**OWASP:** A07:2021 – Identification and Authentication Failures

**CVSS Vector Explanation:**
- AC:H — This is usually an operational or clock-skew issue, not a broadly exploitable condition
- C:N / I:N / A:N — Major scanners generally treat it as informational unless paired with a demonstrated trust-bypass path

**Severity Reasoning:** A "not yet valid" certificate indicates clock skew, deployment error, or intentional misconfiguration. Clients that bypass the warning are exposed to MITM. Less severe than expired (no A:H) because this is typically resolved quickly once discovered. Nessus commonly treats this condition as informational when observed in isolation, so the calibrated score now reflects that vendor posture.

**Attack Prerequisites:**
- Network MITM position
- Client that bypasses certificate validity warnings

---

### HS-TLS-CERT-0003 — Self-Signed Certificate

**Severity:** Medium | **CVSS Score:** 6.5 | **Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N`

**CVE References:** None (configuration issue)
**CWE:** CWE-295 (Improper Certificate Validation), CWE-297 (Improper Validation of Certificate with Host Mismatch)
**OWASP:** A07:2021 – Identification and Authentication Failures

**CVSS Vector Explanation:**
- AC:L — No CA validation; any attacker can generate a matching self-signed cert
- C:L — Exposure depends on the client accepting or pinning the self-signed certificate
- I:L — Integrity impact is likewise conditional on warning bypass
- A:N — Availability is not usually encoded in the base score

**Severity Reasoning:** Self-signed certificates in public contexts provide no third-party identity validation. Any attacker can present a self-signed cert for the same domain, enabling trivial MITM once users are conditioned to accept certificate warnings. Nessus-style scanner results typically keep this in the Medium range, which aligns with the adjusted vector.

**Attack Prerequisites:**
- Generate a self-signed certificate for the target domain
- MITM network position or DNS poisoning to redirect traffic

---

### HS-TLS-CERT-0004 — Hostname Mismatch (SAN/CN)

**Severity:** Medium | **CVSS Score:** 4.8 | **Vector:** `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N`

**CVE References:** None (configuration issue)
**CWE:** CWE-297 (Improper Validation of Certificate with Host Mismatch)
**OWASP:** A07:2021 – Identification and Authentication Failures

**CVSS Vector Explanation:**
- AC:H — Requires a network-positioned attacker or DNS poisoning to exploit
- C:L — Partial confidentiality exposure; an attacker positioned to MITM can observe encrypted traffic
- I:L — Partial integrity exposure; attacker can inject or modify traffic without the victim detecting server identity mismatch
- A:N — No direct availability impact

**Severity Reasoning:** RFC 6125 mandates hostname validation. A mismatch means the certificate does not prove server identity for the accessed hostname, enabling MITM by any attacker with a valid certificate for the correct hostname (obtainable from public CAs). Tenable plugin 45411 (SSL Wrong Hostname) treats this as a Low-Medium finding. Score 4.8 is consistent with other MITM-class findings (e.g., HS-TLS-PROTOCOL-0008, HS-TLS-CIPHER-0006) and reflects the network-position prerequisite.

**Attack Prerequisites:**
- Obtain a valid certificate for the accessed hostname (via CA, Let's Encrypt, etc.)
- MITM network position or DNS poisoning

---

### HS-TLS-CERT-0005 — Weak Signature Algorithm (SHA-1)

**Severity:** Medium | **CVSS Score:** 5.3 | **Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N`

**CVE References:** CVE-2019-14855 (GnuTLS SHA-1 collision); Google SHAttered (2017)
**CWE:** CWE-327 (Use of a Broken or Risky Cryptographic Algorithm)
**OWASP:** A02:2021 – Cryptographic Failures

**CVSS Vector Explanation:**
- AC:L — Vendor baselines often treat deprecated SHA-1 certificate use as a broadly reachable trust issue once present
- C:N — Exposure is mostly tied to trust degradation rather than direct disclosure from the finding alone
- I:L — A successful forgery scenario affects authenticity/integrity
- A:N — No direct availability impact

**Severity Reasoning:** SHA-1 collision attacks are demonstrated (Google SHAttered, 2017). NVD rates related CVEs around 5.9 Medium. The attack cost is high but non-trivial for nation-states or well-funded adversaries. Major browsers reject SHA-1 certificates. Tenable keeps comparable SHA-1 certificate findings in the Medium range, so the revised vector preserves the original concern while aligning with vendor scoring.

**Attack Prerequisites:**
- Significant computational resources (~$100K cloud budget for chosen-prefix collision)
- Ability to submit crafted certificate to a CA (social engineering or compromise)
- MITM network position

---

### HS-TLS-CERT-0006 — RSA Key Size < 2048 Bits

**Severity:** Low | **CVSS Score:** 3.7 | **Vector:** `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N`

**CVE References:** NIST SP 800-131A Rev 2 (deprecation)
**CWE:** CWE-326 (Inadequate Encryption Strength)
**OWASP:** A02:2021 – Cryptographic Failures

**CVSS Vector Explanation:**
- AC:H — Factoring 1024-bit RSA requires significant distributed compute
- C:L — The risk is real but generally treated by vendors as low because exploitation cost is still high for sub-2048-bit keys
- I:N / A:N — No immediate integrity or availability impact absent successful key recovery

**Severity Reasoning:** 1024-bit RSA keys are factorable with dedicated hardware (~$1M, 2024 estimates). NIST SP 800-131A prohibits RSA < 2048 after 2013. Tenable and industry rate this as Medium. High confidentiality impact once key is factored. Vendor scanner write-ups are often more conservative for simple key-length findings, so the calibrated CVSS vector now reflects a Low score while preserving the original rationale.

**Attack Prerequisites:**
- Capture server certificate (public key) from TLS handshake
- Significant distributed compute resources for factoring (weeks to months for 1024-bit)

---

### HS-TLS-CERT-0007 — Incomplete Certificate Chain

**Severity:** Medium | **CVSS Score:** 5.3 | **Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N`

**CVE References:** None
**CWE:** CWE-295 (Improper Certificate Validation)
**OWASP:** A07:2021 – Identification and Authentication Failures

**CVSS Vector Explanation:**
- AC:L — Broken path validation is immediately observable to affected clients
- C:N — The issue is usually trust/validation failure, not direct confidentiality loss
- I:L — Integrity/authenticity is degraded when users or clients proceed despite chain problems
- A:N — Availability effects are operational rather than encoded in the base score

**Severity Reasoning:** Clients that cannot complete chain validation may accept the certificate without full verification or reject it, causing availability issues. Mozilla Firefox and some mobile clients strictly require the complete chain.

**Attack Prerequisites:**
- Client that does not cache intermediate CA certificates
- MITM position to serve a fraudulent certificate

---

### HS-TLS-CERT-0008 — Weak Public Key Type/Params

**Severity:** Medium | **CVSS Score:** 5.3 | **Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N`

**CVE References:** None specific
**CWE:** CWE-326 (Inadequate Encryption Strength)
**OWASP:** A02:2021 – Cryptographic Failures

**CVSS Vector Explanation:**
- AC:L — Weak key parameters are directly reachable once deployed
- C:N — This is usually a trust-strength problem rather than immediate disclosure
- I:L — Authenticity/integrity can be weakened if the parameters are practically attackable
- A:N — No direct availability impact

**Severity Reasoning:** Non-standard or deprecated key types (DSA-512, RSA with small exponent, weak ECC parameters) reduce cryptographic strength below NIST recommendations. Impact depends on specific weakness.

**Attack Prerequisites:**
- Knowledge of specific weak key parameters
- Compute resources proportional to key size vulnerability

---

### HS-TLS-CERT-0009 — Long-Lived Certificate Validity

**Severity:** Info | **CVSS Score:** 0.0 | **Vector:** `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N`

**CVE References:** CA/Browser Forum Ballot SC-22 (398-day limit)
**CWE:** CWE-298 (Improper Validation of Certificate Expiration)
**OWASP:** A02:2021 – Cryptographic Failures (informational)

**Severity Reasoning:** CA/Browser Forum limits DV/OV certificates to 398 days. Longer validity increases the exposure window for key compromise or CA mis-issuance. Informational finding per industry consensus.

**Attack Prerequisites:** None (informational)

---

### HS-TLS-CERT-0010 — OCSP Stapling Not Supported

**Severity:** Info | **CVSS Score:** 0.0 | **Vector:** `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N`

**CVE References:** None
**CWE:** CWE-299 (Improper Check for Certificate Revocation)
**OWASP:** A02:2021 – Cryptographic Failures (informational)

**Severity Reasoning:** Without OCSP stapling, clients perform live OCSP lookups, leaking connection metadata to the CA and potentially suffering latency or soft-fail revocation bypasses. Best practice, not directly exploitable.

**Attack Prerequisites:** None (informational)

---

### HS-TLS-CERT-0011 — OCSP Must-Staple Missing

**Severity:** Info | **CVSS Score:** 0.0 | **Vector:** `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N`

**CVE References:** RFC 7633 (TLS Feature extension)
**CWE:** CWE-299 (Improper Check for Certificate Revocation)
**OWASP:** A02:2021 – Cryptographic Failures (informational)

**Severity Reasoning:** Without the OCSP Must-Staple extension, clients cannot enforce that the server provides fresh revocation status. If a certificate is compromised and revoked, clients may not learn of revocation in a timely manner.

**Attack Prerequisites:** None (informational)

---

### HS-TLS-CERT-0012 — Certificate Transparency SCT Missing

**Severity:** Info | **CVSS Score:** 0.0 | **Vector:** `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N`

**CVE References:** None; Chrome CT Policy
**CWE:** CWE-295 (Improper Certificate Validation)
**OWASP:** A07:2021 – Identification and Authentication Failures (informational)

**Severity Reasoning:** Chrome requires SCTs for publicly trusted certificates (since 2018). Without SCTs, Chrome shows certificate warnings, causing availability issues. Primarily a compliance/trust finding.

**Attack Prerequisites:** None (informational)

---

### HS-TLS-CERT-0013 — RSA Key Below 3072 Bits

**Severity:** Info | **CVSS Score:** 0.0 | **Vector:** `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N`

**CVE References:** NIST SP 800-131A Rev 2 (post-2030 guidance)
**CWE:** CWE-326 (Inadequate Encryption Strength — forward-looking)
**OWASP:** A02:2021 – Cryptographic Failures (informational)

**Severity Reasoning:** NIST recommends RSA ≥ 3072 bits for use beyond 2030. 2048-bit RSA is currently adequate but forward-looking compliance postures should plan migration. Informational finding for long-term planning.

**Attack Prerequisites:** None (informational)

---

### HS-TLS-SCENARIO-0001 — No TLS_FALLBACK_SCSV

**Severity:** Medium | **CVSS Score:** 4.8 | **Vector:** `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N`

**CVE References:** CVE-2014-3566 (POODLE downgrade enabler); RFC 7507
**CWE:** CWE-757 (Selection of Less-Secure Algorithm During Negotiation)
**OWASP:** A02:2021 – Cryptographic Failures

**CVSS Vector Explanation:**
- AC:H — Requires active MITM to interfere with ClientHello
- C:L / I:L — Partial compromise via forced downgrade to older protocol

**Severity Reasoning:** Without TLS_FALLBACK_SCSV (RFC 7507), an active MITM can interfere with the initial ClientHello, forcing a retry on a lower protocol version. This is the enabler for POODLE downgrade attacks.

**Attack Prerequisites:**
- Active MITM position to interfere with initial TLS handshake
- Server that supports weaker protocol versions alongside modern ones

---

### HS-TLS-SCENARIO-0002 — Forced Downgrade to TLS 1.0

**Severity:** Medium | **CVSS Score:** 4.8 | **Vector:** `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N`

**CVE References:** CWE-757, various TLS downgrade CVEs
**CWE:** CWE-757 (Selection of Less-Secure Algorithm During Negotiation)
**OWASP:** A02:2021 – Cryptographic Failures

**Severity Reasoning:** Server accepts a forged TLS 1.0 ClientHello even when advertising TLS 1.2+, enabling downgrade attacks. Combined with BEAST or other TLS 1.0 weaknesses.

**Attack Prerequisites:**
- Active MITM to forge low-version ClientHello
- Server that lacks FALLBACK_SCSV enforcement

---

### HS-TLS-SCENARIO-0003 — Session Tickets Without Rotation

**Severity:** Info | **CVSS Score:** 0.0 | **Vector:** `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N`

**CVE References:** None specific
**CWE:** CWE-311 (Missing Encryption of Sensitive Data — key rotation)
**OWASP:** A02:2021 – Cryptographic Failures (informational)

**Severity Reasoning:** Static session ticket keys undermine forward secrecy. If the ticket key is ever compromised, all sessions resumed with that key can be decrypted. Best practice is to rotate ticket keys every 24 hours.

**Attack Prerequisites:** None directly (informational); requires future ticket key compromise

---

### HS-TLS-SCENARIO-0004 — Weak DH Parameters (Logjam)

**Severity:** Low | **CVSS Score:** 3.7 | **Vector:** `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N`

**CVE References:** CVE-2015-4000 (Logjam)
**CWE:** CWE-326 (Inadequate Encryption Strength)
**OWASP:** A02:2021 – Cryptographic Failures

**CVSS Vector Explanation:**
- AC:H — Precomputation of DH discrete log requires nation-state-level resources for 1024-bit
- C:N — NVD’s baseline for Logjam-style exposure is conservative because the finding is mostly an exposure indicator
- I:L — Integrity/authenticity can be weakened once downgrade or discrete-log conditions are met

**Severity Reasoning:** CVE-2015-4000 (Logjam) shows that state-level actors can precompute discrete logs for standard 1024-bit DH groups, enabling passive decryption. NVD rates at 3.7 Low for the specific attack, but 5.9 is appropriate for the systemic risk. NIST requires DH ≥ 2048 bits. The calibrated vector now follows the published NVD base score because this finding tracks the exposed condition rather than confirmed breakability.

**Attack Prerequisites:**
- Precomputed discrete log tables for specific DH groups (768/1024-bit)
- Passive traffic capture capability

---

### HS-TLS-SCENARIO-0005 — SWEET32 Exposure Indicator

**Severity:** Medium | **CVSS Score:** 4.8 | **Vector:** `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N`

**CVE References:** CVE-2016-2183 (SWEET32)
**CWE:** CWE-327 (Use of a Broken or Risky Cryptographic Algorithm)
**OWASP:** A02:2021 – Cryptographic Failures

**Severity Reasoning:** This scenario indicator flags contexts where SWEET32 conditions exist (3DES active in potentially high-volume sessions). Distinct from HS-TLS-CIPHER-0005 in that this specifically flags the high-volume scenario risk.

**Attack Prerequisites:**
- Long-lived HTTP keep-alive or websocket session over 3DES
- Passive traffic observation
- ~32 GB of captured traffic

---

### HS-TLS-SCENARIO-0006 — BEAST Exposure Indicator

**Severity:** Medium | **CVSS Score:** 4.8 | **Vector:** `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N`

**CVE References:** CVE-2011-3389 (BEAST)
**CWE:** CWE-327 (Use of a Broken or Risky Cryptographic Algorithm)
**OWASP:** A02:2021 – Cryptographic Failures

**Severity Reasoning:** Same as HS-TLS-CIPHER-0006 but detected via scenario analysis (TLS 1.0 + CBC combination confirmed via handshake). This is a confirmed exposure indicator rather than a cipher policy flag.

**Attack Prerequisites:**
- Same as HS-TLS-CIPHER-0006

---

### HS-TLS-SCENARIO-0007 — Insecure Record Fragmentation

**Severity:** Medium | **CVSS Score:** 4.8 | **Vector:** `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N`

**CVE References:** None specific
**CWE:** CWE-20 (Improper Input Validation)
**OWASP:** A02:2021 – Cryptographic Failures

**Severity Reasoning:** Non-standard record fragmentation can bypass security inspection (IDS/WAF) that reconstructs TLS records incorrectly, or trigger implementation vulnerabilities in specific TLS stacks.

**Attack Prerequisites:**
- Active MITM to inject fragmented records
- Target system with TLS implementation vulnerable to fragmentation quirks

---

### HS-TLS-SCENARIO-0008 — Weak Cipher Preference (Server)

**Severity:** Medium | **CVSS Score:** 4.8 | **Vector:** `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N`

**CVE References:** None specific
**CWE:** CWE-757 (Selection of Less-Secure Algorithm During Negotiation)
**OWASP:** A02:2021 – Cryptographic Failures

**Severity Reasoning:** When the server actively prefers weak ciphers over strong ones (even when both are offered), attackers who can observe negotiation can confirm the weaker cipher is always selected, reducing the effective security of the connection.

**Attack Prerequisites:**
- Client that offers both weak and strong cipher suites
- Ability to observe cipher negotiation outcome

---

### HS-TLS-SCENARIO-0009 — TLS 1.3 0-RTT Enabled

**Severity:** Info | **CVSS Score:** 0.0 | **Vector:** `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N`

**CVE References:** None specific; RFC 8446 §8
**CWE:** CWE-294 (Authentication Bypass by Capture-replay)
**OWASP:** A02:2021 – Cryptographic Failures (informational)

**Severity Reasoning:** TLS 1.3 0-RTT early data does not have forward secrecy and is replayable. Applications that process 0-RTT data without replay protection (e.g., non-idempotent operations) are vulnerable. The TLS layer itself is fine; risk is application-layer. Rated informational because exploitability depends on application handling.

**Attack Prerequisites:**
- Captured 0-RTT early data from prior session
- Target application processing non-idempotent requests in 0-RTT

---

### HS-TLS-SCENARIO-0010 — STARTTLS Downgrade Possible

**Severity:** Medium | **CVSS Score:** 4.8 | **Vector:** `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N`

**CVE References:** None specific; STARTTLS stripping is documented attack
**CWE:** CWE-757 (Selection of Less-Secure Algorithm During Negotiation)
**OWASP:** A02:2021 – Cryptographic Failures

**Severity Reasoning:** An active MITM can remove or not advertise the STARTTLS capability in SMTP/IMAP/POP3 banners, causing clients to transmit credentials and mail in cleartext. MTA-STS and DANE mitigate this.

**Attack Prerequisites:**
- Active MITM on the SMTP/IMAP/POP3 connection
- Server STARTTLS is optional (not enforced)

---

### HS-TLS-SCENARIO-0011 — STARTTLS Without Policy Enforcement

**Severity:** Medium | **CVSS Score:** 4.8 | **Vector:** `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N`

**CVE References:** None specific
**CWE:** CWE-319 (Cleartext Transmission of Sensitive Information)
**OWASP:** A02:2021 – Cryptographic Failures

**Severity Reasoning:** Opportunistic STARTTLS (no MTA-STS, DANE, or STARTTLS policy) allows any MITM to strip TLS. Policy-based enforcement (MTA-STS) prevents this.

**Attack Prerequisites:**
- Active MITM on SMTP connection path
- No DANE/MTA-STS policy in DNS for sender domain

---

### HS-TLS-EXTENSION-0011 — ALPN Hardening Missing for HTTP/2

**Severity:** Info | **CVSS Score:** 0.0 | **Vector:** `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N`

**CVE References:** RFC 7540 §9.2
**CWE:** CWE-16 (Configuration)
**OWASP:** A05:2021 – Security Misconfiguration

**Severity Reasoning:** Server advertising HTTP/2 over weak TLS or with blacklisted ciphers violates RFC 7540 §9.2. While not directly exploitable, it represents a misconfiguration that may lead to negotiation of weaker cipher suites for HTTP/2 traffic.

**Attack Prerequisites:** None directly (configuration review finding)

---

### HS-TLS-EXTENSION-0012 — ALPN Not Advertised

**Severity:** Info | **CVSS Score:** 0.0 | **Vector:** `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N`

**CVE References:** RFC 7301 (ALPN), RFC 7540 (HTTP/2 ALPN requirement)
**CWE:** CWE-16 (Configuration)
**OWASP:** A05:2021 – Security Misconfiguration

**Severity Reasoning:** Without ALPN advertisement, HTTP/2 cannot be negotiated in the TLS handshake, forcing fallback to HTTP/1.1 or out-of-band protocol negotiation. Informational configuration finding.

**Attack Prerequisites:** None (informational)

---

### HS-SSH-KEX-0101 — diffie-hellman-group1-sha1

**Severity:** Low | **CVSS Score:** 3.7 | **Vector:** `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N`

**CVE References:** CVE-2016-20012 (related weak KEX); IETF draft-ietf-curdle-ssh-kex-sha2
**CWE:** CWE-326 (Inadequate Encryption Strength)
**OWASP:** A02:2021 – Cryptographic Failures

**CVSS Vector Explanation:**
- AC:H — Logjam-style precomputation required for 1024-bit group
- C:L — Vendor baselines usually treat weak SSH KEX as low-severity cryptographic exposure
- I:N / A:N — No immediate integrity or availability impact

**Severity Reasoning:** Group1 uses a hardcoded 768-bit Oakley Group 2 DH prime. This is equivalent to the Logjam-vulnerable DH parameters in TLS. IETF deprecated this KEX. Downgraded from High to Medium because active exploitation requires nation-state precomputation resources (not commodity threat actors). Nessus now places comparable weak SSH KEX findings in the Low range, so the calibrated score follows the vendor baseline.

**Attack Prerequisites:**
- Precomputed discrete log table for 768/1024-bit Oakley Group 2
- Passive SSH traffic capture

---

### HS-SSH-KEX-0102 — diffie-hellman-group-exchange-sha1

**Severity:** Low | **CVSS Score:** 3.7 | **Vector:** `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N`

**CVE References:** IETF RFC 9142 (deprecation of SHA-1 KEX)
**CWE:** CWE-326 (Inadequate Encryption Strength), CWE-327
**OWASP:** A02:2021 – Cryptographic Failures

**Severity Reasoning:** SHA-1 based group exchange is deprecated by RFC 9142. The SHA-1 hash in KEX does not directly enable current attacks, but SHA-1 weaknesses in the MAC context could facilitate tampering in rare conditions. Consensus: Medium. Current scanner baselines are more conservative and generally keep this class of finding in the Low range, which is why the score was adjusted.

**Attack Prerequisites:**
- Active MITM to downgrade from SHA-256 to SHA-1 group exchange
- SHA-1 collision capability (high cost)

---

### HS-SSH-KEX-0103 — gss-* SHA1 KEX Enabled

**Severity:** Low | **CVSS Score:** 3.7 | **Vector:** `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N`

**CVE References:** RFC 9142 (SHA-1 KEX deprecation)
**CWE:** CWE-327 (Use of a Broken or Risky Cryptographic Algorithm)
**OWASP:** A02:2021 – Cryptographic Failures

**Severity Reasoning:** GSSAPI key exchange with SHA-1 hash is deprecated. Lower risk than group1-sha1 because GSSAPI also involves Kerberos/GSSAPI authentication which adds additional security layers. Primarily a compliance finding. Vendor analogues generally score this class in the Low range, so the updated vector reflects that baseline.

**Attack Prerequisites:**
- GSSAPI/Kerberos infrastructure access
- Active MITM to downgrade to SHA-1 GSSAPI KEX

---

### HS-SSH-HOSTKEY-0104 — ssh-rsa (SHA1) Hostkey

**Severity:** Low | **CVSS Score:** 3.7 | **Vector:** `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N`

**CVE References:** OpenSSH deprecation of ssh-rsa (OpenSSH 8.8, 2021)
**CWE:** CWE-327 (Use of a Broken or Risky Cryptographic Algorithm)
**OWASP:** A02:2021 – Cryptographic Failures

**CVSS Vector Explanation:**
- AC:H — SHA-1 collision to forge host key signature requires significant resources
- C:L — The residual risk is usually treated as low because practical forgery remains expensive
- I:N / A:N — No direct integrity or availability impact from simple algorithm support alone

**Severity Reasoning:** OpenSSH deprecated ssh-rsa (SHA-1) in 8.8 (September 2021). SHA-1 collisions are demonstrated (Google SHAttered). A forged host key signature enables MITM, though the cost is high. Downgraded to Medium per industry consensus (attack not practical for commodity threat actors). Current vendor baselines are more conservative and usually keep simple algorithm support in the Low range.

**Attack Prerequisites:**
- SHA-1 chosen-prefix collision capability
- Ability to impersonate the SSH server (DNS/ARP poisoning or MITM)

---

### HS-SSH-HOSTKEY-0105 — RSA Hostkey < 2048 Bits

**Severity:** Low | **CVSS Score:** 3.7 | **Vector:** `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N`

**CVE References:** NIST SP 800-131A
**CWE:** CWE-326 (Inadequate Encryption Strength)
**OWASP:** A02:2021 – Cryptographic Failures

**Severity Reasoning:** RSA host keys below 2048 bits can be factored. Once factored, attacker can impersonate the server for all future connections (until key rotation). NIST requires ≥ 2048; recommends ≥ 3072 post-2030. Downgraded to Medium because factoring 1024-bit still requires significant resources. Vendor scoring is typically more conservative for standalone key-length findings, so the calibrated vector now lands in the Low range.

**Attack Prerequisites:**
- Capture public host key from SSH banner
- Significant compute for RSA factoring (~weeks for 1024-bit with cloud)

---

### HS-SSH-CIPHER-0106 — CBC Ciphers Enabled

**Severity:** Low | **CVSS Score:** 3.7 | **Vector:** `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N`

**CVE References:** CVE-2008-5161 (SSH CBC vulnerability)
**CWE:** CWE-327 (Use of a Broken or Risky Cryptographic Algorithm)
**OWASP:** A02:2021 – Cryptographic Failures

**CVSS Vector Explanation:**
- AC:H — Plaintext recovery via CBC oracle requires specific conditions
- C:L — Partial session data recovery is the primary concern
- I:N / A:N — Modern implementations and mitigations reduce the likelihood of broader impact

**Severity Reasoning:** CVE-2008-5161 demonstrates CBC plaintext recovery in SSH via adaptive oracle attacks. Modern SSH implementations include workarounds, but the underlying weakness persists. NIST and CIS guides recommend CTR or AEAD modes. Scanner vendors generally keep this in the Low range because the practical oracle conditions are constrained.

**Attack Prerequisites:**
- Active MITM with ability to inject and observe modified CBC blocks
- Server that doesn't implement robust CBC oracle protections

---

### HS-SSH-CIPHER-0107 — arcfour/RC4 Cipher

**Severity:** Medium | **CVSS Score:** 5.9 | **Vector:** `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N`

**CVE References:** CVE-2013-2566, RFC 8758 (prohibits arcfour in SSH)
**CWE:** CWE-327 (Use of a Broken or Risky Cryptographic Algorithm)
**OWASP:** A02:2021 – Cryptographic Failures

**Severity Reasoning:** RC4 is prohibited in SSH by RFC 8758. Same RC4 statistical bias attacks apply (Fluhrer-Mantin-Shamir, Bar Mitzvah). Downgraded from High to Medium consistent with TLS RC4 rating (CVE-2013-2566 = 5.9 Medium).

**Attack Prerequisites:**
- Passive traffic capture of SSH session using arcfour
- ~128 million+ encrypted records for statistical attack

---

### HS-SSH-MAC-0108 — hmac-sha1 Enabled

**Severity:** Info | **CVSS Score:** 0.0 | **Vector:** `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N`

**CVE References:** RFC 9142 (SHA-1 MAC deprecation in SSH)
**CWE:** CWE-327 (Use of a Broken or Risky Cryptographic Algorithm)
**OWASP:** A02:2021 – Cryptographic Failures

**CVSS Vector Explanation:**
- AC:H — Exploitation requires expensive cryptanalytic work and an active MITM position
- C:N / I:N / A:N — Vendors generally treat simple HMAC-SHA1 support as informational hardening debt

**Severity Reasoning:** HMAC-SHA1 is deprecated but not immediately broken for MAC purposes (HMAC construction adds security on top of SHA-1). However, SHA-1 weaknesses affect the security margin. RFC 9142 recommends migrating to HMAC-SHA2-256 or HMAC-SHA2-512. Nessus-class guidance generally treats simple support as informational, so the calibrated score was reduced accordingly.

**Attack Prerequisites:**
- SHA-1 collision capability (nation-state level cost)
- Active MITM position

---

### HS-SSH-MAC-0109 — umac-64 Enabled

**Severity:** Low | **CVSS Score:** 3.7 | **Vector:** `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N`

**CVE References:** None specific
**CWE:** CWE-326 (Inadequate Encryption Strength)
**OWASP:** A02:2021 – Cryptographic Failures

**Severity Reasoning:** UMAC-64 provides only 64-bit authentication tags, offering ~2^32 security for birthday attacks on the MAC. While not immediately broken, umac-128 or HMAC-SHA2-256 provide stronger guarantees. CIS SSH Benchmark recommends avoiding umac-64.

**Attack Prerequisites:**
- Active MITM with ability to forge MAC values
- ~2^32 message forgery attempts

---

### HS-SSH-CONFIG-0110 — SSH Banner Exposes Legacy Version

**Severity:** Info | **CVSS Score:** 0.0 | **Vector:** `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N`

**CVE References:** Various OpenSSH CVEs by version
**CWE:** CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor)
**OWASP:** A01:2021 – Broken Access Control (information disclosure)

**Severity Reasoning:** SSH banners advertising old version strings (e.g., SSH-1.99, OpenSSH_6.x) enable targeted exploitation by revealing which known CVEs apply. The banner itself causes no direct harm but facilitates reconnaissance.

**Attack Prerequisites:**
- Unauthenticated connection to port 22 (or configured SSH port)
- Knowledge of CVEs affecting the disclosed version

---

### HS-RDP-TLS-0201 — RDP Does Not Require NLA

**Severity:** Medium | **CVSS Score:** 4.0 | **Vector:** `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:L/I:N/A:N`

**CVE References:** CVE-2019-0708 (BlueKeep), CVE-2019-1181/1182 (DejaBlue)
**CWE:** CWE-287 (Improper Authentication)
**OWASP:** A07:2021 – Identification and Authentication Failures

**CVSS Vector Explanation:**
- AV:N / AC:H — The condition is remotely reachable, but meaningful exploitation depends on additional attack preconditions
- S:C — Exposure expands the reachable pre-auth attack surface of the remote desktop service
- C:L — Limited confidentiality impact from pre-auth session metadata and login exposure
- I:N / A:N — The finding itself does not guarantee integrity or availability loss

**Severity Reasoning:** Without NLA, RDP presents the Windows login screen before authentication, exposing the system to pre-authentication vulnerabilities (BlueKeep CVE-2019-0708 = CVSS 9.8 Critical), credential brute-force, and screenshot/fingerprinting attacks. NLA gates authentication before the desktop session is established. Industry rates NLA absence as High. Nessus keeps the standalone configuration finding in the Medium range, so the calibrated vector now follows that vendor baseline.

**Attack Prerequisites:**
- Network access to RDP port (3389)
- No NLA enforcement (default on older Windows)

---

### HS-RDP-TLS-0202 — RDP Accepts TLS 1.0

**Severity:** Medium | **CVSS Score:** 4.8 | **Vector:** `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N`

**CVE References:** CVE-2011-3389 (BEAST via TLS 1.0)
**CWE:** CWE-326 (Inadequate Encryption Strength)
**OWASP:** A02:2021 – Cryptographic Failures

**Severity Reasoning:** Same TLS 1.0 risks apply to RDP as to HTTPS (BEAST, downgrade). Microsoft deprecated TLS 1.0 for RDP in Windows Server 2022. PCI DSS 3.2+ prohibits TLS 1.0. Downgraded to Medium consistent with HS-TLS-PROTOCOL-0003.

**Attack Prerequisites:**
- Active MITM on RDP connection path
- Force TLS 1.0 downgrade via ClientHello manipulation

---

### HS-RDP-TLS-0203 — RDP Accepts TLS 1.1

**Severity:** Medium | **CVSS Score:** 4.8 | **Vector:** `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N`

**CVE References:** RFC 8996 (TLS 1.1 deprecation)
**CWE:** CWE-326 (Inadequate Encryption Strength)
**OWASP:** A02:2021 – Cryptographic Failures

**Severity Reasoning:** TLS 1.1 deprecation applies equally to RDP. Same risk profile as HS-TLS-PROTOCOL-0004.

**Attack Prerequisites:**
- Active MITM to force TLS 1.1 downgrade
- RDP client that accepts TLS 1.1

---

### HS-RDP-TLS-0204 — RDP Certificate Invalid/Expired

**Severity:** Medium | **CVSS Score:** 5.3 | **Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N`

**CVE References:** None (operational issue)
**CWE:** CWE-295 (Improper Certificate Validation)
**OWASP:** A07:2021 – Identification and Authentication Failures

**Severity Reasoning:** An invalid RDP certificate means the RDP client cannot validate server identity. Any attacker can perform MITM on RDP sessions, capturing credentials and session data. RDP MITM enables full keystroke and screen capture. Rated High (8.6) consistent with certificate-authentication failures where confidentiality impact is high but integrity and availability impacts are typically partial. Scanner vendors more commonly score this certificate-validation family as Medium, so the calibrated vector now reflects that external baseline.

**Attack Prerequisites:**
- Network MITM position on RDP path
- RDP client that bypasses certificate warnings (common with self-signed RDP certs)

---

### HS-RDP-CONFIG-0205 — RDP Weak Cipher Suites

**Severity:** Medium | **CVSS Score:** 5.3 | **Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`

**CVE References:** None specific
**CWE:** CWE-326 (Inadequate Encryption Strength)
**OWASP:** A02:2021 – Cryptographic Failures

**Severity Reasoning:** Weak cipher suites in RDP reduce the effective confidentiality of remote desktop sessions containing potentially sensitive data. FIPS 140-2 mode in Windows disables weak RDP ciphers.

**Attack Prerequisites:**
- MITM on RDP connection
- Force weak cipher negotiation (server must support and prefer weak)

---

### HS-GENERAL-CONFIG-0900 — Target Normalization Ambiguity

**Severity:** Info | **CVSS Score:** 0.0 | **Vector:** `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N`

**CWE:** CWE-20 (Improper Input Validation)
**OWASP:** A05:2021 – Security Misconfiguration (operational)

**Severity Reasoning:** Operational diagnostic. Scan may have tested unintended endpoints. Requires operator review to confirm scan scope.

---

### HS-GENERAL-CONFIG-0901 — DNS Resolution Failed

**Severity:** Info | **CVSS Score:** 0.0 | **Vector:** `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N`

**CWE:** CWE-20 (Improper Input Validation)
**OWASP:** A05:2021 – Security Misconfiguration (operational)

**Severity Reasoning:** Operational diagnostic. Endpoint unreachable; posture cannot be determined. Check DNS configuration and network connectivity.

---

### HS-GENERAL-CONFIG-0902 — Connection Timeout

**Severity:** Info | **CVSS Score:** 0.0 | **Vector:** `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N`

**CWE:** CWE-400 (Uncontrolled Resource Consumption — network)
**OWASP:** A05:2021 – Security Misconfiguration (operational)

**Severity Reasoning:** Operational diagnostic. TCP connection timed out; firewall, host, or network is unresponsive. Does not indicate a vulnerability.

---

### HS-GENERAL-CONFIG-0903 — Protocol Auto-Detect Mismatch

**Severity:** Info | **CVSS Score:** 0.0 | **Vector:** `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N`

**CWE:** CWE-20 (Improper Input Validation)
**OWASP:** A05:2021 – Security Misconfiguration (operational)

**Severity Reasoning:** Operational diagnostic. Port is reachable but does not respond to the expected protocol. Verify the target, port, and imported scan file type before retrying.

---

### HS-GENERAL-CONFIG-0904 — Policy Profile Missing/Invalid

**Severity:** Info | **CVSS Score:** 0.0 | **Vector:** `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N`

**CWE:** CWE-20 (Improper Input Validation)
**OWASP:** A05:2021 – Security Misconfiguration (operational)

**Severity Reasoning:** Operational diagnostic. The specified YAML policy file could not be loaded; compliance evaluation was skipped. Verify the policy file path and YAML syntax.

---

*Generated for Handshaker v7.3.2 — Source: `src/findings/catalog.rs`*
