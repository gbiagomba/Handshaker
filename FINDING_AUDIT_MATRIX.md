# Finding Audit Matrix

Compact mapping of each finding to its current severity/CVSS basis after the 68-finding audit.

Primary source of truth: `src/findings/catalog.rs`

| ID | Protocol | Severity | Title | CVSS Vector | External Source Basis |
|----|----------|----------|-------|-------------|-----------------------|
| HS-GENERAL-CONFIG-0900 | General | Info | Target normalization ambiguity (multiple resolutions) | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N` | Internal calibration from standards/best-practice guidance documented in FINDING_INDEX.MD |
| HS-GENERAL-CONFIG-0901 | General | Info | DNS resolution failed | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N` | Internal calibration from standards/best-practice guidance documented in FINDING_INDEX.MD |
| HS-GENERAL-CONFIG-0902 | General | Info | Connection timeout (indeterminate posture) | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N` | Internal calibration from standards/best-practice guidance documented in FINDING_INDEX.MD |
| HS-GENERAL-CONFIG-0903 | General | Info | Protocol auto-detect mismatch | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N` | Internal calibration from standards/best-practice guidance documented in FINDING_INDEX.MD |
| HS-GENERAL-CONFIG-0904 | General | Info | Policy profile missing/invalid | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N` | Internal calibration from standards/best-practice guidance documented in FINDING_INDEX.MD |
| HS-RDP-CONFIG-0205 | Rdp | Medium | RDP weak cipher suites detected | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` | https://www.tenable.com/plugins/nessus/57690; https://www.tenable.com/plugins/nessus/26928 |
| HS-RDP-TLS-0201 | Rdp | Medium | RDP does not require NLA | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:L/I:N/A:N` | https://www.tenable.com/plugins/nessus/58453 |
| HS-RDP-TLS-0202 | Rdp | Medium | RDP accepts TLS 1.0 | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N` | Internal calibration from standards/best-practice guidance documented in FINDING_INDEX.MD |
| HS-RDP-TLS-0203 | Rdp | Medium | RDP accepts TLS 1.1 | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N` | Internal calibration from standards/best-practice guidance documented in FINDING_INDEX.MD |
| HS-RDP-TLS-0204 | Rdp | Medium | RDP certificate invalid/expired | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N` | https://www.tenable.com/plugins/nessus/15901; https://www.tenable.com/plugins/nessus/51192 |
| HS-SSH-CIPHER-0106 | Ssh | Low | CBC ciphers enabled | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N` | https://www.tenable.com/plugins/nessus/70658; https://www.tenable.com/plugins/nessus/44065 |
| HS-SSH-CIPHER-0107 | Ssh | Medium | arcfour/RC4 enabled | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N` | Internal calibration from standards/best-practice guidance documented in FINDING_INDEX.MD |
| HS-SSH-CONFIG-0110 | Ssh | Info | SSH banner exposes legacy server version | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N` | Internal calibration from standards/best-practice guidance documented in FINDING_INDEX.MD |
| HS-SSH-HOSTKEY-0104 | Ssh | Low | ssh-rsa (SHA1) hostkey enabled | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N` | https://www.rfc-editor.org/rfc/rfc9142 |
| HS-SSH-HOSTKEY-0105 | Ssh | Low | RSA hostkey < 2048 | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N` | https://www.tenable.com/plugins/nessus/153954; https://csrc.nist.gov/pubs/sp/800/131/a/r2/final |
| HS-SSH-KEX-0101 | Ssh | Low | diffie-hellman-group1-sha1 enabled | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N` | https://www.tenable.com/plugins/nessus/153953; https://www.rfc-editor.org/rfc/rfc9142 |
| HS-SSH-KEX-0102 | Ssh | Low | diffie-hellman-group-exchange-sha1 enabled | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N` | https://www.tenable.com/plugins/nessus/153953; https://www.rfc-editor.org/rfc/rfc9142 |
| HS-SSH-KEX-0103 | Ssh | Low | gss-* sha1 KEX enabled | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N` | https://www.tenable.com/plugins/nessus/153953; https://www.rfc-editor.org/rfc/rfc9142 |
| HS-SSH-MAC-0108 | Ssh | Info | hmac-sha1 enabled | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N` | https://www.tenable.com/plugins/nessus/153588 |
| HS-SSH-MAC-0109 | Ssh | Low | umac-64 enabled | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N` | https://www.tenable.com/plugins/nessus/71049 |
| HS-TLS-CERT-0001 | Tls | Medium | Certificate expired | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N` | https://www.tenable.com/plugins/nessus/15901 |
| HS-TLS-CERT-0002 | Tls | Info | Certificate not yet valid | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N` | https://www.tenable.com/plugins/nessus/42980 |
| HS-TLS-CERT-0003 | Tls | Medium | Self-signed certificate (public context) | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N` | https://www.tenable.com/plugins/nessus/57582 |
| HS-TLS-CERT-0004 | Tls | Info | Hostname mismatch (SAN/CN) | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N` | https://www.tenable.com/plugins/nessus/45410; https://www.rfc-editor.org/rfc/rfc6125 |
| HS-TLS-CERT-0005 | Tls | Medium | Weak signature algorithm (SHA1) | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N` | https://www.tenable.com/plugins/nessus/35291; https://www.tenable.com/plugins/nessus/86067 |
| HS-TLS-CERT-0006 | Tls | Low | RSA key size < 2048 | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N` | https://www.tenable.com/plugins/nessus/73459; https://www.tenable.com/plugins/was/112540; https://csrc.nist.gov/pubs/sp/800/131/a/r2/final |
| HS-TLS-CERT-0007 | Tls | Medium | Certificate chain incomplete | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N` | https://www.tenable.com/plugins/nessus/51192 |
| HS-TLS-CERT-0008 | Tls | Medium | Certificate uses weak public key type/params | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N` | https://www.tenable.com/plugins/nessus/56284; https://www.rfc-editor.org/rfc/rfc5280 |
| HS-TLS-CERT-0009 | Tls | Info | Long-lived certificate validity (policy violation) | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N` | Internal calibration from standards/best-practice guidance documented in FINDING_INDEX.MD |
| HS-TLS-CERT-0010 | Tls | Info | OCSP stapling not supported (best practice) | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N` | Internal calibration from standards/best-practice guidance documented in FINDING_INDEX.MD |
| HS-TLS-CERT-0011 | Tls | Info | OCSP Must-Staple not set | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N` | Internal calibration from standards/best-practice guidance documented in FINDING_INDEX.MD |
| HS-TLS-CERT-0012 | Tls | Info | Certificate transparency SCT not observed | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N` | Internal calibration from standards/best-practice guidance documented in FINDING_INDEX.MD |
| HS-TLS-CERT-0013 | Tls | Info | RSA key size below 3072 | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N` | Internal calibration from standards/best-practice guidance documented in FINDING_INDEX.MD |
| HS-TLS-CIPHER-0001 | Tls | Critical | NULL cipher suite supported | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` | Internal calibration from standards/best-practice guidance documented in FINDING_INDEX.MD |
| HS-TLS-CIPHER-0002 | Tls | Medium | Anonymous (aNULL) cipher suite supported | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N` | https://www.tenable.com/plugins/nessus/31705 |
| HS-TLS-CIPHER-0003 | Tls | High | EXPORT cipher suite supported | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N` | Internal calibration from standards/best-practice guidance documented in FINDING_INDEX.MD |
| HS-TLS-CIPHER-0004 | Tls | Medium | RC4 cipher suite supported | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N` | https://www.tenable.com/plugins/nessus/73683 |
| HS-TLS-CIPHER-0005 | Tls | High | 3DES cipher suite supported (SWEET32 exposure indicator) | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` | https://www.tenable.com/plugins/nessus/111649 |
| HS-TLS-CIPHER-0006 | Tls | Medium | CBC-only suites with TLS 1.0 enabled (BEAST exposure indicator) | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N` | Internal calibration from standards/best-practice guidance documented in FINDING_INDEX.MD |
| HS-TLS-CIPHER-0007 | Tls | Medium | Weak medium strength cipher policy (64–112-bit) | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N` | https://www.tenable.com/plugins/nessus/42873 |
| HS-TLS-CIPHER-0008 | Tls | Medium | No AEAD suites available (no GCM/ChaCha20) | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N` | Internal calibration from standards/best-practice guidance documented in FINDING_INDEX.MD |
| HS-TLS-CIPHER-0009 | Tls | Medium | No forward secrecy suites observed | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N` | Internal calibration from standards/best-practice guidance documented in FINDING_INDEX.MD |
| HS-TLS-CIPHER-0010 | Tls | Medium | Legacy RSA key exchange supported (no (EC)DHE) | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N` | Internal calibration from standards/best-practice guidance documented in FINDING_INDEX.MD |
| HS-TLS-CIPHER-0011 | Tls | Medium | Weak elliptic curve supported | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N` | Internal calibration from standards/best-practice guidance documented in FINDING_INDEX.MD |
| HS-TLS-CIPHER-0012 | Tls | Info | No ChaCha20-Poly1305 suites available | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N` | Internal calibration from standards/best-practice guidance documented in FINDING_INDEX.MD |
| HS-TLS-EXTENSION-0011 | Tls | Info | ALPN hardening missing for HTTP/2 | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N` | Internal calibration from standards/best-practice guidance documented in FINDING_INDEX.MD |
| HS-TLS-EXTENSION-0012 | Tls | Info | ALPN not advertised | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N` | Internal calibration from standards/best-practice guidance documented in FINDING_INDEX.MD |
| HS-TLS-PROTOCOL-0001 | Tls | Critical | SSLv2 supported | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` | Internal calibration from standards/best-practice guidance documented in FINDING_INDEX.MD |
| HS-TLS-PROTOCOL-0002 | Tls | High | SSLv3 supported | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L` | Internal calibration from standards/best-practice guidance documented in FINDING_INDEX.MD |
| HS-TLS-PROTOCOL-0003 | Tls | Medium | TLS 1.0 enabled | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:N` | https://www.tenable.com/plugins/nessus/104743; https://www.tenable.com/plugins/nessus/84470; https://www.rfc-editor.org/rfc/rfc8996 |
| HS-TLS-PROTOCOL-0004 | Tls | Medium | TLS 1.1 enabled | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:N` | https://www.tenable.com/plugins/nessus/157288; https://www.rfc-editor.org/rfc/rfc8996 |
| HS-TLS-PROTOCOL-0005 | Tls | High | TLS 1.2 not supported | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L` | Internal calibration from standards/best-practice guidance documented in FINDING_INDEX.MD |
| HS-TLS-PROTOCOL-0006 | Tls | Info | TLS 1.3 not supported | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N` | Internal calibration from standards/best-practice guidance documented in FINDING_INDEX.MD |
| HS-TLS-PROTOCOL-0007 | Tls | Medium | Insecure renegotiation allowed | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N` | Internal calibration from standards/best-practice guidance documented in FINDING_INDEX.MD |
| HS-TLS-PROTOCOL-0008 | Tls | Medium | Secure renegotiation not supported | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N` | Internal calibration from standards/best-practice guidance documented in FINDING_INDEX.MD |
| HS-TLS-PROTOCOL-0009 | Tls | Medium | TLS compression enabled (CRIME risk indicator) | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N` | Internal calibration from standards/best-practice guidance documented in FINDING_INDEX.MD |
| HS-TLS-PROTOCOL-0010 | Tls | Medium | HTTP/2 offered over weak TLS settings | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N` | Internal calibration from standards/best-practice guidance documented in FINDING_INDEX.MD |
| HS-TLS-SCENARIO-0001 | Tls | Medium | No TLS_FALLBACK_SCSV support (downgrade resilience indicator) | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N` | Internal calibration from standards/best-practice guidance documented in FINDING_INDEX.MD |
| HS-TLS-SCENARIO-0002 | Tls | Medium | Accepts forced downgrade to TLS 1.0 | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N` | Internal calibration from standards/best-practice guidance documented in FINDING_INDEX.MD |
| HS-TLS-SCENARIO-0003 | Tls | Info | Session tickets enabled without rotation indicator | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N` | Internal calibration from standards/best-practice guidance documented in FINDING_INDEX.MD |
| HS-TLS-SCENARIO-0004 | Tls | Low | Supports weak DH parameters (Logjam-style exposure indicator) | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N` | https://nvd.nist.gov/vuln/detail/CVE-2015-4000; https://www.tenable.com/plugins/nessus/53360 |
| HS-TLS-SCENARIO-0005 | Tls | Medium | SWEET32 exposure indicator (3DES + high-volume contexts) | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N` | Internal calibration from standards/best-practice guidance documented in FINDING_INDEX.MD |
| HS-TLS-SCENARIO-0006 | Tls | Medium | BEAST exposure indicator (TLS1.0 + CBC) | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N` | Internal calibration from standards/best-practice guidance documented in FINDING_INDEX.MD |
| HS-TLS-SCENARIO-0007 | Tls | Medium | Insecure record fragmentation behavior indicator | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N` | Internal calibration from standards/best-practice guidance documented in FINDING_INDEX.MD |
| HS-TLS-SCENARIO-0008 | Tls | Medium | Weak cipher preference (server chooses weak even if strong offered) | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N` | Internal calibration from standards/best-practice guidance documented in FINDING_INDEX.MD |
| HS-TLS-SCENARIO-0009 | Tls | Info | TLS 1.3 0-RTT enabled indicator | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N` | Internal calibration from standards/best-practice guidance documented in FINDING_INDEX.MD |
| HS-TLS-SCENARIO-0010 | Tls | Medium | STARTTLS downgrade possible (banner lacks STARTTLS) | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N` | Internal calibration from standards/best-practice guidance documented in FINDING_INDEX.MD |
| HS-TLS-SCENARIO-0011 | Tls | Medium | STARTTLS accepted without policy enforcement | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N` | Internal calibration from standards/best-practice guidance documented in FINDING_INDEX.MD |
