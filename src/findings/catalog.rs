pub use crate::findings::types::FindingMeta;
use crate::models::{Protocol, Severity};

// Generated starter catalog from rsc/handshake_support_prompt.md

pub const HS_TLS_PROTOCOL_0001: FindingMeta = FindingMeta {
    id: "HS-TLS-PROTOCOL-0001",
    title: "SSLv2 supported",
    protocol: Protocol::Tls,
    severity: Severity::Critical,
    description: "The service negotiates SSLv2, an obsolete protocol with severe cryptographic weaknesses.",
    impact: "An on-path attacker can exploit legacy protocol weaknesses to break confidentiality and integrity, enabling interception or manipulation of traffic.",
    remediation: "Disable SSLv2 at the server and any upstream TLS termination points. Ensure clients cannot negotiate SSLv2.",
    references: &[],
    cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
};

pub const HS_TLS_PROTOCOL_0002: FindingMeta = FindingMeta {
    id: "HS-TLS-PROTOCOL-0002",
    title: "SSLv3 supported",
    protocol: Protocol::Tls,
    severity: Severity::High,
    description: "The service negotiates SSLv3, an obsolete protocol with well-known weaknesses.",
    impact: "Legacy downgrade paths can enable man-in-the-middle attacks and weaken or break confidentiality.",
    remediation: "Disable SSLv3. Permit only TLS 1.2+ (and preferably TLS 1.3).",
    references: &[],
    cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
};

pub const HS_TLS_PROTOCOL_0003: FindingMeta = FindingMeta {
    id: "HS-TLS-PROTOCOL-0003",
    title: "TLS 1.0 enabled",
    protocol: Protocol::Tls,
    severity: Severity::Medium,
    description: "The service accepts connections using TLS 1.0, a deprecated protocol version.",
    impact: "TLS 1.0 is affected by multiple cryptographic weaknesses and ecosystem deprecations; attackers may leverage downgrade or protocol weaknesses to weaken confidentiality and integrity.",
    remediation: "Disable TLS 1.0 at the service and any TLS termination points. Enforce TLS 1.2+.",
    references: &[
        "https://www.tenable.com/plugins/nessus/84470",
        "https://www.tenable.com/plugins/nessus/104743",
    ],
    cvss_vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
};

pub const HS_TLS_PROTOCOL_0004: FindingMeta = FindingMeta {
    id: "HS-TLS-PROTOCOL-0004",
    title: "TLS 1.1 enabled",
    protocol: Protocol::Tls,
    severity: Severity::Medium,
    description: "The service accepts connections using TLS 1.1, a deprecated protocol version.",
    impact: "TLS 1.1 lacks support for modern recommended cipher suites and is deprecated by major vendors; allowing it increases downgrade surface and weakens posture.",
    remediation: "Disable TLS 1.1 and enforce TLS 1.2+.",
    references: &["https://www.tenable.com/plugins/nessus/157288"],
    cvss_vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
};

pub const HS_TLS_PROTOCOL_0005: FindingMeta = FindingMeta {
    id: "HS-TLS-PROTOCOL-0005",
    title: "TLS 1.2 not supported",
    protocol: Protocol::Tls,
    severity: Severity::High,
    description: "The service does not support TLS 1.2, preventing modern cipher suites and secure interoperability.",
    impact: "Clients may be forced onto deprecated protocols/ciphers or fail to connect; where connectivity remains, security posture is materially degraded.",
    remediation: "Enable TLS 1.2 (and ideally TLS 1.3). Update server libraries and configuration to support modern suites.",
    references: &[],
    cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L",
};

pub const HS_TLS_PROTOCOL_0006: FindingMeta = FindingMeta {
    id: "HS-TLS-PROTOCOL-0006",
    title: "TLS 1.3 not supported",
    protocol: Protocol::Tls,
    severity: Severity::Low,
    description: "The service does not support TLS 1.3.",
    impact: "Lack of TLS 1.3 can indicate slower handshakes and missing modern hardening features.",
    remediation: "Enable TLS 1.3 where supported by the server stack.",
    references: &[],
    cvss_vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N",
};

pub const HS_TLS_PROTOCOL_0007: FindingMeta = FindingMeta {
    id: "HS-TLS-PROTOCOL-0007",
    title: "Insecure renegotiation allowed",
    protocol: Protocol::Tls,
    severity: Severity::Medium,
    description: "The service allows insecure renegotiation.",
    impact: "Insecure renegotiation enables man-in-the-middle protocol injection attacks.",
    remediation: "Disable insecure renegotiation and enable secure renegotiation (RFC 5746).",
    references: &[],
    cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
};

pub const HS_TLS_PROTOCOL_0008: FindingMeta = FindingMeta {
    id: "HS-TLS-PROTOCOL-0008",
    title: "Secure renegotiation not supported",
    protocol: Protocol::Tls,
    severity: Severity::Medium,
    description: "The service does not support secure renegotiation.",
    impact: "Missing secure renegotiation widens compatibility with insecure clients and can weaken posture.",
    remediation: "Enable secure renegotiation (RFC 5746) or upgrade the TLS stack.",
    references: &[],
    cvss_vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
};

pub const HS_TLS_PROTOCOL_0009: FindingMeta = FindingMeta {
    id: "HS-TLS-PROTOCOL-0009",
    title: "TLS compression enabled (CRIME risk indicator)",
    protocol: Protocol::Tls,
    severity: Severity::Medium,
    description: "The server allows TLS-level compression.",
    impact: "TLS compression enables CRIME-style attacks in certain contexts.",
    remediation: "Disable TLS compression.",
    references: &[],
    cvss_vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
};

pub const HS_TLS_PROTOCOL_0010: FindingMeta = FindingMeta {
    id: "HS-TLS-PROTOCOL-0010",
    title: "HTTP/2 offered over weak TLS settings",
    protocol: Protocol::Tls,
    severity: Severity::Medium,
    description: "HTTP/2 offered with weak TLS settings.",
    impact:
        "HTTP/2 requires stronger TLS posture; weak settings can lead to downgrade or exposure.",
    remediation: "Harden TLS settings to meet HTTP/2 security requirements.",
    references: &[],
    cvss_vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
};

pub const HS_TLS_CIPHER_0001: FindingMeta = FindingMeta {
    id: "HS-TLS-CIPHER-0001",
    title: "NULL cipher suite supported",
    protocol: Protocol::Tls,
    severity: Severity::Critical,
    description: "The service supports NULL cipher suites (no encryption).",
    impact: "Traffic can be intercepted or modified by an on-path attacker.",
    remediation: "Disable NULL cipher suites.",
    references: &[],
    cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
};

pub const HS_TLS_CIPHER_0002: FindingMeta = FindingMeta {
    id: "HS-TLS-CIPHER-0002",
    title: "Anonymous (aNULL) cipher suite supported",
    protocol: Protocol::Tls,
    severity: Severity::High,
    description: "The service supports anonymous cipher suites without authentication.",
    impact: "Man-in-the-middle attacks are possible due to lack of authentication.",
    remediation: "Disable aNULL cipher suites.",
    references: &[],
    cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
};

pub const HS_TLS_CIPHER_0003: FindingMeta = FindingMeta {
    id: "HS-TLS-CIPHER-0003",
    title: "EXPORT cipher suite supported",
    protocol: Protocol::Tls,
    severity: Severity::High,
    description: "The service supports export-grade cipher suites.",
    impact: "Export-grade ciphers are trivially breakable.",
    remediation: "Disable export cipher suites.",
    references: &[],
    cvss_vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
};

pub const HS_TLS_CIPHER_0004: FindingMeta = FindingMeta {
    id: "HS-TLS-CIPHER-0004",
    title: "RC4 cipher suite supported",
    protocol: Protocol::Tls,
    severity: Severity::Medium,
    description: "The service supports RC4 cipher suites.",
    impact: "RC4 has known biases that enable plaintext recovery in some contexts.",
    remediation: "Disable RC4 cipher suites.",
    references: &["https://www.tenable.com/plugins/nessus/73683"],
    cvss_vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
};

pub const HS_TLS_CIPHER_0005: FindingMeta = FindingMeta {
    id: "HS-TLS-CIPHER-0005",
    title: "3DES cipher suite supported (SWEET32 exposure indicator)",
    protocol: Protocol::Tls,
    severity: Severity::High,
    description: "The service supports 3DES cipher suites.",
    impact: "3DES is vulnerable to SWEET32-style attacks in high-volume contexts.",
    remediation: "Disable 3DES cipher suites.",
    references: &["https://www.tenable.com/plugins/nessus/111649"],
    cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
};

pub const HS_TLS_CIPHER_0006: FindingMeta = FindingMeta {
    id: "HS-TLS-CIPHER-0006",
    title: "CBC-only suites with TLS 1.0 enabled (BEAST exposure indicator)",
    protocol: Protocol::Tls,
    severity: Severity::Medium,
    description: "TLS 1.0 with CBC-only cipher suites can be vulnerable to BEAST.",
    impact: "An on-path attacker could exploit BEAST in certain contexts.",
    remediation: "Disable TLS 1.0 or prefer AEAD suites.",
    references: &[],
    cvss_vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
};

pub const HS_TLS_CIPHER_0007: FindingMeta = FindingMeta {
    id: "HS-TLS-CIPHER-0007",
    title: "Weak medium strength cipher policy (64–112-bit)",
    protocol: Protocol::Tls,
    severity: Severity::Medium,
    description: "The service supports medium strength cipher suites.",
    impact: "Medium strength ciphers are less resistant to brute force.",
    remediation: "Disable medium strength ciphers.",
    references: &["https://www.tenable.com/plugins/nessus/42873"],
    cvss_vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
};

pub const HS_TLS_CIPHER_0008: FindingMeta = FindingMeta {
    id: "HS-TLS-CIPHER-0008",
    title: "No AEAD suites available (no GCM/ChaCha20)",
    protocol: Protocol::Tls,
    severity: Severity::Medium,
    description: "The service did not offer any AEAD cipher suites.",
    impact: "Lack of AEAD suites can increase exposure to padding oracles.",
    remediation: "Enable AEAD suites such as AES-GCM or ChaCha20-Poly1305.",
    references: &[],
    cvss_vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
};

pub const HS_TLS_CIPHER_0009: FindingMeta = FindingMeta {
    id: "HS-TLS-CIPHER-0009",
    title: "No forward secrecy suites observed",
    protocol: Protocol::Tls,
    severity: Severity::Medium,
    description: "The server does not negotiate forward secrecy cipher suites.",
    impact: "If the private key is compromised, past sessions may be decrypted.",
    remediation: "Enable ECDHE/DHE cipher suites.",
    references: &[],
    cvss_vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
};

pub const HS_TLS_CIPHER_0010: FindingMeta = FindingMeta {
    id: "HS-TLS-CIPHER-0010",
    title: "Legacy RSA key exchange supported (no (EC)DHE)",
    protocol: Protocol::Tls,
    severity: Severity::Medium,
    description: "The server supports RSA key exchange without (EC)DHE.",
    impact: "Lack of ephemeral key exchange weakens forward secrecy.",
    remediation: "Enable (EC)DHE suites.",
    references: &[],
    cvss_vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
};

pub const HS_TLS_CERT_0001: FindingMeta = FindingMeta {
    id: "HS-TLS-CERT-0001",
    title: "Certificate expired",
    protocol: Protocol::Tls,
    severity: Severity::Critical,
    description: "The certificate is expired.",
    impact: "Clients may reject the connection or be vulnerable to MITM.",
    remediation: "Renew and replace the certificate.",
    references: &[],
    cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
};

pub const HS_TLS_CERT_0002: FindingMeta = FindingMeta {
    id: "HS-TLS-CERT-0002",
    title: "Certificate not yet valid",
    protocol: Protocol::Tls,
    severity: Severity::High,
    description: "The certificate is not yet valid.",
    impact: "Clients may reject the connection or be vulnerable to MITM.",
    remediation: "Correct system time or install a valid certificate.",
    references: &[],
    cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
};

pub const HS_TLS_CERT_0003: FindingMeta = FindingMeta {
    id: "HS-TLS-CERT-0003",
    title: "Self-signed certificate (public context)",
    protocol: Protocol::Tls,
    severity: Severity::High,
    description: "The server presents a self-signed certificate.",
    impact: "Clients cannot validate server identity, enabling MITM attacks.",
    remediation: "Use a certificate issued by a trusted CA.",
    references: &[],
    cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
};

pub const HS_TLS_CERT_0004: FindingMeta = FindingMeta {
    id: "HS-TLS-CERT-0004",
    title: "Hostname mismatch (SAN/CN)",
    protocol: Protocol::Tls,
    severity: Severity::High,
    description: "Certificate hostname does not match the target host.",
    impact: "Clients may reject the connection or be vulnerable to MITM.",
    remediation: "Issue a certificate with proper SAN/CN entries.",
    references: &[],
    cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
};

pub const HS_TLS_CERT_0005: FindingMeta = FindingMeta {
    id: "HS-TLS-CERT-0005",
    title: "Weak signature algorithm (SHA1)",
    protocol: Protocol::Tls,
    severity: Severity::Medium,
    description: "The certificate uses a SHA1 signature algorithm.",
    impact: "SHA1 is deprecated due to collision attacks.",
    remediation: "Use SHA-256 or stronger.",
    references: &[],
    cvss_vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
};

pub const HS_TLS_CERT_0006: FindingMeta = FindingMeta {
    id: "HS-TLS-CERT-0006",
    title: "RSA key size < 2048",
    protocol: Protocol::Tls,
    severity: Severity::Medium,
    description: "The certificate uses an RSA key smaller than 2048 bits.",
    impact: "Short keys are vulnerable to brute force.",
    remediation: "Use RSA 2048+ or ECDSA with strong curves.",
    references: &[],
    cvss_vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
};

pub const HS_TLS_CERT_0007: FindingMeta = FindingMeta {
    id: "HS-TLS-CERT-0007",
    title: "Certificate chain incomplete",
    protocol: Protocol::Tls,
    severity: Severity::Medium,
    description: "The certificate chain is incomplete.",
    impact: "Some clients may fail to validate the certificate.",
    remediation: "Serve the full certificate chain.",
    references: &[],
    cvss_vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
};

pub const HS_TLS_CERT_0008: FindingMeta = FindingMeta {
    id: "HS-TLS-CERT-0008",
    title: "Certificate uses weak public key type/params",
    protocol: Protocol::Tls,
    severity: Severity::Medium,
    description: "The certificate uses weak public key parameters.",
    impact: "Weak public key parameters reduce cryptographic strength.",
    remediation: "Use modern key types and parameters.",
    references: &[],
    cvss_vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
};

pub const HS_TLS_CERT_0009: FindingMeta = FindingMeta {
    id: "HS-TLS-CERT-0009",
    title: "Long-lived certificate validity (policy violation)",
    protocol: Protocol::Tls,
    severity: Severity::Low,
    description: "The certificate validity exceeds recommended limits.",
    impact: "Long-lived certs increase exposure window for key compromise.",
    remediation: "Use shorter certificate validity periods.",
    references: &[],
    cvss_vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N",
};

pub const HS_TLS_CERT_0010: FindingMeta = FindingMeta {
    id: "HS-TLS-CERT-0010",
    title: "OCSP stapling not supported (best practice)",
    protocol: Protocol::Tls,
    severity: Severity::Low,
    description: "OCSP stapling was not observed.",
    impact: "Clients may have to fetch OCSP, impacting privacy or performance.",
    remediation: "Enable OCSP stapling.",
    references: &[],
    cvss_vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N",
};

pub const HS_TLS_CERT_0011: FindingMeta = FindingMeta {
    id: "HS-TLS-CERT-0011",
    title: "OCSP Must-Staple not set",
    protocol: Protocol::Tls,
    severity: Severity::Low,
    description: "The certificate does not include the OCSP Must-Staple extension.",
    impact:
        "Clients may be unable to require stapled OCSP responses, reducing revocation freshness.",
    remediation:
        "Issue a certificate with the TLS Feature extension for OCSP Must-Staple if required.",
    references: &[],
    cvss_vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N",
};

pub const HS_TLS_CERT_0012: FindingMeta = FindingMeta {
    id: "HS-TLS-CERT-0012",
    title: "Certificate transparency SCT not observed",
    protocol: Protocol::Tls,
    severity: Severity::Low,
    description: "Signed Certificate Timestamps (SCT) were not observed.",
    impact: "Missing SCTs can reduce transparency auditing for publicly trusted certificates.",
    remediation: "Ensure CT logs/SCTs are included for public certificates.",
    references: &[],
    cvss_vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N",
};

pub const HS_TLS_CIPHER_0011: FindingMeta = FindingMeta {
    id: "HS-TLS-CIPHER-0011",
    title: "Weak elliptic curve supported",
    protocol: Protocol::Tls,
    severity: Severity::Medium,
    description: "The server supports weak elliptic curve parameters.",
    impact: "Weak curves reduce the effective security of ECDHE.",
    remediation: "Disable weak curves and prefer modern curves (e.g., X25519, P-256).",
    references: &[],
    cvss_vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
};

pub const HS_TLS_EXTENSION_0011: FindingMeta = FindingMeta {
    id: "HS-TLS-EXTENSION-0011",
    title: "ALPN hardening missing for HTTP/2",
    protocol: Protocol::Tls,
    severity: Severity::Low,
    description: "ALPN configuration does not enforce expected HTTP/2 hardening.",
    impact: "ALPN misconfiguration can allow weaker protocol negotiation paths.",
    remediation: "Configure ALPN explicitly for HTTP/2 and restrict weak protocol paths.",
    references: &[],
    cvss_vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N",
};

pub const HS_TLS_SCENARIO_0009: FindingMeta = FindingMeta {
    id: "HS-TLS-SCENARIO-0009",
    title: "TLS 1.3 0-RTT enabled indicator",
    protocol: Protocol::Tls,
    severity: Severity::Low,
    description: "0-RTT appears enabled for TLS 1.3.",
    impact: "0-RTT can enable replay of early data if not mitigated.",
    remediation: "Disable 0-RTT or restrict early data for idempotent requests only.",
    references: &[],
    cvss_vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N",
};

pub const HS_TLS_SCENARIO_0010: FindingMeta = FindingMeta {
    id: "HS-TLS-SCENARIO-0010",
    title: "STARTTLS downgrade possible (banner lacks STARTTLS)",
    protocol: Protocol::Tls,
    severity: Severity::Medium,
    description: "STARTTLS capability was not advertised where expected.",
    impact: "Downgrade to cleartext may be possible in STARTTLS-based protocols.",
    remediation: "Ensure STARTTLS is enforced and announced for STARTTLS services.",
    references: &[],
    cvss_vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
};

pub const HS_TLS_SCENARIO_0011: FindingMeta = FindingMeta {
    id: "HS-TLS-SCENARIO-0011",
    title: "STARTTLS accepted without policy enforcement",
    protocol: Protocol::Tls,
    severity: Severity::Medium,
    description: "STARTTLS was optional and could be bypassed.",
    impact: "Opportunistic STARTTLS can be stripped by active attackers.",
    remediation: "Require STARTTLS and enforce TLS-only policy.",
    references: &[],
    cvss_vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
};

pub const HS_TLS_CIPHER_0012: FindingMeta = FindingMeta {
    id: "HS-TLS-CIPHER-0012",
    title: "No ChaCha20-Poly1305 suites available",
    protocol: Protocol::Tls,
    severity: Severity::Low,
    description: "The server does not appear to offer ChaCha20-Poly1305 suites.",
    impact: "Lack of ChaCha20 can reduce performance or resilience on some platforms.",
    remediation: "Enable ChaCha20-Poly1305 suites where appropriate.",
    references: &[],
    cvss_vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N",
};

pub const HS_TLS_EXTENSION_0012: FindingMeta = FindingMeta {
    id: "HS-TLS-EXTENSION-0012",
    title: "ALPN not advertised",
    protocol: Protocol::Tls,
    severity: Severity::Low,
    description: "The server did not advertise any ALPN protocols.",
    impact: "Lack of ALPN can prevent negotiation of modern protocols like HTTP/2.",
    remediation: "Configure ALPN to advertise supported application protocols.",
    references: &[],
    cvss_vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N",
};

pub const HS_TLS_CERT_0013: FindingMeta = FindingMeta {
    id: "HS-TLS-CERT-0013",
    title: "RSA key size below 3072",
    protocol: Protocol::Tls,
    severity: Severity::Low,
    description: "The certificate uses RSA with size below 3072 bits.",
    impact: "Some policies require 3072-bit RSA for higher assurance.",
    remediation: "Use RSA 3072+ or modern ECDSA keys where policy requires.",
    references: &[],
    cvss_vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N",
};

pub const HS_TLS_SCENARIO_0001: FindingMeta = FindingMeta {
    id: "HS-TLS-SCENARIO-0001",
    title: "No TLS_FALLBACK_SCSV support (downgrade resilience indicator)",
    protocol: Protocol::Tls,
    severity: Severity::Medium,
    description: "The server does not support TLS_FALLBACK_SCSV.",
    impact: "Lack of TLS_FALLBACK_SCSV can allow downgrade attacks.",
    remediation: "Enable TLS_FALLBACK_SCSV support.",
    references: &[],
    cvss_vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
};

pub const HS_TLS_SCENARIO_0002: FindingMeta = FindingMeta {
    id: "HS-TLS-SCENARIO-0002",
    title: "Accepts forced downgrade to TLS 1.0",
    protocol: Protocol::Tls,
    severity: Severity::Medium,
    description: "The server accepts a forced downgrade to TLS 1.0.",
    impact: "Attackers may force weaker protocol versions.",
    remediation: "Disable TLS 1.0 and support TLS_FALLBACK_SCSV.",
    references: &[],
    cvss_vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
};

pub const HS_TLS_SCENARIO_0003: FindingMeta = FindingMeta {
    id: "HS-TLS-SCENARIO-0003",
    title: "Session tickets enabled without rotation indicator",
    protocol: Protocol::Tls,
    severity: Severity::Low,
    description: "Session tickets appear enabled without rotation indicator.",
    impact: "Static ticket keys can allow long-term decryption if compromised.",
    remediation: "Rotate session ticket keys regularly.",
    references: &[],
    cvss_vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N",
};

pub const HS_TLS_SCENARIO_0004: FindingMeta = FindingMeta {
    id: "HS-TLS-SCENARIO-0004",
    title: "Supports weak DH parameters (Logjam-style exposure indicator)",
    protocol: Protocol::Tls,
    severity: Severity::Medium,
    description: "The server supports weak DH parameters.",
    impact: "Weak DH parameters can enable Logjam-style attacks.",
    remediation: "Use strong DH parameters (>=2048 bits) or ECDHE.",
    references: &[],
    cvss_vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
};

pub const HS_TLS_SCENARIO_0005: FindingMeta = FindingMeta {
    id: "HS-TLS-SCENARIO-0005",
    title: "SWEET32 exposure indicator (3DES + high-volume contexts)",
    protocol: Protocol::Tls,
    severity: Severity::Medium,
    description: "3DES usage indicates SWEET32 exposure in high-volume contexts.",
    impact: "High-volume sessions can leak plaintext via SWEET32.",
    remediation: "Disable 3DES.",
    references: &[],
    cvss_vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
};

pub const HS_TLS_SCENARIO_0006: FindingMeta = FindingMeta {
    id: "HS-TLS-SCENARIO-0006",
    title: "BEAST exposure indicator (TLS1.0 + CBC)",
    protocol: Protocol::Tls,
    severity: Severity::Medium,
    description: "TLS 1.0 with CBC indicates BEAST exposure.",
    impact: "BEAST can enable partial plaintext recovery.",
    remediation: "Disable TLS 1.0 or prefer AEAD suites.",
    references: &[],
    cvss_vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
};

pub const HS_TLS_SCENARIO_0007: FindingMeta = FindingMeta {
    id: "HS-TLS-SCENARIO-0007",
    title: "Insecure record fragmentation behavior indicator",
    protocol: Protocol::Tls,
    severity: Severity::Medium,
    description: "Record fragmentation behavior indicates potential risk.",
    impact: "Fragmentation quirks can weaken protections.",
    remediation: "Use modern TLS stacks and disable legacy modes.",
    references: &[],
    cvss_vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
};

pub const HS_TLS_SCENARIO_0008: FindingMeta = FindingMeta {
    id: "HS-TLS-SCENARIO-0008",
    title: "Weak cipher preference (server chooses weak even if strong offered)",
    protocol: Protocol::Tls,
    severity: Severity::Medium,
    description: "Server preference selects weak ciphers even when strong are offered.",
    impact: "Attackers may steer negotiation to weak ciphers.",
    remediation: "Prefer strong ciphers and disable weak ones.",
    references: &[],
    cvss_vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
};

pub const HS_SSH_KEX_0101: FindingMeta = FindingMeta {
    id: "HS-SSH-KEX-0101",
    title: "diffie-hellman-group1-sha1 enabled",
    protocol: Protocol::Ssh,
    severity: Severity::Medium,
    description: "The server supports diffie-hellman-group1-sha1.",
    impact: "Group1 is weak and vulnerable to logjam-style attacks.",
    remediation: "Disable group1 and use modern KEX algorithms.",
    references: &[],
    cvss_vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
};

pub const HS_SSH_KEX_0102: FindingMeta = FindingMeta {
    id: "HS-SSH-KEX-0102",
    title: "diffie-hellman-group-exchange-sha1 enabled",
    protocol: Protocol::Ssh,
    severity: Severity::Medium,
    description: "The server supports diffie-hellman-group-exchange-sha1.",
    impact: "SHA1-based KEX is deprecated.",
    remediation: "Use group-exchange-sha256 or curve25519.",
    references: &[],
    cvss_vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
};

pub const HS_SSH_KEX_0103: FindingMeta = FindingMeta {
    id: "HS-SSH-KEX-0103",
    title: "gss-* sha1 KEX enabled",
    protocol: Protocol::Ssh,
    severity: Severity::Medium,
    description: "The server supports gss-* sha1 key exchange.",
    impact: "SHA1 in KEX is deprecated.",
    remediation: "Disable SHA1-based KEX.",
    references: &[],
    cvss_vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
};

pub const HS_SSH_HOSTKEY_0104: FindingMeta = FindingMeta {
    id: "HS-SSH-HOSTKEY-0104",
    title: "ssh-rsa (SHA1) hostkey enabled",
    protocol: Protocol::Ssh,
    severity: Severity::Medium,
    description: "The server supports ssh-rsa with SHA1 signatures.",
    impact: "SHA1 is deprecated and weak.",
    remediation: "Disable ssh-rsa or enable rsa-sha2-*.",
    references: &[],
    cvss_vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
};

pub const HS_SSH_HOSTKEY_0105: FindingMeta = FindingMeta {
    id: "HS-SSH-HOSTKEY-0105",
    title: "RSA hostkey < 2048",
    protocol: Protocol::Ssh,
    severity: Severity::Medium,
    description: "The server presents an RSA hostkey < 2048 bits.",
    impact: "Short RSA keys are weak against brute force.",
    remediation: "Use RSA 2048+ or ECDSA/Ed25519.",
    references: &[],
    cvss_vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
};

pub const HS_SSH_CIPHER_0106: FindingMeta = FindingMeta {
    id: "HS-SSH-CIPHER-0106",
    title: "CBC ciphers enabled",
    protocol: Protocol::Ssh,
    severity: Severity::Medium,
    description: "The server supports CBC-mode ciphers.",
    impact: "CBC in SSH can be vulnerable to plaintext recovery in some contexts.",
    remediation: "Use CTR or AEAD modes.",
    references: &[],
    cvss_vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
};

pub const HS_SSH_CIPHER_0107: FindingMeta = FindingMeta {
    id: "HS-SSH-CIPHER-0107",
    title: "arcfour/RC4 enabled",
    protocol: Protocol::Ssh,
    severity: Severity::Medium,
    description: "The server supports RC4/arcfour ciphers.",
    impact: "RC4 is deprecated and insecure.",
    remediation: "Disable RC4.",
    references: &[],
    cvss_vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
};

pub const HS_SSH_MAC_0108: FindingMeta = FindingMeta {
    id: "HS-SSH-MAC-0108",
    title: "hmac-sha1 enabled",
    protocol: Protocol::Ssh,
    severity: Severity::Medium,
    description: "The server supports hmac-sha1.",
    impact: "SHA1-based MACs are deprecated.",
    remediation: "Disable hmac-sha1.",
    references: &[],
    cvss_vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
};

pub const HS_SSH_MAC_0109: FindingMeta = FindingMeta {
    id: "HS-SSH-MAC-0109",
    title: "umac-64 enabled",
    protocol: Protocol::Ssh,
    severity: Severity::Medium,
    description: "The server supports umac-64.",
    impact: "UMAC-64 provides reduced integrity strength.",
    remediation: "Use umac-128 or hmac-sha2.",
    references: &[],
    cvss_vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
};

pub const HS_SSH_CONFIG_0110: FindingMeta = FindingMeta {
    id: "HS-SSH-CONFIG-0110",
    title: "SSH banner exposes legacy server version",
    protocol: Protocol::Ssh,
    severity: Severity::Low,
    description: "The server banner discloses a legacy version.",
    impact: "Legacy versions are more likely to contain known vulnerabilities.",
    remediation: "Upgrade SSH server and avoid version disclosure if possible.",
    references: &[],
    cvss_vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N",
};

pub const HS_RDP_TLS_0201: FindingMeta = FindingMeta {
    id: "HS-RDP-TLS-0201",
    title: "RDP does not require NLA",
    protocol: Protocol::Rdp,
    severity: Severity::High,
    description: "RDP does not require Network Level Authentication.",
    impact:
        "RDP without NLA increases exposure to credential attacks and pre-auth vulnerabilities.",
    remediation: "Require NLA and restrict RDP exposure.",
    references: &[],
    cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L",
};

pub const HS_RDP_TLS_0202: FindingMeta = FindingMeta {
    id: "HS-RDP-TLS-0202",
    title: "RDP accepts TLS 1.0",
    protocol: Protocol::Rdp,
    severity: Severity::Medium,
    description: "RDP service accepts TLS 1.0.",
    impact: "TLS 1.0 is deprecated and weak.",
    remediation: "Disable TLS 1.0 for RDP.",
    references: &[],
    cvss_vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
};

pub const HS_RDP_TLS_0203: FindingMeta = FindingMeta {
    id: "HS-RDP-TLS-0203",
    title: "RDP accepts TLS 1.1",
    protocol: Protocol::Rdp,
    severity: Severity::Medium,
    description: "RDP service accepts TLS 1.1.",
    impact: "TLS 1.1 is deprecated.",
    remediation: "Disable TLS 1.1 for RDP.",
    references: &[],
    cvss_vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
};

pub const HS_RDP_TLS_0204: FindingMeta = FindingMeta {
    id: "HS-RDP-TLS-0204",
    title: "RDP certificate invalid/expired",
    protocol: Protocol::Rdp,
    severity: Severity::High,
    description: "RDP certificate is invalid or expired.",
    impact: "Clients may not be able to validate the server identity.",
    remediation: "Replace the RDP certificate with a valid one.",
    references: &[],
    cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
};

pub const HS_RDP_CONFIG_0205: FindingMeta = FindingMeta {
    id: "HS-RDP-CONFIG-0205",
    title: "RDP weak cipher suites detected",
    protocol: Protocol::Rdp,
    severity: Severity::Medium,
    description: "RDP negotiates weak cipher suites.",
    impact: "Weak ciphers reduce confidentiality.",
    remediation: "Harden RDP TLS cipher suites.",
    references: &[],
    cvss_vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
};

pub const HS_GENERAL_CONFIG_0900: FindingMeta = FindingMeta {
    id: "HS-GENERAL-CONFIG-0900",
    title: "Target normalization ambiguity (multiple resolutions)",
    protocol: Protocol::General,
    severity: Severity::Info,
    description: "Target normalization produced multiple resolutions.",
    impact: "Ambiguity can lead to inconsistent scanning results.",
    remediation: "Use explicit targets or resolve ambiguities.",
    references: &[],
    cvss_vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N",
};

pub const HS_GENERAL_CONFIG_0901: FindingMeta = FindingMeta {
    id: "HS-GENERAL-CONFIG-0901",
    title: "DNS resolution failed",
    protocol: Protocol::General,
    severity: Severity::Info,
    description: "DNS resolution failed for target.",
    impact: "Target may be unreachable.",
    remediation: "Check DNS configuration.",
    references: &[],
    cvss_vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N",
};

pub const HS_GENERAL_CONFIG_0902: FindingMeta = FindingMeta {
    id: "HS-GENERAL-CONFIG-0902",
    title: "Connection timeout (indeterminate posture)",
    protocol: Protocol::General,
    severity: Severity::Info,
    description: "Connection timed out.",
    impact: "Unable to determine posture.",
    remediation: "Check network reachability and firewall rules.",
    references: &[],
    cvss_vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N",
};

pub const HS_GENERAL_CONFIG_0903: FindingMeta = FindingMeta {
    id: "HS-GENERAL-CONFIG-0903",
    title: "Protocol auto-detect mismatch",
    protocol: Protocol::General,
    severity: Severity::Info,
    description: "Protocol auto-detection did not match the expected service.",
    impact: "Results may not reflect the intended protocol.",
    remediation: "Specify the correct protocol explicitly.",
    references: &[],
    cvss_vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N",
};

pub const HS_GENERAL_CONFIG_0904: FindingMeta = FindingMeta {
    id: "HS-GENERAL-CONFIG-0904",
    title: "Policy profile missing/invalid",
    protocol: Protocol::General,
    severity: Severity::Info,
    description: "Policy profile is missing or invalid.",
    impact: "Compliance evaluation could not be completed.",
    remediation: "Provide a valid policy profile.",
    references: &[],
    cvss_vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N",
};

pub const ALL_FINDINGS: &[&FindingMeta] = &[
    &HS_TLS_PROTOCOL_0001,
    &HS_TLS_PROTOCOL_0002,
    &HS_TLS_PROTOCOL_0003,
    &HS_TLS_PROTOCOL_0004,
    &HS_TLS_PROTOCOL_0005,
    &HS_TLS_PROTOCOL_0006,
    &HS_TLS_PROTOCOL_0007,
    &HS_TLS_PROTOCOL_0008,
    &HS_TLS_PROTOCOL_0009,
    &HS_TLS_PROTOCOL_0010,
    &HS_TLS_CIPHER_0001,
    &HS_TLS_CIPHER_0002,
    &HS_TLS_CIPHER_0003,
    &HS_TLS_CIPHER_0004,
    &HS_TLS_CIPHER_0005,
    &HS_TLS_CIPHER_0006,
    &HS_TLS_CIPHER_0007,
    &HS_TLS_CIPHER_0008,
    &HS_TLS_CIPHER_0009,
    &HS_TLS_CIPHER_0010,
    &HS_TLS_CERT_0001,
    &HS_TLS_CERT_0002,
    &HS_TLS_CERT_0003,
    &HS_TLS_CERT_0004,
    &HS_TLS_CERT_0005,
    &HS_TLS_CERT_0006,
    &HS_TLS_CERT_0007,
    &HS_TLS_CERT_0008,
    &HS_TLS_CERT_0009,
    &HS_TLS_CERT_0010,
    &HS_TLS_CERT_0011,
    &HS_TLS_CERT_0012,
    &HS_TLS_SCENARIO_0001,
    &HS_TLS_SCENARIO_0002,
    &HS_TLS_SCENARIO_0003,
    &HS_TLS_SCENARIO_0004,
    &HS_TLS_SCENARIO_0005,
    &HS_TLS_SCENARIO_0006,
    &HS_TLS_SCENARIO_0007,
    &HS_TLS_SCENARIO_0008,
    &HS_TLS_SCENARIO_0009,
    &HS_TLS_SCENARIO_0010,
    &HS_TLS_SCENARIO_0011,
    &HS_TLS_CIPHER_0011,
    &HS_TLS_CIPHER_0012,
    &HS_TLS_EXTENSION_0011,
    &HS_TLS_EXTENSION_0012,
    &HS_TLS_CERT_0013,
    &HS_SSH_KEX_0101,
    &HS_SSH_KEX_0102,
    &HS_SSH_KEX_0103,
    &HS_SSH_HOSTKEY_0104,
    &HS_SSH_HOSTKEY_0105,
    &HS_SSH_CIPHER_0106,
    &HS_SSH_CIPHER_0107,
    &HS_SSH_MAC_0108,
    &HS_SSH_MAC_0109,
    &HS_SSH_CONFIG_0110,
    &HS_RDP_TLS_0201,
    &HS_RDP_TLS_0202,
    &HS_RDP_TLS_0203,
    &HS_RDP_TLS_0204,
    &HS_RDP_CONFIG_0205,
    &HS_GENERAL_CONFIG_0900,
    &HS_GENERAL_CONFIG_0901,
    &HS_GENERAL_CONFIG_0902,
    &HS_GENERAL_CONFIG_0903,
    &HS_GENERAL_CONFIG_0904,
];

use std::collections::HashMap;
use std::sync::OnceLock;

static FINDING_INDEX: OnceLock<HashMap<&'static str, &'static FindingMeta>> = OnceLock::new();

/// O(1) lookup by stable finding ID.
pub fn find_by_id(id: &str) -> Option<&'static FindingMeta> {
    let idx = FINDING_INDEX.get_or_init(|| {
        let mut m = HashMap::with_capacity(ALL_FINDINGS.len());
        for f in ALL_FINDINGS {
            m.insert(f.id, *f);
        }
        m
    });
    idx.get(id).copied()
}
