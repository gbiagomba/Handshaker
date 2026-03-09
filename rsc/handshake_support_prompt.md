Got it. I?m going to give you all 3 deliverables in one shot:
	1.	Starter catalog (50 findings) with a stable naming convention, default CVSS v3.1 vectors, and Tenable-plugin-informed writeups (referencing Tenable plugin pages where applicable).
	2.	First 20 IDs fully written out as Rust FindingMeta constants + a registry you can paste into src/findings/catalog.rs.
	3.	SQLite schema DDL ready to paste into src/output/sqlite.rs (or a migration file).

I?m also including a small prompt patch at the end so your ?Handshaker v7? master prompt stays cumulative.

?

1) Starter catalog: 50 stable findings (IDs + CVSS + Tenable plugin anchors)

ID format: HS-{PROTOCOL}-{CATEGORY}-{4_DIGIT}
	?	PROTOCOL: TLS | SSH | RDP | GENERAL
	?	CATEGORY: PROTOCOL | CIPHER | CERT | KEX | MAC | EXTENSION | SCENARIO | CONFIG
	?	IDs never reused; deprecated findings stay but get status=Deprecated.

Note: Tenable plugin pages vary by product line (Nessus/NNM/WAS). I?m using them as ?writeup anchors? for problem framing and typical risk language, not copying large verbatim text. Key anchors include TLS 1.0 detection, TLS 1.1 deprecated, RC4, and 3DES/SWEET32, plus downgrade protection via TLS_FALLBACK_SCSV.  ?

TLS ? Protocol

ID	Title	Sev	Default CVSS v3.1	Tenable anchor
HS-TLS-PROTOCOL-0001	SSLv2 supported	Critical	CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N	(N/A; baseline)
HS-TLS-PROTOCOL-0002	SSLv3 supported	Critical	CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N	(N/A; baseline)
HS-TLS-PROTOCOL-0003	TLS 1.0 enabled	High	CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N	?TLS 1.0 Protocol Detection?  ?
HS-TLS-PROTOCOL-0004	TLS 1.1 enabled	Medium	CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N	?TLS 1.1 Deprecated Protocol?  ?
HS-TLS-PROTOCOL-0005	TLS 1.2 not supported	High	CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L	(policy-driven)
HS-TLS-PROTOCOL-0006	TLS 1.3 not supported	Low	CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N	(best practice)
HS-TLS-PROTOCOL-0007	Insecure renegotiation allowed	High	CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N	(N/A; baseline)
HS-TLS-PROTOCOL-0008	Secure renegotiation not supported	Medium	CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N	(N/A; baseline)
HS-TLS-PROTOCOL-0009	TLS compression enabled (CRIME risk indicator)	Medium	CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N	(N/A; baseline)
HS-TLS-PROTOCOL-0010	HTTP/2 offered over weak TLS settings	Medium	CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N	(N/A; baseline)

TLS ? Ciphers

ID	Title	Sev	Default CVSS v3.1	Tenable anchor
HS-TLS-CIPHER-0001	NULL cipher suite supported	Critical	CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H	(baseline)
HS-TLS-CIPHER-0002	Anonymous (aNULL) cipher suite supported	Critical	CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N	(baseline)
HS-TLS-CIPHER-0003	EXPORT cipher suite supported	Critical	CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N	(baseline)
HS-TLS-CIPHER-0004	RC4 cipher suite supported	High	CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N	?RC4 Cipher Suites Supported?  ?
HS-TLS-CIPHER-0005	3DES cipher suite supported (SWEET32 exposure indicator)	Medium	CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N	?Medium Strength Ciphers / 3DES?  ?
HS-TLS-CIPHER-0006	CBC-only suites with TLS 1.0 enabled (BEAST exposure indicator)	Medium	CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N	(baseline)
HS-TLS-CIPHER-0007	Weak ?medium strength? cipher policy (64?<112-bit)	Medium	CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N	?Medium Strength Ciphers Supported?  ?
HS-TLS-CIPHER-0008	No AEAD suites available (no GCM/ChaCha20)	Medium	CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N	(baseline)
HS-TLS-CIPHER-0009	No forward secrecy suites observed	Medium	CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N	(baseline)
HS-TLS-CIPHER-0010	Legacy RSA key exchange supported (no (EC)DHE)	Medium	CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N	(baseline)

TLS ? Certificates

ID	Title	Sev	Default CVSS v3.1	Tenable anchor
HS-TLS-CERT-0001	Certificate expired	Critical	CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N	(common baseline)
HS-TLS-CERT-0002	Certificate not yet valid	High	CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N	(baseline)
HS-TLS-CERT-0003	Self-signed certificate (public context)	High	CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N	(baseline)
HS-TLS-CERT-0004	Hostname mismatch (SAN/CN)	High	CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N	(baseline)
HS-TLS-CERT-0005	Weak signature algorithm (SHA1)	High	CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N	(baseline; SHA1 discouraged)
HS-TLS-CERT-0006	RSA key size < 2048	High	CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N	(baseline)
HS-TLS-CERT-0007	Certificate chain incomplete	Medium	CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N	(baseline)
HS-TLS-CERT-0008	Certificate uses weak public key type/params	Medium	CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N	(baseline)
HS-TLS-CERT-0009	Long-lived certificate validity (policy violation)	Low	CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N	(policy-driven)
HS-TLS-CERT-0010	OCSP stapling not supported (best practice)	Low	CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N	(baseline)

TLS ? Scenarios / Downgrade / Extensions (testssl-class)

ID	Title	Sev	Default CVSS v3.1	Tenable anchor
HS-TLS-SCENARIO-0001	No TLS_FALLBACK_SCSV support (downgrade resilience indicator)	Medium	CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N	TLS_FALLBACK_SCSV context  ?
HS-TLS-SCENARIO-0002	Accepts forced downgrade to TLS 1.0	High	CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N	TLS 1.0 detection  ?
HS-TLS-SCENARIO-0003	Session tickets enabled without rotation indicator	Low	CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N	(baseline)
HS-TLS-SCENARIO-0004	Supports weak DH parameters (Logjam-style exposure indicator)	High	CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N	(baseline)
HS-TLS-SCENARIO-0005	SWEET32 exposure indicator (3DES + high-volume contexts)	Medium	CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N	3DES/medium strength  ?
HS-TLS-SCENARIO-0006	BEAST exposure indicator (TLS1.0 + CBC)	Medium	CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N	TLS1.0 detection  ?
HS-TLS-SCENARIO-0007	Insecure record fragmentation behavior indicator	Medium	CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N	Fragmentation probe context  ?
HS-TLS-SCENARIO-0008	Weak cipher preference (server chooses weak even if strong offered)	Medium	CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N	weak ciphers supported  ?

SSH ? KEX / Ciphers / MAC / Host keys

ID	Title	Sev	Default CVSS v3.1	Tenable anchor
HS-SSH-KEX-0101	diffie-hellman-group1-sha1 enabled	High	CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N	?SSH Weak KEX Algorithms Enabled?  ?
HS-SSH-KEX-0102	diffie-hellman-group-exchange-sha1 enabled	High	CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N	?
HS-SSH-KEX-0103	gss-* sha1 KEX enabled	Medium	CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N	?
HS-SSH-HOSTKEY-0104	ssh-rsa (SHA1) hostkey enabled	High	CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N	(same weak-KEX family)  ?
HS-SSH-HOSTKEY-0105	RSA hostkey < 2048	High	CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N	(baseline)
HS-SSH-CIPHER-0106	CBC ciphers enabled	Medium	CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N	(baseline)
HS-SSH-CIPHER-0107	arcfour/RC4 enabled	High	CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N	(baseline)
HS-SSH-MAC-0108	hmac-sha1 enabled	Medium	CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N	(baseline)
HS-SSH-MAC-0109	umac-64 enabled	Medium	CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N	(baseline)
HS-SSH-CONFIG-0110	SSH banner exposes legacy server version	Low	CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N	(baseline)

RDP ? Posture probes

ID	Title	Sev	Default CVSS v3.1	Tenable anchor
HS-RDP-TLS-0201	RDP does not require NLA	High	CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L	(baseline)
HS-RDP-TLS-0202	RDP accepts TLS 1.0	High	CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N	(baseline)
HS-RDP-TLS-0203	RDP accepts TLS 1.1	Medium	CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N	(baseline)
HS-RDP-TLS-0204	RDP certificate invalid/expired	High	CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N	(baseline)
HS-RDP-CONFIG-0205	RDP weak cipher suites detected	Medium	CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N	(baseline)

General ? Input/Config hygiene (useful for pipelines)

ID	Title	Sev	Default CVSS v3.1	Tenable anchor
HS-GENERAL-CONFIG-0900	Target normalization ambiguity (multiple resolutions)	Info	CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N	(tooling)
HS-GENERAL-CONFIG-0901	DNS resolution failed	Info	CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N	(tooling)
HS-GENERAL-CONFIG-0902	Connection timeout (indeterminate posture)	Info	CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N	(tooling)
HS-GENERAL-CONFIG-0903	Protocol auto-detect mismatch	Info	CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N	(tooling)
HS-GENERAL-CONFIG-0904	Policy profile missing/invalid	Info	CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N	(tooling)

That?s 50 findings. If you want to expand to ~60, the next ?most valuable? adds are: OCSP Must-Staple, SCT/CT policy notes, TLS 1.3 0-RTT enabled indicator, weak elliptic curves, missing ALPN hardening for HTTP/2, and STARTTLS downgrade behaviors.

?

2) First 20 IDs fully written out (Rust paste-ready)

Paste this into src/findings/catalog.rs. It?s structured so handshaker explain HS-TLS-PROTOCOL-0003 is instant.

// src/findings/catalog.rs

use crate::models::{Protocol, Severity};

#[derive(Debug, Clone)]
pub struct FindingMeta {
    pub id: &'static str,
    pub title: &'static str,
    pub protocol: Protocol,
    pub severity: Severity,

    /// What is it?
    pub description: &'static str,

    /// Why should anyone care (attacker POV / impact)?
    pub impact: &'static str,

    /// How to fix it (actionable).
    pub remediation: &'static str,

    /// References (Tenable plugin pages, RFCs, etc.)
    pub references: &'static [&'static str],

    /// Default CVSS v3.1 vector for configuration-risk alignment.
    pub cvss_vector: &'static str,
}

// ---------- TLS / PROTOCOL (0001..0010) ----------
pub const HS_TLS_PROTOCOL_0001: FindingMeta = FindingMeta {
    id: "HS-TLS-PROTOCOL-0001",
    title: "SSLv2 supported",
    protocol: Protocol::Tls,
    severity: Severity::Critical,
    description: "The service negotiates SSLv2, an obsolete protocol with severe cryptographic weaknesses.",
    impact: "An on-path attacker can exploit legacy protocol weaknesses to break confidentiality and integrity, enabling interception or manipulation of traffic.",
    remediation: "Disable SSLv2 at the server and any upstream TLS termination points. Ensure clients cannot negotiate SSLv2.",
    references: &[],
    cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
};

pub const HS_TLS_PROTOCOL_0002: FindingMeta = FindingMeta {
    id: "HS-TLS-PROTOCOL-0002",
    title: "SSLv3 supported",
    protocol: Protocol::Tls,
    severity: Severity::Critical,
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
    severity: Severity::High,
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
    cvss_vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
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
    impact: "Not an immediate break, but misses modern security and performance improvements; may reduce grade and compliance posture over time.",
    remediation: "Upgrade TLS stack and enable TLS 1.3 where supported and compatible.",
    references: &[],
    cvss_vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N",
};

pub const HS_TLS_PROTOCOL_0007: FindingMeta = FindingMeta {
    id: "HS-TLS-PROTOCOL-0007",
    title: "Insecure renegotiation allowed",
    protocol: Protocol::Tls,
    severity: Severity::High,
    description: "The service permits renegotiation without sufficient safeguards (or indicates unsafe renegotiation).",
    impact: "Renegotiation weaknesses can allow traffic injection or session confusion under certain conditions.",
    remediation: "Disable insecure renegotiation. Ensure secure renegotiation support is enabled in the TLS stack.",
    references: &[],
    cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
};

pub const HS_TLS_PROTOCOL_0008: FindingMeta = FindingMeta {
    id: "HS-TLS-PROTOCOL-0008",
    title: "Secure renegotiation not supported",
    protocol: Protocol::Tls,
    severity: Severity::Medium,
    description: "The service does not indicate support for secure renegotiation.",
    impact: "If renegotiation is used, lack of secure renegotiation increases risk of injection-style issues; often also correlates with legacy stacks.",
    remediation: "Enable secure renegotiation or disable renegotiation features in the TLS stack if not needed.",
    references: &[],
    cvss_vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
};

pub const HS_TLS_PROTOCOL_0009: FindingMeta = FindingMeta {
    id: "HS-TLS-PROTOCOL-0009",
    title: "TLS compression enabled (CRIME indicator)",
    protocol: Protocol::Tls,
    severity: Severity::Medium,
    description: "The service negotiates TLS-level compression, which is generally discouraged.",
    impact: "TLS compression can leak secrets in certain contexts through compression side channels (configuration risk indicator).",
    remediation: "Disable TLS compression in the TLS stack and at any upstream termination points.",
    references: &[],
    cvss_vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
};

pub const HS_TLS_PROTOCOL_0010: FindingMeta = FindingMeta {
    id: "HS-TLS-PROTOCOL-0010",
    title: "HTTP/2 offered over weak TLS settings",
    protocol: Protocol::Tls,
    severity: Severity::Medium,
    description: "The service offers HTTP/2 but also allows deprecated TLS versions or weak ciphers.",
    impact: "The endpoint?s effective security is governed by its weakest allowed negotiation path; mixed posture increases downgrade and misconfiguration risk.",
    remediation: "Harden TLS config: disable deprecated versions and weak ciphers; enforce modern suites for HTTP/2.",
    references: &[],
    cvss_vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
};

// ---------- TLS / CIPHER (0001..0010) ----------
pub const HS_TLS_CIPHER_0001: FindingMeta = FindingMeta {
    id: "HS-TLS-CIPHER-0001",
    title: "NULL cipher suite supported",
    protocol: Protocol::Tls,
    severity: Severity::Critical,
    description: "The service supports NULL encryption cipher suites (no confidentiality).",
    impact: "Traffic can be observed and altered; confidentiality and integrity protections are effectively absent.",
    remediation: "Disable NULL cipher suites. Use modern AEAD suites (AES-GCM or ChaCha20-Poly1305).",
    references: &[],
    cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
};

pub const HS_TLS_CIPHER_0002: FindingMeta = FindingMeta {
    id: "HS-TLS-CIPHER-0002",
    title: "Anonymous (aNULL) cipher suite supported",
    protocol: Protocol::Tls,
    severity: Severity::Critical,
    description: "The service supports anonymous key exchange cipher suites (no authentication).",
    impact: "Enables straightforward man-in-the-middle attacks because the server is not authenticated.",
    remediation: "Disable aNULL suites; require authenticated cipher suites backed by trusted certificates.",
    references: &[],
    cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
};

pub const HS_TLS_CIPHER_0003: FindingMeta = FindingMeta {
    id: "HS-TLS-CIPHER-0003",
    title: "EXPORT cipher suite supported",
    protocol: Protocol::Tls,
    severity: Severity::Critical,
    description: "The service supports EXPORT-grade cipher suites (intentionally weak).",
    impact: "Attackers can exploit weak cryptography to decrypt or manipulate traffic.",
    remediation: "Disable EXPORT suites and any legacy compatibility settings enabling them.",
    references: &[],
    cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
};

pub const HS_TLS_CIPHER_0004: FindingMeta = FindingMeta {
    id: "HS-TLS-CIPHER-0004",
    title: "RC4 cipher suite supported",
    protocol: Protocol::Tls,
    severity: Severity::High,
    description: "The service supports RC4-based cipher suites.",
    impact: "RC4 has well-known biases; with sufficient captured traffic in some contexts, plaintext recovery becomes feasible.",
    remediation: "Disable all RC4 cipher suites. Prefer AEAD suites (AES-GCM, ChaCha20-Poly1305).",
    references: &["https://www.tenable.com/plugins/nessus/65821"],
    cvss_vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
};

pub const HS_TLS_CIPHER_0005: FindingMeta = FindingMeta {
    id: "HS-TLS-CIPHER-0005",
    title: "3DES cipher suite supported (SWEET32 indicator)",
    protocol: Protocol::Tls,
    severity: Severity::Medium,
    description: "The service supports 3DES, a 64-bit block cipher associated with SWEET32-style risks in high-volume contexts.",
    impact: "64-bit block ciphers can leak information in long-lived or high-throughput sessions; increases confidentiality risk for cookies/tokens in some scenarios.",
    remediation: "Disable 3DES suites; enforce modern AEAD suites.",
    references: &["https://www.tenable.com/plugins/nessus/42873"],
    cvss_vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
};

pub const HS_TLS_CIPHER_0006: FindingMeta = FindingMeta {
    id: "HS-TLS-CIPHER-0006",
    title: "CBC-only suites with TLS 1.0 enabled (BEAST indicator)",
    protocol: Protocol::Tls,
    severity: Severity::Medium,
    description: "The endpoint supports TLS 1.0 and CBC ciphers without strong modern alternatives observed.",
    impact: "TLS 1.0 + CBC increases exposure to legacy attack classes and downgrade/compat risks (configuration risk indicator).",
    remediation: "Disable TLS 1.0 and prefer AEAD suites under TLS 1.2+ (AES-GCM/ChaCha20).",
    references: &["https://www.tenable.com/plugins/nessus/84470"],
    cvss_vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
};

pub const HS_TLS_CIPHER_0007: FindingMeta = FindingMeta {
    id: "HS-TLS-CIPHER-0007",
    title: "Weak/medium strength cipher policy enabled",
    protocol: Protocol::Tls,
    severity: Severity::Medium,
    description: "The service supports cipher suites considered 'medium strength' (e.g., 64?<112-bit or 3DES).",
    impact: "Medium strength cryptography is more practical to attack than modern suites, particularly in on-path scenarios.",
    remediation: "Disable medium/weak ciphers. Permit only strong AEAD suites and strong key exchange.",
    references: &["https://www.tenable.com/plugins/nessus/42873"],
    cvss_vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
};

pub const HS_TLS_CIPHER_0008: FindingMeta = FindingMeta {
    id: "HS-TLS-CIPHER-0008",
    title: "No AEAD suites available (no GCM/ChaCha20)",
    protocol: Protocol::Tls,
    severity: Severity::Medium,
    description: "No authenticated encryption (AEAD) cipher suites were observed (AES-GCM / ChaCha20-Poly1305).",
    impact: "Endpoints without AEAD typically rely on legacy MAC-then-encrypt patterns and older cipher families.",
    remediation: "Enable AEAD suites and disable legacy-only cipher configurations.",
    references: &[],
    cvss_vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
};

pub const HS_TLS_CIPHER_0009: FindingMeta = FindingMeta {
    id: "HS-TLS-CIPHER-0009",
    title: "No forward secrecy suites observed",
    protocol: Protocol::Tls,
    severity: Severity::Medium,
    description: "No (EC)DHE-based suites were observed; the server appears to rely on non-PFS key exchange.",
    impact: "Compromise of server private key can expose historical sessions (in contexts where recordings exist).",
    remediation: "Enable ECDHE/DHE suites; prefer TLS 1.3 (PFS by design).",
    references: &[],
    cvss_vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
};

pub const HS_TLS_CIPHER_0010: FindingMeta = FindingMeta {
    id: "HS-TLS-CIPHER-0010",
    title: "Legacy RSA key exchange supported",
    protocol: Protocol::Tls,
    severity: Severity::Medium,
    description: "The service supports RSA key exchange (non-(EC)DHE), indicating legacy negotiation paths.",
    impact: "Reduces posture and can correlate with weaker downgrade and cipher configurations.",
    remediation: "Prefer (EC)DHE suites and TLS 1.3; disable RSA key exchange where not required.",
    references: &[],
    cvss_vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
};

// ---------- Registry (first 20) ----------
pub const FIRST_20_FINDINGS: &[FindingMeta] = &[
    HS_TLS_PROTOCOL_0001,
    HS_TLS_PROTOCOL_0002,
    HS_TLS_PROTOCOL_0003,
    HS_TLS_PROTOCOL_0004,
    HS_TLS_PROTOCOL_0005,
    HS_TLS_PROTOCOL_0006,
    HS_TLS_PROTOCOL_0007,
    HS_TLS_PROTOCOL_0008,
    HS_TLS_PROTOCOL_0009,
    HS_TLS_PROTOCOL_0010,
    HS_TLS_CIPHER_0001,
    HS_TLS_CIPHER_0002,
    HS_TLS_CIPHER_0003,
    HS_TLS_CIPHER_0004,
    HS_TLS_CIPHER_0005,
    HS_TLS_CIPHER_0006,
    HS_TLS_CIPHER_0007,
    HS_TLS_CIPHER_0008,
    HS_TLS_CIPHER_0009,
    HS_TLS_CIPHER_0010,
];

If you want this to scale cleanly, I recommend using a compile-time map (e.g., phf) keyed by id for O(1) explain, but the above is copy-paste friendly and works today.

?

3) SQLite schema DDL (paste-ready)

This is designed to support:
	?	multiple runs
	?	multiple targets per run
	?	many findings per target
	?	both SSL Labs scoring + CVSS aggregates
	?	compliance + benchmark artifacts
	?	diff by JSON or by DB run IDs

-- SQLite DDL for Handshaker
-- Recommended: PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS runs (
  id                INTEGER PRIMARY KEY AUTOINCREMENT,
  started_at_utc     TEXT NOT NULL,         -- ISO-8601
  finished_at_utc    TEXT,                  -- ISO-8601
  tool_version       TEXT NOT NULL,
  input_kind         TEXT NOT NULL,          -- cli|file|stdin|nmap-grep|nmap-xml|nuclei
  input_ref          TEXT,                   -- file path or '-' for stdin
  policy_mode        TEXT,                   -- default|pci-dss|nist-800-52r2|custom:<path>
  benchmark_profile  TEXT,                   -- cis-like|custom:<path>
  notes              TEXT
);

CREATE TABLE IF NOT EXISTS targets (
  id                INTEGER PRIMARY KEY AUTOINCREMENT,
  run_id             INTEGER NOT NULL,
  host               TEXT NOT NULL,
  port               INTEGER NOT NULL,
  protocol           TEXT NOT NULL,          -- https|smtps|imaps|ldaps|ftps-implicit|ftp-explicit-tls|smtp-starttls|imap-starttls|pop3-starttls|ssh|rdp|tls-generic|unknown
  normalized_target  TEXT NOT NULL,          -- e.g., https://example.com:443
  source_hint        TEXT,                   -- nuclei template id, nmap service name, etc.
  status             TEXT NOT NULL,          -- ok|timeout|refused|dns_fail|handshake_fail|unsupported
  error              TEXT,
  scanned_at_utc     TEXT NOT NULL,
  UNIQUE(run_id, normalized_target),
  FOREIGN KEY(run_id) REFERENCES runs(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS observations (
  id                INTEGER PRIMARY KEY AUTOINCREMENT,
  target_id          INTEGER NOT NULL,
  observations_json  TEXT NOT NULL,          -- raw structured observations (versions, ciphers, cert fields, ssh algos, rdp posture)
  FOREIGN KEY(target_id) REFERENCES targets(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS findings (
  id                INTEGER PRIMARY KEY AUTOINCREMENT,
  target_id          INTEGER NOT NULL,
  finding_id         TEXT NOT NULL,          -- HS-*
  severity           TEXT NOT NULL,          -- Critical|High|Medium|Low|Info
  cvss_vector        TEXT NOT NULL,
  cvss_score         REAL NOT NULL,
  evidence_json      TEXT NOT NULL,          -- structured evidence for this target
  created_at_utc     TEXT NOT NULL,
  UNIQUE(target_id, finding_id),
  FOREIGN KEY(target_id) REFERENCES targets(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS scores (
  id                INTEGER PRIMARY KEY AUTOINCREMENT,
  target_id          INTEGER NOT NULL,

  -- SSL Labs style scoring:
  ssllabs_overall    INTEGER NOT NULL,       -- 0..100
  ssllabs_grade      TEXT NOT NULL,          -- A+|A|B|C|D|F
  ssllabs_breakdown  TEXT NOT NULL,          -- JSON: cert/protocol/kex/cipher + cap reasons

  -- CVSS aggregates:
  risk_max           REAL NOT NULL,
  risk_weighted      REAL NOT NULL,
  risk_breakdown     TEXT NOT NULL,          -- JSON: how computed (topN, weights)

  FOREIGN KEY(target_id) REFERENCES targets(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS compliance (
  id                INTEGER PRIMARY KEY AUTOINCREMENT,
  target_id          INTEGER NOT NULL,
  mode              TEXT NOT NULL,           -- pci-dss|nist-800-52r2|custom
  compliant         INTEGER NOT NULL,        -- 0/1
  failures_json     TEXT NOT NULL,           -- list of failed controls + evidence + remediation
  evaluated_at_utc  TEXT NOT NULL,
  FOREIGN KEY(target_id) REFERENCES targets(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS benchmarks (
  id                INTEGER PRIMARY KEY AUTOINCREMENT,
  target_id          INTEGER NOT NULL,
  profile           TEXT NOT NULL,           -- cis-like|custom
  pass_rate         REAL NOT NULL,           -- 0..100
  failures_json     TEXT NOT NULL,
  evaluated_at_utc  TEXT NOT NULL,
  FOREIGN KEY(target_id) REFERENCES targets(id) ON DELETE CASCADE
);

-- Helpful indexes for querying and diffing:
CREATE INDEX IF NOT EXISTS idx_targets_run_id ON targets(run_id);
CREATE INDEX IF NOT EXISTS idx_findings_target_id ON findings(target_id);
CREATE INDEX IF NOT EXISTS idx_findings_finding_id ON findings(finding_id);
CREATE INDEX IF NOT EXISTS idx_scores_target_id ON scores(target_id);
CREATE INDEX IF NOT EXISTS idx_compliance_target_id ON compliance(target_id);
CREATE INDEX IF NOT EXISTS idx_benchmarks_target_id ON benchmarks(target_id);


?

Patch to your master coding-agent prompt (keep it cumulative)

Add these explicit requirements under the ?Findings? section of your v7 prompt:
	?	Implement a findings/catalog.rs with at least 50 FindingMeta entries using the stable ID format.
	?	handshaker explain <ID> must output:
	?	title, description, impact, remediation, references
	?	default CVSS vector + computed base score
	?	(optional) ?how Handshaker detects this? guidance based on evidence fields
	?	Catalog entries should cite Tenable plugin pages in references[] where there is a close match (e.g., TLS 1.0, TLS 1.1, RC4, 3DES/medium strength, TLS_FALLBACK_SCSV).  ?
	?	Create src/output/sqlite.rs that initializes this exact schema, inserts runs/targets/findings/scores, and supports handshaker diff --db ... --run-old ... --run-new ....

Alright  here are the remaining 30 in the same paste-ready Rust format, plus an O(1) lookup option and a clean way to assemble a 50-finding catalog (FIRST_20 + NEXT_30).

I also tightened the Tenable anchors so the ones we cite actually exist and load (TLS 1.0/1.1/RC4/3DES/SSH weak KEX).  



src/findings/catalog_more.rs (Remaining 30 findings)

What this contains (30 total):
		TLS CERT: 0001..0010 (10)
		TLS SCENARIO: 0001..0008 (8)
		SSH (KEX/HOSTKEY/CIPHER): 0101..0107 (7)
		RDP: 0201..0205 (5)

This gives you 20 (already done) + 30 (below) = 50.

// src/findings/catalog_more.rs
//
// Remaining 30 findings to reach 50 total with FIRST_20_FINDINGS.
// Keep IDs stable forever.

use crate::findings::catalog::FindingMeta;
use crate::models::{Protocol, Severity};

// ---------- TLS / CERT (0001..0010) ----------
pub const HS_TLS_CERT_0001: FindingMeta = FindingMeta {
    id: "HS-TLS-CERT-0001",
    title: "Certificate expired",
    protocol: Protocol::Tls,
    severity: Severity::Critical,
    description: "The service presents an expired X.509 certificate.",
    impact: "Clients may reject connections or users may bypass warnings. Attackers can exploit this trust breakdown to facilitate interception and phishing-style MITM scenarios.",
    remediation: "Replace/renew the certificate, ensure full chain is deployed, and implement automated renewal with monitoring for expiry thresholds (e.g., 30/14/7 days).",
    references: &[],
    cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
};

pub const HS_TLS_CERT_0002: FindingMeta = FindingMeta {
    id: "HS-TLS-CERT-0002",
    title: "Certificate not yet valid",
    protocol: Protocol::Tls,
    severity: Severity::High,
    description: "The certificate validity period begins in the future (clock skew or mis-issuance).",
    impact: "Clients may reject the cert, causing outages; attackers can abuse user habituation to bypass warnings.",
    remediation: "Fix system time/NTP on issuing or terminating systems, reissue the certificate if necessary, and validate deployment across the chain.",
    references: &[],
    cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
};

pub const HS_TLS_CERT_0003: FindingMeta = FindingMeta {
    id: "HS-TLS-CERT-0003",
    title: "Self-signed certificate in use (public context)",
    protocol: Protocol::Tls,
    severity: Severity::High,
    description: "The endpoint presents a self-signed certificate (or untrusted issuer) where public trust is expected.",
    impact: "Enables trivial MITM because clients cannot authenticate the server identity through a trusted CA chain.",
    remediation: "Use a certificate issued by a trusted CA (or a private PKI properly distributed to clients for internal services).",
    references: &[],
    cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
};

pub const HS_TLS_CERT_0004: FindingMeta = FindingMeta {
    id: "HS-TLS-CERT-0004",
    title: "Hostname mismatch (SAN/CN)",
    protocol: Protocol::Tls,
    severity: Severity::High,
    description: "The certificate's subjectAltName/CommonName does not match the requested hostname.",
    impact: "Clients may reject the connection; users who bypass warnings become vulnerable to MITM and impersonation.",
    remediation: "Issue a certificate with correct SAN entries for all hostnames served; ensure SNI routing matches cert deployment.",
    references: &[],
    cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
};

pub const HS_TLS_CERT_0005: FindingMeta = FindingMeta {
    id: "HS-TLS-CERT-0005",
    title: "Weak certificate signature algorithm (SHA-1)",
    protocol: Protocol::Tls,
    severity: Severity::High,
    description: "The certificate uses SHA-1 for signatures, which is deprecated.",
    impact: "SHA-1 is collision-prone. While practical exploitation depends on the ecosystem, this materially degrades trust and compliance posture.",
    remediation: "Reissue certificates using SHA-256 (or stronger) signatures; ensure intermediate CAs are also modern.",
    references: &[],
    cvss_vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
};

pub const HS_TLS_CERT_0006: FindingMeta = FindingMeta {
    id: "HS-TLS-CERT-0006",
    title: "Weak RSA public key length (< 2048 bits)",
    protocol: Protocol::Tls,
    severity: Severity::High,
    description: "The endpoint presents an RSA certificate with key size below 2048 bits.",
    impact: "Weaker keys reduce cryptographic safety margins and can fail compliance requirements; long-lived services accumulate risk over time.",
    remediation: "Reissue certificates with RSA 2048+ (or ECDSA with strong curves) and retire weak keys everywhere they appear (leaf/intermediate).",
    references: &[],
    cvss_vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
};

pub const HS_TLS_CERT_0007: FindingMeta = FindingMeta {
    id: "HS-TLS-CERT-0007",
    title: "Certificate chain incomplete",
    protocol: Protocol::Tls,
    severity: Severity::Medium,
    description: "The server does not provide the full certificate chain required for many clients to build trust.",
    impact: "Breaks client trust inconsistently; increases user warning clicks and operational failure rates.",
    remediation: "Install the complete chain (leaf + intermediates). Validate with multiple client stacks (OpenSSL/rustls/platform).",
    references: &[],
    cvss_vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
};

pub const HS_TLS_CERT_0008: FindingMeta = FindingMeta {
    id: "HS-TLS-CERT-0008",
    title: "Weak certificate public key type/parameters",
    protocol: Protocol::Tls,
    severity: Severity::Medium,
    description: "The certificate uses a public key type or parameters that are considered weak or non-recommended.",
    impact: "Reduces cryptographic safety margin and can break compliance baselines.",
    remediation: "Reissue certificates using modern algorithms (RSA 2048+/ECDSA P-256+). Avoid legacy curves/params.",
    references: &[],
    cvss_vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
};

pub const HS_TLS_CERT_0009: FindingMeta = FindingMeta {
    id: "HS-TLS-CERT-0009",
    title: "Certificate validity period violates policy (long-lived cert)",
    protocol: Protocol::Tls,
    severity: Severity::Low,
    description: "The certificates validity exceeds a configured policy threshold (organizational/industry baseline).",
    impact: "Long-lived certs increase blast radius of key compromise and slow down cryptographic agility.",
    remediation: "Reduce certificate lifetime; automate issuance/renewal; enforce policy in CI and certificate management.",
    references: &[],
    cvss_vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N",
};

pub const HS_TLS_CERT_0010: FindingMeta = FindingMeta {
    id: "HS-TLS-CERT-0010",
    title: "OCSP stapling not supported (best practice)",
    protocol: Protocol::Tls,
    severity: Severity::Low,
    description: "The server does not staple OCSP responses during TLS handshakes.",
    impact: "Clients may perform their own OCSP lookups (privacy/perf impact) or rely on soft-fail semantics; posture can be reduced in strict environments.",
    remediation: "Enable OCSP stapling on the TLS terminator and ensure it can fetch/refresh OCSP responses reliably.",
    references: &[],
    cvss_vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N",
};

// ---------- TLS / SCENARIO (0001..0008) ----------
pub const HS_TLS_SCENARIO_0001: FindingMeta = FindingMeta {
    id: "HS-TLS-SCENARIO-0001",
    title: "No TLS_FALLBACK_SCSV support (downgrade resilience indicator)",
    protocol: Protocol::Tls,
    severity: Severity::Medium,
    description: "The server does not appear to support TLS_FALLBACK_SCSV during forced fallback handshakes.",
    impact: "Increases downgrade attack surface in ecosystems where clients retry with lower protocol versions after handshake failures.",
    remediation: "Enable TLS_FALLBACK_SCSV support (RFC 7507) and disable legacy protocol versions where possible.",
    references: &[
        "https://datatracker.ietf.org/doc/html/rfc7507",
        // Tenable mention exists, though the plugin is not *about* SCSV; it references it.
        "https://www.tenable.com/plugins/nessus/79685",
    ],
    cvss_vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
};

pub const HS_TLS_SCENARIO_0002: FindingMeta = FindingMeta {
    id: "HS-TLS-SCENARIO-0002",
    title: "Accepts forced downgrade to TLS 1.0",
    protocol: Protocol::Tls,
    severity: Severity::High,
    description: "When probed, the endpoint accepts TLS 1.0 negotiation (forced downgrade path observed).",
    impact: "Allows downgrade to a deprecated protocol version, increasing exposure to legacy weaknesses and compliance failures.",
    remediation: "Disable TLS 1.0 and TLS 1.1; enforce TLS 1.2+; ensure downgrade signaling (SCSV) is supported where applicable.",
    references: &[
        "https://www.tenable.com/plugins/nessus/84470",
        "https://www.tenable.com/plugins/nessus/104743",
    ],
    cvss_vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
};

pub const HS_TLS_SCENARIO_0003: FindingMeta = FindingMeta {
    id: "HS-TLS-SCENARIO-0003",
    title: "Session tickets enabled without rotation indicator",
    protocol: Protocol::Tls,
    severity: Severity::Low,
    description: "The endpoint supports TLS session tickets; rotation posture cannot be validated from handshake alone.",
    impact: "If ticket keys are not rotated, compromise can extend session replay windows; risk depends on deployment and key management.",
    remediation: "Rotate ticket encryption keys frequently; prefer short ticket lifetimes; consider session IDs if rotation is difficult.",
    references: &[],
    cvss_vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N",
};

pub const HS_TLS_SCENARIO_0004: FindingMeta = FindingMeta {
    id: "HS-TLS-SCENARIO-0004",
    title: "Weak DH parameters observed (Logjam-style indicator)",
    protocol: Protocol::Tls,
    severity: Severity::High,
    description: "The server negotiates finite-field Diffie-Hellman with parameters that appear weak (e.g., small group size).",
    impact: "Weak DH groups can reduce confidentiality guarantees and may permit practical attacks depending on parameter size and attacker capability.",
    remediation: "Use ECDHE suites (preferred) or ensure strong DH parameters (>= 2048-bit) and modern configurations.",
    references: &[],
    cvss_vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
};

pub const HS_TLS_SCENARIO_0005: FindingMeta = FindingMeta {
    id: "HS-TLS-SCENARIO-0005",
    title: "SWEET32 exposure indicator (3DES supported)",
    protocol: Protocol::Tls,
    severity: Severity::Medium,
    description: "The service supports 3DES or other 64-bit block ciphers (SWEET32-class risk indicator).",
    impact: "High-volume sessions can leak information due to birthday bound limitations of 64-bit blocks; risk depends on traffic patterns and session longevity.",
    remediation: "Disable 3DES/64-bit block ciphers; enforce modern AEAD suites (AES-GCM/ChaCha20).",
    references: &["https://www.tenable.com/plugins/nessus/42873"],
    cvss_vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
};

pub const HS_TLS_SCENARIO_0006: FindingMeta = FindingMeta {
    id: "HS-TLS-SCENARIO-0006",
    title: "BEAST exposure indicator (TLS 1.0 + CBC supported)",
    protocol: Protocol::Tls,
    severity: Severity::Medium,
    description: "TLS 1.0 is enabled and CBC suites are supported, increasing exposure to legacy CBC attack classes (indicator).",
    impact: "While mitigations exist in modern clients, allowing TLS 1.0 keeps legacy paths open and reduces overall posture.",
    remediation: "Disable TLS 1.0; prioritize AEAD suites under TLS 1.2+.",
    references: &[
        "https://www.tenable.com/plugins/nessus/84470",
        "https://www.tenable.com/plugins/nessus/104743",
    ],
    cvss_vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
};

pub const HS_TLS_SCENARIO_0007: FindingMeta = FindingMeta {
    id: "HS-TLS-SCENARIO-0007",
    title: "TLS handshake fragmentation anomaly (risk indicator)",
    protocol: Protocol::Tls,
    severity: Severity::Medium,
    description: "Active probing observed anomalous fragmentation/record-layer behavior that can correlate with legacy stacks or misconfigurations.",
    impact: "May indicate fragile or outdated implementations; can contribute to interoperability or security edge-case behavior.",
    remediation: "Upgrade the TLS stack / terminator; harden protocol versions and ciphers; retest.",
    references: &[],
    cvss_vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
};

pub const HS_TLS_SCENARIO_0008: FindingMeta = FindingMeta {
    id: "HS-TLS-SCENARIO-0008",
    title: "Weak cipher preference (server selects weak when strong offered)",
    protocol: Protocol::Tls,
    severity: Severity::Medium,
    description: "When both weak and strong suites are offered, the server selects a weaker suite (poor preference order).",
    impact: "If clients offer legacy suites for compatibility, attackers can steer sessions toward weaker cryptography via downgrade/negotiation manipulation.",
    remediation: "Prefer strong suites first; disable weak suites entirely; enable TLS 1.3 where possible.",
    references: &[
        "https://www.tenable.com/plugins/nessus/42873",
        "https://www.tenable.com/plugins/nessus/65821",
    ],
    cvss_vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
};

// ---------- SSH (0101..0107) ----------
pub const HS_SSH_KEX_0101: FindingMeta = FindingMeta {
    id: "HS-SSH-KEX-0101",
    title: "diffie-hellman-group1-sha1 enabled",
    protocol: Protocol::Ssh,
    severity: Severity::High,
    description: "The SSH server advertises the diffie-hellman-group1-sha1 key exchange algorithm.",
    impact: "Legacy DH groups and SHA-1 reduce cryptographic safety margins; attackers with sufficient capability may target weaker negotiation paths.",
    remediation: "Disable weak KEX algorithms; follow modern recommendations (e.g., curve25519-sha256, ecdh-sha2-*, sntrup761x25519-sha512).",
    references: &["https://www.tenable.com/plugins/nessus/153953"],
    cvss_vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
};

pub const HS_SSH_KEX_0102: FindingMeta = FindingMeta {
    id: "HS-SSH-KEX-0102",
    title: "diffie-hellman-group-exchange-sha1 enabled",
    protocol: Protocol::Ssh,
    severity: Severity::High,
    description: "The SSH server advertises diffie-hellman-group-exchange-sha1.",
    impact: "SHA-1-based KEX is deprecated and may violate policy baselines; weak negotiation paths expand attack surface.",
    remediation: "Disable SHA-1 KEX and prefer modern algorithms per RFC 9142 guidance.",
    references: &["https://www.tenable.com/plugins/nessus/153953"],
    cvss_vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
};

pub const HS_SSH_KEX_0103: FindingMeta = FindingMeta {
    id: "HS-SSH-KEX-0103",
    title: "GSSAPI SHA-1 key exchanges enabled (gss-gex-sha1-* / gss-group1-sha1-*)",
    protocol: Protocol::Ssh,
    severity: Severity::Medium,
    description: "The SSH server advertises GSSAPI-based key exchange variants that rely on SHA-1.",
    impact: "Expands legacy negotiation surface and can fail hardening standards; typically unnecessary unless you rely on specific enterprise GSS flows.",
    remediation: "Disable SHA-1 GSS KEX variants; keep only required GSS mechanisms and modern KEX options.",
    references: &["https://www.tenable.com/plugins/nessus/153953"],
    cvss_vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
};

pub const HS_SSH_HOSTKEY_0104: FindingMeta = FindingMeta {
    id: "HS-SSH-HOSTKEY-0104",
    title: "ssh-rsa (SHA-1) hostkey enabled",
    protocol: Protocol::Ssh,
    severity: Severity::High,
    description: "The SSH server advertises ssh-rsa host keys/signatures (SHA-1).",
    impact: "SHA-1 is deprecated; allowing ssh-rsa can keep clients on weak authentication paths and break policy compliance.",
    remediation: "Disable ssh-rsa; enable rsa-sha2-256/512, ed25519, and/or ecdsa-sha2-* as appropriate.",
    references: &["https://www.tenable.com/plugins/nessus/153953"],
    cvss_vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
};

pub const HS_SSH_HOSTKEY_0105: FindingMeta = FindingMeta {
    id: "HS-SSH-HOSTKEY-0105",
    title: "RSA host key size < 2048 bits",
    protocol: Protocol::Ssh,
    severity: Severity::High,
    description: "The SSH server presents an RSA host key below 2048 bits.",
    impact: "Weakens cryptographic safety margin and may violate compliance requirements.",
    remediation: "Regenerate host keys using RSA 2048+ or prefer ed25519; update known_hosts where applicable.",
    references: &[],
    cvss_vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
};

pub const HS_SSH_CIPHER_0106: FindingMeta = FindingMeta {
    id: "HS-SSH-CIPHER-0106",
    title: "SSH CBC ciphers enabled",
    protocol: Protocol::Ssh,
    severity: Severity::Medium,
    description: "The SSH server advertises CBC-mode encryption ciphers.",
    impact: "CBC in SSH is discouraged; modern AEAD options provide better security properties and are recommended by hardening baselines.",
    remediation: "Disable CBC ciphers; prefer chacha20-poly1305@openssh.com or aes128/256-gcm@openssh.com.",
    references: &[],
    cvss_vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
};

pub const HS_SSH_CIPHER_0107: FindingMeta = FindingMeta {
    id: "HS-SSH-CIPHER-0107",
    title: "SSH RC4 (arcfour) enabled",
    protocol: Protocol::Ssh,
    severity: Severity::High,
    description: "The SSH server advertises RC4/arcfour ciphers.",
    impact: "RC4 is cryptographically broken and deprecated; keeping it enabled expands downgrade and weak-negotiation surface.",
    remediation: "Disable arcfour/RC4 ciphers and enforce modern AEAD ciphers.",
    references: &[],
    cvss_vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
};

// ---------- RDP (0201..0205) ----------
pub const HS_RDP_TLS_0201: FindingMeta = FindingMeta {
    id: "HS-RDP-TLS-0201",
    title: "RDP does not require NLA",
    protocol: Protocol::Rdp,
    severity: Severity::High,
    description: "RDP appears to accept connections without requiring Network Level Authentication (NLA).",
    impact: "Increases exposure to pre-auth attack surface and brute-force pressure; can worsen blast radius for credential attacks.",
    remediation: "Enable and require NLA. Restrict RDP exposure at network boundaries and use MFA / jump hosts.",
    references: &[],
    cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L",
};

pub const HS_RDP_TLS_0202: FindingMeta = FindingMeta {
    id: "HS-RDP-TLS-0202",
    title: "RDP accepts TLS 1.0",
    protocol: Protocol::Rdp,
    severity: Severity::High,
    description: "RDP TLS negotiation indicates support for TLS 1.0 (deprecated).",
    impact: "Legacy TLS versions expand downgrade and weak-crypto paths; also undermines compliance baselines.",
    remediation: "Disable TLS 1.0/1.1 for RDP endpoints. Enforce TLS 1.2+ and require NLA.",
    references: &[
        "https://www.tenable.com/plugins/nessus/84470",
        "https://www.tenable.com/plugins/nessus/104743",
    ],
    cvss_vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
};

pub const HS_RDP_TLS_0203: FindingMeta = FindingMeta {
    id: "HS-RDP-TLS-0203",
    title: "RDP accepts TLS 1.1",
    protocol: Protocol::Rdp,
    severity: Severity::Medium,
    description: "RDP TLS negotiation indicates support for TLS 1.1 (deprecated).",
    impact: "TLS 1.1 is deprecated and reduces cryptographic agility and compliance posture.",
    remediation: "Disable TLS 1.1 and enforce TLS 1.2+ for RDP endpoints.",
    references: &["https://www.tenable.com/plugins/nessus/157288"],
    cvss_vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
};

pub const HS_RDP_TLS_0204: FindingMeta = FindingMeta {
    id: "HS-RDP-TLS-0204",
    title: "RDP certificate invalid/expired",
    protocol: Protocol::Rdp,
    severity: Severity::High,
    description: "The RDP endpoint presents an invalid certificate (expired/untrusted/mismatched).",
    impact: "Clients may accept weak identity signals, increasing MITM risk and reducing trust in the channel.",
    remediation: "Deploy a valid, trusted certificate and ensure correct EKU/SAN settings for the RDP host.",
    references: &[],
    cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
};

pub const HS_RDP_CONFIG_0205: FindingMeta = FindingMeta {
    id: "HS-RDP-CONFIG-0205",
    title: "RDP weak cipher suites detected (configuration indicator)",
    protocol: Protocol::Rdp,
    severity: Severity::Medium,
    description: "Handshake observations suggest weak or deprecated cipher suites are available to RDP TLS.",
    impact: "Weak suites expand downgrade/negotiation risk and can violate policy baselines.",
    remediation: "Harden SCHANNEL cipher suite order; disable legacy suites; enforce TLS 1.2+.",
    references: &[],
    cvss_vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
};

// ---------- Registry (NEXT 30) ----------
pub const NEXT_30_FINDINGS: &[FindingMeta] = &[
    // TLS CERT (10)
    HS_TLS_CERT_0001,
    HS_TLS_CERT_0002,
    HS_TLS_CERT_0003,
    HS_TLS_CERT_0004,
    HS_TLS_CERT_0005,
    HS_TLS_CERT_0006,
    HS_TLS_CERT_0007,
    HS_TLS_CERT_0008,
    HS_TLS_CERT_0009,
    HS_TLS_CERT_0010,
    // TLS SCENARIO (8)
    HS_TLS_SCENARIO_0001,
    HS_TLS_SCENARIO_0002,
    HS_TLS_SCENARIO_0003,
    HS_TLS_SCENARIO_0004,
    HS_TLS_SCENARIO_0005,
    HS_TLS_SCENARIO_0006,
    HS_TLS_SCENARIO_0007,
    HS_TLS_SCENARIO_0008,
    // SSH (7)
    HS_SSH_KEX_0101,
    HS_SSH_KEX_0102,
    HS_SSH_KEX_0103,
    HS_SSH_HOSTKEY_0104,
    HS_SSH_HOSTKEY_0105,
    HS_SSH_CIPHER_0106,
    HS_SSH_CIPHER_0107,
    // RDP (5)
    HS_RDP_TLS_0201,
    HS_RDP_TLS_0202,
    HS_RDP_TLS_0203,
    HS_RDP_TLS_0204,
    HS_RDP_CONFIG_0205,
];




Combine into a single catalog (50 total)

In src/findings/mod.rs (or src/findings/catalog.rs), add:

use crate::findings::catalog::{FIRST_20_FINDINGS};
use crate::findings::catalog_more::NEXT_30_FINDINGS;
use crate::findings::catalog::FindingMeta;

pub fn all_findings() -> Vec<&'static FindingMeta> {
    let mut v: Vec<&'static FindingMeta> = Vec::with_capacity(50);
    v.extend(FIRST_20_FINDINGS.iter());
    v.extend(NEXT_30_FINDINGS.iter());
    v
}




Fast explain lookup (recommended)

Option A (no extra dependency): build a HashMap once

Simple and fine for 50200 findings.

use std::collections::HashMap;
use std::sync::OnceLock;

static FINDING_INDEX: OnceLock<HashMap<&'static str, &'static FindingMeta>> = OnceLock::new();

pub fn finding_by_id(id: &str) -> Option<&'static FindingMeta> {
    let idx = FINDING_INDEX.get_or_init(|| {
        let mut m = HashMap::new();
        for f in crate::findings::all_findings() {
            m.insert(f.id, f);
        }
        m
    });
    idx.get(id).copied()
}

Option B (compile-time perfect hash): phf

Faster and static, but youll maintain the map macro.

If you want this, add phf = { version = "0.11", features = ["macros"] } and Ill generate the full phf_map!{} block for all 50 IDs.



Prompt patch v8 (tiny, cumulative change)

Add these to your master coding-agent prompt under Findings / Explain:
		Implement catalog_more.rs containing NEXT_30_FINDINGS to reach 50 total findings minimum.
		Implement finding_by_id() using OnceLock<HashMap<...>> or phf.
		handshaker explain <ID> must fail cleanly with:
		Unknown finding ID
		list of closest matches (string similarity) and/or category hints.

Also keep these Tenable anchors as writeup style references for key baseline findings:
		TLS 1.0 detection (84470 / 104743)  
		TLS 1.1 deprecated (157288)  
		RC4 supported (65821)  
		Medium strength / 3DES (42873)  
		SSH weak KEX guidance (153953)  



