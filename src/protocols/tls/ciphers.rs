use crate::errors::{HandshakerError, Result};
use crate::findings::catalog;
use crate::models::{FindingInstance, Target};
use crate::protocols::tls::posture::CipherCategory;
use openssl::ssl::{SslConnector, SslMethod};
use tokio::task::spawn_blocking;

pub async fn check(target: &Target) -> Result<(Vec<FindingInstance>, Vec<CipherCategory>)> {
    let target = target.clone();
    spawn_blocking(move || check_blocking(&target))
        .await
        .unwrap_or_else(|e| Err(HandshakerError::Ssl(format!("join error: {e}"))))
}

fn check_blocking(target: &Target) -> Result<(Vec<FindingInstance>, Vec<CipherCategory>)> {
    let mut findings = Vec::new();

    // If we cannot connect at all, return empty results rather than a scan error.
    // handshake_with_builder returns Ok("") on connection failure, so treat an empty
    // default cipher the same as an Err — the host is unreachable or not TLS.
    let default_cipher = match handshake_cipher(target, None) {
        Ok(c) if !c.is_empty() => c,
        _ => return Ok((findings, vec![])),
    };

    // Probe each cipher category; connection failures mean "not supported".
    let null_ok   = supports_cipher_list(target, "NULL").unwrap_or(false);
    let anull_ok  = supports_cipher_list(target, "aNULL").unwrap_or(false);
    let exp_ok    = supports_cipher_list(target, "EXP").unwrap_or(false);
    let rc4_ok    = supports_cipher_list(target, "RC4").unwrap_or(false);
    let des3_ok   = supports_cipher_list(target, "3DES").unwrap_or(false);
    let medium_ok = supports_cipher_list(target, "MEDIUM").unwrap_or(false);
    let aead_ok   = supports_cipher_list(target, "AEAD").unwrap_or(false);
    let fs_ok     = supports_cipher_list(target, "ECDHE:DHE").unwrap_or(false);
    let chacha_ok = supports_cipher_list(target, "CHACHA20").unwrap_or(false);
    let krsa_ok   = supports_cipher_list(target, "kRSA").unwrap_or(false);

    // Emit findings only for security issues.
    if null_ok   { push(&mut findings, "HS-TLS-CIPHER-0001", "cipher list supported: NULL"); }
    if anull_ok  { push(&mut findings, "HS-TLS-CIPHER-0002", "cipher list supported: aNULL"); }
    if exp_ok    { push(&mut findings, "HS-TLS-CIPHER-0003", "cipher list supported: EXP"); }
    if rc4_ok    { push(&mut findings, "HS-TLS-CIPHER-0004", "cipher list supported: RC4"); }
    if des3_ok   { push(&mut findings, "HS-TLS-CIPHER-0005", "cipher list supported: 3DES"); }
    if medium_ok { push(&mut findings, "HS-TLS-CIPHER-0007", "cipher list supported: MEDIUM"); }
    if !aead_ok  { push(&mut findings, "HS-TLS-CIPHER-0008", "no AEAD cipher suites observed"); }
    if !fs_ok    { push(&mut findings, "HS-TLS-CIPHER-0009", "no forward secrecy suites observed"); }
    if !chacha_ok { push(&mut findings, "HS-TLS-CIPHER-0012", "no ChaCha20-Poly1305 suites observed"); }
    if krsa_ok   { push(&mut findings, "HS-TLS-CIPHER-0010", "legacy RSA key exchange supported"); }

    if default_cipher.contains("CBC")
        && supports_tls_version(target, openssl::ssl::SslVersion::TLS1).unwrap_or(false)
    {
        push(&mut findings, "HS-TLS-CIPHER-0006", "TLS 1.0 with CBC observed");
    }

    if let Some(bits) = negotiated_curve_bits(target).unwrap_or(None) {
        if is_weak_curve_bits(bits) {
            if let Some(meta) = catalog::find_by_id("HS-TLS-CIPHER-0011") {
                findings.push(build(meta, format!("weak curve size: {bits} bits")));
            }
        }
    }

    let categories = vec![
        CipherCategory { name: "AEAD".into(),   accepted: aead_ok },
        CipherCategory { name: "FS".into(),     accepted: fs_ok },
        CipherCategory { name: "NULL".into(),   accepted: null_ok },
        CipherCategory { name: "3DES".into(),   accepted: des3_ok },
        CipherCategory { name: "RC4".into(),    accepted: rc4_ok },
        CipherCategory { name: "EXPORT".into(), accepted: exp_ok },
        CipherCategory { name: "MEDIUM".into(), accepted: medium_ok },
    ];

    Ok((findings, categories))
}

fn supports_cipher_list(target: &Target, cipher_list: &str) -> Result<bool> {
    handshake_cipher(target, Some(cipher_list)).map(|c| !c.is_empty())
}

fn handshake_cipher(target: &Target, cipher_list: Option<&str>) -> Result<String> {
    let mut builder =
        SslConnector::builder(SslMethod::tls()).map_err(|e| HandshakerError::Ssl(e.to_string()))?;
    if let Some(list) = cipher_list {
        if builder.set_cipher_list(list).is_err() {
            // Cipher family not compiled into this OpenSSL build → treat as unsupported.
            return Ok(String::new());
        }
    }
    handshake_with_builder(target, builder)
}

fn supports_tls_version(target: &Target, version: openssl::ssl::SslVersion) -> Result<bool> {
    let mut builder =
        SslConnector::builder(SslMethod::tls()).map_err(|e| HandshakerError::Ssl(e.to_string()))?;
    builder.set_min_proto_version(Some(version)).ok();
    builder.set_max_proto_version(Some(version)).ok();
    handshake_with_builder(target, builder).map(|c| !c.is_empty())
}

fn handshake_with_builder(
    target: &Target,
    builder: openssl::ssl::SslConnectorBuilder,
) -> Result<String> {
    match crate::protocols::tls::starttls::connect(target, builder) {
        Ok(ssl) => Ok(ssl
            .ssl()
            .current_cipher()
            .map(|c| c.name().to_string())
            .unwrap_or_default()),
        // Connection failure means the cipher/version is simply not supported.
        Err(_) => Ok(String::new()),
    }
}

fn negotiated_curve_bits(target: &Target) -> Result<Option<u32>> {
    let builder =
        SslConnector::builder(SslMethod::tls()).map_err(|e| HandshakerError::Ssl(e.to_string()))?;
    match crate::protocols::tls::starttls::connect(target, builder) {
        Ok(ssl) => {
            if let Ok(key) = ssl.ssl().tmp_key() {
                return Ok(Some(key.bits()));
            }
            Ok(None)
        }
        Err(_) => Ok(None),
    }
}

fn is_weak_curve_bits(bits: u32) -> bool {
    bits > 0 && bits < 256
}

fn push(findings: &mut Vec<FindingInstance>, id: &str, details: &str) {
    if let Some(meta) = catalog::find_by_id(id) {
        findings.push(build(meta, details.to_string()));
    }
}

fn build(meta: &'static crate::findings::catalog::FindingMeta, details: String) -> FindingInstance {
    FindingInstance {
        id: meta.id.to_string(),
        title: meta.title.to_string(),
        protocol: meta.protocol,
        severity: meta.severity,
        details,
        cvss_vector: meta.cvss_vector.to_string(),
        cvss_score: crate::scoring::cvss::score(meta.cvss_vector).unwrap_or(0.0),
    }
}
