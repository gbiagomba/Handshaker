use crate::errors::{HandshakerError, Result};
use crate::findings::catalog;
use crate::models::{FindingInstance, Target};
use openssl::ssl::{SslConnector, SslMethod};
use tokio::task::spawn_blocking;

pub async fn check(target: &Target) -> Result<Vec<FindingInstance>> {
    let target = target.clone();
    spawn_blocking(move || check_blocking(&target))
        .await
        .unwrap_or_else(|e| Err(HandshakerError::Ssl(format!("join error: {e}"))))
}

fn check_blocking(target: &Target) -> Result<Vec<FindingInstance>> {
    let mut findings = Vec::new();
    let default_cipher = handshake_cipher(target, None)?;

    let weak_checks = [
        ("HS-TLS-CIPHER-0001", "NULL"),
        ("HS-TLS-CIPHER-0002", "aNULL"),
        ("HS-TLS-CIPHER-0003", "EXP"),
        ("HS-TLS-CIPHER-0004", "RC4"),
        ("HS-TLS-CIPHER-0005", "3DES"),
        ("HS-TLS-CIPHER-0007", "MEDIUM"),
    ];
    for (id, list) in weak_checks {
        if supports_cipher_list(target, list)? {
            if let Some(meta) = catalog::find_by_id(id) {
                findings.push(build(meta, format!("cipher list supported: {list}")));
            }
        }
    }

    let aead_supported = supports_cipher_list(target, "AEAD")?;
    if !aead_supported {
        if let Some(meta) = catalog::find_by_id("HS-TLS-CIPHER-0008") {
            findings.push(build(meta, "no AEAD cipher suites observed".into()));
        }
    }

    let fs_supported = supports_cipher_list(target, "ECDHE:DHE")?;
    if !fs_supported {
        if let Some(meta) = catalog::find_by_id("HS-TLS-CIPHER-0009") {
            findings.push(build(meta, "no forward secrecy suites observed".into()));
        }
    }

    if !supports_cipher_list(target, "CHACHA20")? {
        if let Some(meta) = catalog::find_by_id("HS-TLS-CIPHER-0012") {
            findings.push(build(meta, "no ChaCha20-Poly1305 suites observed".into()));
        }
    }

    let rsa_kex = supports_cipher_list(target, "kRSA")?;
    if rsa_kex {
        if let Some(meta) = catalog::find_by_id("HS-TLS-CIPHER-0010") {
            findings.push(build(meta, "legacy RSA key exchange supported".into()));
        }
    }

    if default_cipher.contains("CBC")
        && supports_tls_version(target, openssl::ssl::SslVersion::TLS1)?
    {
        if let Some(meta) = catalog::find_by_id("HS-TLS-CIPHER-0006") {
            findings.push(build(meta, "TLS 1.0 with CBC observed".into()));
        }
    }

    if let Some(bits) = negotiated_curve_bits(target)? {
        if is_weak_curve_bits(bits) {
            if let Some(meta) = catalog::find_by_id("HS-TLS-CIPHER-0011") {
                findings.push(build(meta, format!("weak curve size: {bits} bits")));
            }
        }
    }

    Ok(findings)
}

fn supports_cipher_list(target: &Target, cipher_list: &str) -> Result<bool> {
    handshake_cipher(target, Some(cipher_list)).map(|c| !c.is_empty())
}

fn handshake_cipher(target: &Target, cipher_list: Option<&str>) -> Result<String> {
    let mut builder =
        SslConnector::builder(SslMethod::tls()).map_err(|e| HandshakerError::Ssl(e.to_string()))?;
    if let Some(list) = cipher_list {
        builder
            .set_cipher_list(list)
            .map_err(|e| HandshakerError::Ssl(e.to_string()))?;
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
    let ssl = crate::protocols::tls::starttls::connect(target, builder)?;
    Ok(ssl
        .ssl()
        .current_cipher()
        .map(|c| c.name().to_string())
        .unwrap_or_default())
}

fn negotiated_curve_bits(target: &Target) -> Result<Option<u32>> {
    let builder =
        SslConnector::builder(SslMethod::tls()).map_err(|e| HandshakerError::Ssl(e.to_string()))?;
    let ssl = crate::protocols::tls::starttls::connect(target, builder)?;
    if let Ok(key) = ssl.ssl().tmp_key() {
        return Ok(Some(key.bits()));
    }
    Ok(None)
}

fn is_weak_curve_bits(bits: u32) -> bool {
    bits > 0 && bits < 256
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
