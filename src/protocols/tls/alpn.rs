use crate::errors::{HandshakerError, Result};
use crate::findings::catalog;
use crate::models::{FindingInstance, Target};
use openssl::ssl::{SslConnector, SslMethod, SslVersion};
use tokio::task::spawn_blocking;

/// Returns (findings, alpn_protocols_negotiated).
pub async fn check(target: &Target) -> Result<(Vec<FindingInstance>, Vec<String>)> {
    let target = target.clone();
    spawn_blocking(move || check_blocking(&target))
        .await
        .unwrap_or_else(|e| Err(HandshakerError::Ssl(format!("join error: {e}"))))
}

fn check_blocking(target: &Target) -> Result<(Vec<FindingInstance>, Vec<String>)> {
    let mut findings = Vec::new();
    let mut alpn_protocols = Vec::new();

    let mut builder =
        SslConnector::builder(SslMethod::tls()).map_err(|e| HandshakerError::Ssl(e.to_string()))?;
    builder.set_alpn_protos(b"\x02h2\x08http/1.1").ok();
    if let Ok(ssl) = crate::protocols::tls::starttls::connect(target, builder) {
        if let Some(alpn) = ssl.ssl().selected_alpn_protocol() {
            let alpn_str = String::from_utf8_lossy(alpn).to_string();
            alpn_protocols.push(alpn_str.clone());
            if alpn_str == "h2"
                && (supports_tls_version(target, SslVersion::TLS1).unwrap_or(false)
                    || supports_tls_version(target, SslVersion::TLS1_1).unwrap_or(false))
            {
                if let Some(meta) = catalog::find_by_id("HS-TLS-PROTOCOL-0010") {
                    findings.push(build(meta, "HTTP/2 offered with weak TLS versions".into()));
                }
            }
        } else if let Some(meta) = catalog::find_by_id("HS-TLS-EXTENSION-0012") {
            findings.push(build(meta, "ALPN not advertised".into()));
        }
    }
    Ok((findings, alpn_protocols))
}

fn supports_tls_version(target: &Target, version: SslVersion) -> Result<bool> {
    let mut builder =
        SslConnector::builder(SslMethod::tls()).map_err(|e| HandshakerError::Ssl(e.to_string()))?;
    builder.set_min_proto_version(Some(version)).ok();
    builder.set_max_proto_version(Some(version)).ok();
    Ok(crate::protocols::tls::starttls::connect(target, builder).is_ok())
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
