use crate::errors::{HandshakerError, Result};
use crate::findings::catalog;
use crate::models::{FindingInstance, ScanResult, Target};
use openssl::ssl::{SslConnector, SslMethod, SslVersion};
use std::net::TcpStream;
use tokio::task::spawn_blocking;

pub async fn probe(target: Target) -> Result<ScanResult> {
    let t = target.clone();
    spawn_blocking(move || probe_blocking(t))
        .await
        .unwrap_or_else(|e| Err(HandshakerError::Rdp(format!("join error: {e}"))))
}

fn try_tls_version(target: &Target, version: SslVersion) -> Result<()> {
    let mut builder =
        SslConnector::builder(SslMethod::tls()).map_err(|e| HandshakerError::Rdp(e.to_string()))?;
    builder.set_min_proto_version(Some(version)).ok();
    builder.set_max_proto_version(Some(version)).ok();
    let connector = builder.build();
    let addr = format!("{}:{}", target.host, target.port);
    let stream = TcpStream::connect(addr)?;
    connector
        .connect(&target.host, stream)
        .map_err(|e| HandshakerError::Rdp(e.to_string()))?;
    Ok(())
}

fn push(findings: &mut Vec<FindingInstance>, id: &str, details: &str) {
    if let Some(meta) = catalog::find_by_id(id) {
        findings.push(FindingInstance {
            id: meta.id.to_string(),
            title: meta.title.to_string(),
            protocol: meta.protocol,
            severity: meta.severity,
            details: details.to_string(),
            cvss_vector: meta.cvss_vector.to_string(),
            cvss_score: crate::scoring::cvss::score(meta.cvss_vector).unwrap_or(0.0),
        });
    }
}

fn probe_blocking(target: Target) -> Result<ScanResult> {
    let mut findings = Vec::new();
    if try_tls_version(&target, SslVersion::TLS1).is_ok() {
        push(&mut findings, "HS-RDP-TLS-0202", "RDP accepted TLS 1.0");
    }
    if try_tls_version(&target, SslVersion::TLS1_1).is_ok() {
        push(&mut findings, "HS-RDP-TLS-0203", "RDP accepted TLS 1.1");
    }

    let addr = format!("{}:{}", target.host, target.port);
    let stream = TcpStream::connect(addr)?;
    let connector = SslConnector::builder(SslMethod::tls())
        .map_err(|e| HandshakerError::Rdp(e.to_string()))?
        .build();
    if let Ok(ssl) = connector.connect(&target.host, stream) {
        if let Some(cert) = ssl.ssl().peer_certificate() {
            if is_expired(&cert) {
                push(&mut findings, "HS-RDP-TLS-0204", "RDP certificate expired");
            }
        } else {
            push(&mut findings, "HS-RDP-TLS-0204", "RDP certificate missing");
        }
        // Only report NLA not enforced when plain TLS succeeds without CredSSP.
        push(
            &mut findings,
            "HS-RDP-TLS-0201",
            "NLA requirement not validated; TLS accepted without CredSSP",
        );
    }

    Ok(ScanResult {
        target,
        findings,
        metadata: serde_json::json!({"protocol": "rdp"}),
    })
}

fn is_expired(cert: &openssl::x509::X509) -> bool {
    if let Ok(now) = openssl::asn1::Asn1Time::days_from_now(0) {
        return cert
            .not_after()
            .compare(&now)
            .map(|o| o == std::cmp::Ordering::Less)
            .unwrap_or(false);
    }
    false
}
