use crate::errors::Result;
use crate::models::{ScanResult, Target};

use super::posture::TlsPosture;
use super::{alpn, certs, ciphers, scenarios, versions};

pub async fn probe(target: Target) -> Result<ScanResult> {
    // Run all five TLS checks concurrently; scan time = max(module_time).
    let (ver_result, cip_result, cert_result, alp_result, scen_result) = tokio::join!(
        versions::check(&target),
        ciphers::check(&target),
        certs::check(&target),
        alpn::check(&target),
        scenarios::check(&target),
    );

    let mut posture = TlsPosture::default();
    let mut findings = Vec::new();

    if let Ok((fs, accepted, rejected)) = ver_result {
        findings.extend(fs);
        posture.protocols_accepted = accepted;
        posture.protocols_rejected = rejected;
    }

    if let Ok((fs, categories)) = cip_result {
        findings.extend(fs);
        posture.cipher_categories = categories;
    }

    if let Ok((fs, cert_summary)) = cert_result {
        findings.extend(fs);
        posture.certificate = cert_summary;
    }

    if let Ok((fs, alpn_protocols)) = alp_result {
        findings.extend(fs);
        posture.alpn_protocols = alpn_protocols;
    }

    if let Ok((fs, fallback_scsv, secure_renegotiation, compression)) = scen_result {
        findings.extend(fs);
        posture.fallback_scsv = fallback_scsv;
        posture.secure_renegotiation = secure_renegotiation;
        posture.compression = compression;
    }

    Ok(ScanResult {
        target,
        findings,
        metadata: serde_json::json!({"protocol": "tls", "posture": posture}),
    })
}
