use crate::errors::{HandshakerError, Result};
use crate::findings::catalog;
use crate::models::{FindingInstance, ScanResult, Target};
use ssh2::{MethodType, Session};
use std::net::TcpStream;
use tokio::task::spawn_blocking;

pub async fn probe(target: Target) -> Result<ScanResult> {
    let t = target.clone();
    spawn_blocking(move || probe_blocking(t))
        .await
        .unwrap_or_else(|e| Err(HandshakerError::Ssh(format!("join error: {e}"))))
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

fn probe_blocking(target: Target) -> Result<ScanResult> {
    let mut findings = Vec::new();
    let addr = format!("{}:{}", target.host, target.port);
    let stream = TcpStream::connect(addr)?;
    let mut sess = Session::new().map_err(|e| HandshakerError::Ssh(e.to_string()))?;
    sess.set_tcp_stream(stream);
    sess.handshake()
        .map_err(|e| HandshakerError::Ssh(e.to_string()))?;

    let banner = sess.banner().unwrap_or("");
    if banner.contains("OpenSSH_4") || banner.contains("OpenSSH_5") {
        if let Some(meta) = catalog::find_by_id("HS-SSH-CONFIG-0110") {
            findings.push(build(meta, format!("banner: {banner}")));
        }
    }

    if let Some(kex) = sess.methods(MethodType::Kex) {
        let parts = kex.split(',');
        if parts.clone().any(|m| m.contains("group1")) {
            push(
                &mut findings,
                "HS-SSH-KEX-0101",
                "weak diffie-hellman group1",
            );
        }
        if parts.clone().any(|m| m.contains("group-exchange-sha1")) {
            push(
                &mut findings,
                "HS-SSH-KEX-0102",
                "group-exchange-sha1 enabled",
            );
        }
        if parts
            .clone()
            .any(|m| m.contains("gss") && m.contains("sha1"))
        {
            push(&mut findings, "HS-SSH-KEX-0103", "gss-* sha1 enabled");
        }
    }

    if let Some(ciphers) = sess.methods(MethodType::CryptCs) {
        let parts = ciphers.split(',');
        if parts.clone().any(|c| c.contains("cbc")) {
            push(&mut findings, "HS-SSH-CIPHER-0106", "CBC ciphers enabled");
        }
        if parts
            .clone()
            .any(|c| c.contains("arcfour") || c.contains("rc4"))
        {
            push(&mut findings, "HS-SSH-CIPHER-0107", "RC4 ciphers enabled");
        }
    }

    if let Some(macs) = sess.methods(MethodType::MacCs) {
        let parts = macs.split(',');
        if parts.clone().any(|m| m.contains("hmac-sha1")) {
            push(&mut findings, "HS-SSH-MAC-0108", "hmac-sha1 enabled");
        }
        if parts.clone().any(|m| m.contains("umac-64")) {
            push(&mut findings, "HS-SSH-MAC-0109", "umac-64 enabled");
        }
    }

    if let Some(hostkeys) = sess.methods(MethodType::HostKey) {
        let parts = hostkeys.split(',');
        if parts.clone().any(|h| h == "ssh-rsa") {
            push(&mut findings, "HS-SSH-HOSTKEY-0104", "ssh-rsa enabled");
        }
    }

    if let Some((key, key_type)) = sess.host_key() {
        // Ed25519 and other fixed-size algorithms have short key blobs by design;
        // only flag RSA keys smaller than 2048 bits (256 bytes).
        if matches!(key_type, ssh2::HostKeyType::Rsa) && key.len() < 256 {
            push(
                &mut findings,
                "HS-SSH-HOSTKEY-0105",
                "hostkey length < 2048 bits",
            );
        }
    }

    Ok(ScanResult {
        target,
        findings,
        metadata: serde_json::json!({"protocol": "ssh"}),
    })
}

fn push(findings: &mut Vec<FindingInstance>, id: &str, details: &str) {
    if let Some(meta) = catalog::find_by_id(id) {
        findings.push(build(meta, details.to_string()));
    }
}
