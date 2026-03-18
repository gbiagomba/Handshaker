use crate::errors::{HandshakerError, Result};
use crate::findings::catalog;
use crate::models::{FindingInstance, Target};
use crate::protocols::tls::posture::CertSummary;
use openssl::pkey::Id;
use openssl::ssl::{SslConnector, SslMethod};
use openssl::x509::X509;
use tokio::task::spawn_blocking;

/// Returns (findings, cert_summary).
pub async fn check(target: &Target) -> Result<(Vec<FindingInstance>, Option<CertSummary>)> {
    let target = target.clone();
    spawn_blocking(move || check_blocking(&target))
        .await
        .unwrap_or_else(|e| Err(HandshakerError::Ssl(format!("join error: {e}"))))
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

fn check_blocking(target: &Target) -> Result<(Vec<FindingInstance>, Option<CertSummary>)> {
    let mut findings = Vec::new();
    let mut cert_summary = None;

    let builder =
        SslConnector::builder(SslMethod::tls()).map_err(|e| HandshakerError::Ssl(e.to_string()))?;
    let ssl = crate::protocols::tls::starttls::connect(target, builder);
    if let Ok(ssl) = ssl {
        if let Some(cert) = ssl.ssl().peer_certificate() {
            cert_summary = Some(extract_cert_summary(&cert, &target.host));
            if is_expired(&cert) {
                push(&mut findings, "HS-TLS-CERT-0001", "certificate expired");
            }
            if let Ok(now) = openssl::asn1::Asn1Time::days_from_now(0) {
                if cert
                    .not_before()
                    .compare(&now)
                    .map(|o| o == std::cmp::Ordering::Greater)
                    .unwrap_or(false)
                {
                    push(
                        &mut findings,
                        "HS-TLS-CERT-0002",
                        "certificate not yet valid",
                    );
                }
            }
            if is_self_signed(&cert) {
                push(&mut findings, "HS-TLS-CERT-0003", "self-signed certificate");
            }
            if !hostname_matches(&cert, &target.host) {
                push(&mut findings, "HS-TLS-CERT-0004", "hostname mismatch");
            }
            if is_sha1_signature(&cert) {
                push(
                    &mut findings,
                    "HS-TLS-CERT-0005",
                    "SHA1 signature algorithm",
                );
            }
            if rsa_key_too_small(&cert) {
                push(&mut findings, "HS-TLS-CERT-0006", "RSA key size < 2048");
            }
            if rsa_key_below_3072(&cert) {
                push(&mut findings, "HS-TLS-CERT-0013", "RSA key size < 3072");
            }
            if !has_extension_oid(&cert, "1.3.6.1.5.5.7.1.24") {
                push(
                    &mut findings,
                    "HS-TLS-CERT-0011",
                    "OCSP Must-Staple extension missing",
                );
            }
            if !has_extension_oid(&cert, "1.3.6.1.4.1.11129.2.4.2") {
                push(
                    &mut findings,
                    "HS-TLS-CERT-0012",
                    "Certificate Transparency SCT missing",
                );
            }
        } else {
            push(&mut findings, "HS-TLS-CERT-0007", "no peer certificate");
        }
        if let Some(chain) = ssl.ssl().peer_cert_chain() {
            if chain.len() < 2 {
                push(
                    &mut findings,
                    "HS-TLS-CERT-0007",
                    "certificate chain incomplete",
                );
            }
        }
    }
    Ok((findings, cert_summary))
}

fn extract_cert_summary(cert: &X509, host: &str) -> CertSummary {
    let subject = cert
        .subject_name()
        .entries_by_nid(openssl::nid::Nid::COMMONNAME)
        .next()
        .and_then(|e| e.data().as_utf8().ok().map(|s| s.to_string()))
        .unwrap_or_else(|| host.to_string());

    let issuer = cert
        .issuer_name()
        .entries_by_nid(openssl::nid::Nid::COMMONNAME)
        .next()
        .and_then(|e| e.data().as_utf8().ok().map(|s| s.to_string()))
        .unwrap_or_default();

    let not_before = cert.not_before().to_string();
    let not_after = cert.not_after().to_string();

    let (key_type, key_bits) = if let Ok(pkey) = cert.public_key() {
        let kt = match pkey.id() {
            Id::RSA => "RSA".to_string(),
            Id::EC => "ECDSA".to_string(),
            Id::DSA => "DSA".to_string(),
            _ => "unknown".to_string(),
        };
        let kb = pkey.bits();
        (kt, kb)
    } else {
        ("unknown".to_string(), 0)
    };

    let sig_algorithm = cert
        .signature_algorithm()
        .object()
        .nid()
        .short_name()
        .map(|s| s.to_string())
        .unwrap_or_default();

    let sans = cert
        .subject_alt_names()
        .map(|names| {
            names
                .iter()
                .filter_map(|n| n.dnsname().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();

    CertSummary {
        subject,
        issuer,
        not_before,
        not_after,
        key_type,
        key_bits,
        sig_algorithm,
        sans,
    }
}

fn hostname_matches(cert: &X509, host: &str) -> bool {
    if let Some(names) = cert.subject_alt_names() {
        for name in names {
            if let Some(dns) = name.dnsname() {
                if matches_dns(dns, host) {
                    return true;
                }
            }
        }
    }
    if let Some(entry) = cert
        .subject_name()
        .entries_by_nid(openssl::nid::Nid::COMMONNAME)
        .next()
    {
        if let Ok(cn) = entry.data().as_utf8() {
            return matches_dns(cn.as_ref(), host);
        }
    }
    false
}

fn matches_dns(pattern: &str, host: &str) -> bool {
    if pattern.starts_with("*.") {
        let suffix = &pattern[1..]; // e.g. ".example.com"
        if !host.ends_with(suffix) {
            return false;
        }
        // RFC 6125 §6.4.3: wildcard matches exactly one label.
        // The left-hand portion before the suffix must contain no dots.
        let label = &host[..host.len() - suffix.len()];
        return !label.contains('.');
    }
    pattern.eq_ignore_ascii_case(host)
}

fn is_sha1_signature(cert: &X509) -> bool {
    cert.signature_algorithm()
        .object()
        .nid()
        .short_name()
        .map(|n| n.to_ascii_lowercase().contains("sha1"))
        .unwrap_or(false)
}

fn rsa_key_too_small(cert: &X509) -> bool {
    if let Ok(pkey) = cert.public_key() {
        if let Ok(rsa) = pkey.rsa() {
            return rsa.size() * 8 < 2048;
        }
    }
    false
}

fn rsa_key_below_3072(cert: &X509) -> bool {
    if let Ok(pkey) = cert.public_key() {
        if let Ok(rsa) = pkey.rsa() {
            let bits = rsa.size() * 8;
            return bits < 3072;
        }
    }
    false
}

fn is_expired(cert: &X509) -> bool {
    if let Ok(now) = openssl::asn1::Asn1Time::days_from_now(0) {
        return cert
            .not_after()
            .compare(&now)
            .map(|o| o == std::cmp::Ordering::Less)
            .unwrap_or(false);
    }
    false
}

fn is_self_signed(cert: &X509) -> bool {
    let issuer = cert.issuer_name().to_der();
    let subject = cert.subject_name().to_der();
    issuer.ok() == subject.ok()
}

fn has_extension_oid(cert: &X509, oid: &str) -> bool {
    let Ok(text) = cert.to_text() else {
        return false;
    };
    let text = String::from_utf8_lossy(&text);
    match oid {
        "1.3.6.1.5.5.7.1.24" => text.contains("TLS Feature") || text.contains("status_request"),
        "1.3.6.1.4.1.11129.2.4.2" => text.contains("Signed Certificate Timestamp"),
        _ => false,
    }
}
