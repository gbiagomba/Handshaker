use crate::errors::{HandshakerError, Result};
use crate::findings::catalog;
use crate::models::{FindingInstance, Target};
use openssl::ssl::{SslConnector, SslMethod, SslVersion};
use tokio::task::spawn_blocking;

/// Returns (findings, protocols_accepted, protocols_rejected).
pub async fn check(
    target: &Target,
) -> Result<(Vec<FindingInstance>, Vec<String>, Vec<String>)> {
    let mut findings = Vec::new();
    let mut accepted = Vec::new();
    let mut rejected = Vec::new();

    let versions = [
        (SslVersion::SSL3,   "HS-TLS-PROTOCOL-0002", "SSLv3"),
        (SslVersion::TLS1,   "HS-TLS-PROTOCOL-0003", "TLS1.0"),
        (SslVersion::TLS1_1, "HS-TLS-PROTOCOL-0004", "TLS1.1"),
        (SslVersion::TLS1_2, "HS-TLS-PROTOCOL-0005", "TLS1.2"),
        (SslVersion::TLS1_3, "HS-TLS-PROTOCOL-0006", "TLS1.3"),
    ];

    for (version, id, name) in versions {
        if let Ok(supported) = try_version_async(target, version).await {
            if supported {
                accepted.push(name.to_string());
            } else {
                rejected.push(name.to_string());
            }
            if (id == "HS-TLS-PROTOCOL-0005" || id == "HS-TLS-PROTOCOL-0006") && supported {
                continue;
            }
            if (id != "HS-TLS-PROTOCOL-0005" && id != "HS-TLS-PROTOCOL-0006") && !supported {
                continue;
            }
            if let Some(meta) = catalog::find_by_id(id) {
                findings.push(build(
                    meta,
                    format!("version {version:?} supported = {supported}"),
                ));
            }
        }
    }

    Ok((findings, accepted, rejected))
}

fn try_version(target: &Target, version: SslVersion) -> Result<bool> {
    let mut builder =
        SslConnector::builder(SslMethod::tls()).map_err(|e| HandshakerError::Ssl(e.to_string()))?;
    builder.set_min_proto_version(Some(version)).ok();
    builder.set_max_proto_version(Some(version)).ok();
    let ssl = crate::protocols::tls::starttls::connect(target, builder);
    Ok(ssl.is_ok())
}

async fn try_version_async(target: &Target, version: SslVersion) -> Result<bool> {
    let target = target.clone();
    spawn_blocking(move || try_version(&target, version))
        .await
        .unwrap_or_else(|e| Err(HandshakerError::Ssl(format!("join error: {e}"))))
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
