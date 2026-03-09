use crate::errors::Result;
use crate::models::{ScanResult, Target};

use super::{alpn, certs, ciphers, scenarios, versions};

pub async fn probe(target: Target) -> Result<ScanResult> {
    let mut findings = Vec::new();
    findings.extend(versions::check(&target).await?);
    findings.extend(ciphers::check(&target).await?);
    findings.extend(certs::check(&target).await?);
    findings.extend(alpn::check(&target).await?);
    findings.extend(scenarios::check(&target).await?);

    Ok(ScanResult {
        target,
        findings,
        metadata: serde_json::json!({"protocol": "tls"}),
    })
}
