pub mod policy_loader;

use crate::errors::Result;
use crate::models::{ComplianceResult, ScanResult};

pub fn evaluate(profile: &str, results: &[ScanResult]) -> Result<ComplianceResult> {
    let policy = policy_loader::load_policy(profile)?;
    let mut failed = Vec::new();
    for r in results {
        for f in &r.findings {
            if policy.forbidden_findings.contains(&f.id) {
                failed.push(f.id.clone());
            }
        }
    }
    failed.sort();
    failed.dedup();
    Ok(ComplianceResult {
        profile: policy.name,
        compliant: failed.is_empty(),
        failed_controls: failed,
    })
}
