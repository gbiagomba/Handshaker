use crate::errors::Result;
use crate::models::{BenchmarkResult, ScanResult};

pub fn evaluate(profile: &str, results: &[ScanResult]) -> Result<BenchmarkResult> {
    // Simple benchmark: score 100 minus 5 for each unique finding
    let mut unique = std::collections::HashSet::new();
    for r in results {
        for f in &r.findings {
            unique.insert(f.id.clone());
        }
    }
    let mut score = 100i32 - (unique.len() as i32 * 5);
    if score < 0 {
        score = 0;
    }
    Ok(BenchmarkResult {
        profile: profile.to_string(),
        score: score as u32,
        failures: unique.into_iter().collect(),
    })
}
