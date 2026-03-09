use crate::errors::Result;
use crate::models::{CvssSummary, ScanResult, ScoreSummary};

pub fn aggregate_scores(results: &[ScanResult]) -> Result<ScoreSummary> {
    Ok(crate::scoring::ssllabs::score(results))
}

pub fn aggregate_cvss(results: &[ScanResult]) -> CvssSummary {
    let mut scores: Vec<f64> = Vec::new();
    for r in results {
        for f in &r.findings {
            scores.push(f.cvss_score);
        }
    }
    scores.sort_by(|a, b| b.partial_cmp(a).unwrap_or(std::cmp::Ordering::Equal));
    let risk_max = scores.first().copied().unwrap_or(0.0);
    let mut weighted = 0.0;
    let mut weight = 1.0;
    for s in scores.iter().take(5) {
        weighted += s * weight;
        weight *= 0.6;
    }
    CvssSummary {
        risk_max,
        risk_weighted: (weighted * 10.0).round() / 10.0,
    }
}
