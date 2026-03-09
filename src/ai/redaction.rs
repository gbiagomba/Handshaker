use crate::models::ScanResult;

pub fn redact(results: &[ScanResult]) -> Vec<ScanResult> {
    let mut out = Vec::new();
    for r in results {
        let mut r2 = r.clone();
        r2.target.host = "<redacted>".to_string();
        out.push(r2);
    }
    out
}
