use crate::models::ScanResult;

pub fn build_prompt(results: &[ScanResult]) -> String {
    let mut out = String::from("Summarize security posture findings:\n");
    for r in results {
        out.push_str(&format!("Target {}:{}\n", r.target.host, r.target.port));
        for f in &r.findings {
            out.push_str(&format!("- {} {}\n", f.id, f.title));
        }
    }
    out
}
