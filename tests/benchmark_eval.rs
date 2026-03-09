use handshaker::benchmark::evaluate;
use handshaker::models::{FindingInstance, Protocol, ScanResult, Severity, Target};

fn make_result(finding_ids: &[&str]) -> ScanResult {
    ScanResult {
        target: Target {
            raw: "a:443".into(),
            host: "a".into(),
            port: 443,
            scheme: None,
        },
        findings: finding_ids
            .iter()
            .map(|id| FindingInstance {
                id: id.to_string(),
                title: id.to_string(),
                protocol: Protocol::Tls,
                severity: Severity::High,
                details: "test".into(),
                cvss_vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N".into(),
                cvss_score: 4.8,
            })
            .collect(),
        metadata: serde_json::json!({}),
    }
}

#[test]
fn benchmark_scores() {
    let res = make_result(&["HS-TLS-PROTOCOL-0003"]);
    let result = evaluate("default", &[res]).unwrap();
    assert!(result.score <= 100);
}

#[test]
fn benchmark_clean_scan_high_score() {
    let res = make_result(&[]);
    let result = evaluate("default", &[res]).unwrap();
    // A clean scan should achieve a higher score than one with findings
    let dirty = make_result(&["HS-TLS-PROTOCOL-0001", "HS-TLS-CIPHER-0001"]);
    let dirty_result = evaluate("default", &[dirty]).unwrap();
    assert!(result.score >= dirty_result.score);
}

#[test]
fn benchmark_profile_name_returned() {
    let res = make_result(&[]);
    let result = evaluate("default", &[res]).unwrap();
    assert!(!result.profile.is_empty());
}
