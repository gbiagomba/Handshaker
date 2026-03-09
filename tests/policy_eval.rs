use handshaker::compliance::evaluate;
use handshaker::models::{FindingInstance, Protocol, ScanResult, Severity, Target};

fn make_result(finding_ids: &[&str]) -> ScanResult {
    ScanResult {
        target: Target {
            raw: "example.com:443".into(),
            host: "example.com".into(),
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
        metadata: serde_json::json!({"protocol": "tls"}),
    }
}

#[test]
fn policy_fails_on_forbidden() {
    let res = make_result(&["HS-TLS-PROTOCOL-0003"]);
    let result = evaluate("default", &[res]).unwrap();
    assert!(!result.compliant);
    assert!(result.failed_controls.contains(&"HS-TLS-PROTOCOL-0003".to_string()));
}

#[test]
fn policy_passes_on_clean_scan() {
    let res = make_result(&[]);
    let result = evaluate("default", &[res]).unwrap();
    assert!(result.compliant);
    assert!(result.failed_controls.is_empty());
}

#[test]
fn policy_deduplicates_failed_controls() {
    // Same finding on two targets
    let r1 = make_result(&["HS-TLS-PROTOCOL-0003"]);
    let r2 = make_result(&["HS-TLS-PROTOCOL-0003"]);
    let result = evaluate("default", &[r1, r2]).unwrap();
    assert!(!result.compliant);
    assert_eq!(
        result
            .failed_controls
            .iter()
            .filter(|c| *c == "HS-TLS-PROTOCOL-0003")
            .count(),
        1,
        "duplicate finding should appear once"
    );
}

#[test]
fn policy_pci_dss_loads() {
    let res = make_result(&["HS-TLS-PROTOCOL-0001"]);
    let result = evaluate("pci-dss", &[res]).unwrap();
    assert!(!result.compliant);
}

#[test]
fn policy_nist_loads() {
    let res = make_result(&[]);
    let result = evaluate("nist-800-52r2", &[res]).unwrap();
    assert!(result.compliant);
}
