use handshaker::diff::compare;
use handshaker::models::{FindingInstance, Protocol, ScanResult, Severity, Target};

fn make_result(host: &str, finding_ids: &[&str]) -> ScanResult {
    ScanResult {
        target: Target {
            raw: format!("{host}:443"),
            host: host.into(),
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
                cvss_vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N".into(),
                cvss_score: 3.7,
            })
            .collect(),
        metadata: serde_json::json!({}),
    }
}

#[test]
fn diff_detects_added() {
    let left = make_result("a", &[]);
    let right = make_result("a", &["HS-TLS-PROTOCOL-0003"]);
    let diff = compare(&[left], &[right]);
    assert_eq!(diff.added.len(), 1);
    assert!(diff.removed.is_empty());
}

#[test]
fn diff_detects_removed() {
    let left = make_result("a", &["HS-TLS-PROTOCOL-0003"]);
    let right = make_result("a", &[]);
    let diff = compare(&[left], &[right]);
    assert_eq!(diff.removed.len(), 1);
    assert!(diff.added.is_empty());
}

#[test]
fn diff_no_changes() {
    let id = "HS-TLS-CIPHER-0004";
    let left = make_result("a", &[id]);
    let right = make_result("a", &[id]);
    let diff = compare(&[left], &[right]);
    assert!(diff.added.is_empty());
    assert!(diff.removed.is_empty());
}

#[test]
fn diff_multiple_targets() {
    let left = vec![
        make_result("a", &["HS-TLS-PROTOCOL-0003"]),
        make_result("b", &[]),
    ];
    let right = vec![
        make_result("a", &[]),
        make_result("b", &["HS-TLS-CIPHER-0001"]),
    ];
    let diff = compare(&left, &right);
    assert!(!diff.added.is_empty());
    assert!(!diff.removed.is_empty());
}
