use handshaker::models::{FindingInstance, Protocol, ScanResult, Severity, Target};
use handshaker::scoring::aggregate_scores;

fn make_target() -> Target {
    Target {
        raw: "example.com:443".into(),
        host: "example.com".into(),
        port: 443,
        scheme: None,
    }
}

fn make_finding(id: &str, severity: Severity, cvss: &str, score: f64) -> FindingInstance {
    FindingInstance {
        id: id.into(),
        title: id.into(),
        protocol: Protocol::Tls,
        severity,
        details: "test".into(),
        cvss_vector: cvss.into(),
        cvss_score: score,
    }
}

#[test]
fn score_runs() {
    let res = ScanResult {
        target: make_target(),
        findings: vec![make_finding(
            "HS-TLS-PROTOCOL-0003",
            Severity::High,
            "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
            4.8,
        )],
        metadata: serde_json::json!({"protocol": "tls"}),
    };
    let score = aggregate_scores(&[res]).unwrap();
    assert!(score.overall <= 100);
    assert!(!score.grade.is_empty());
}

#[test]
fn score_ssle2_sslv3_caps_to_f() {
    let res = ScanResult {
        target: make_target(),
        findings: vec![make_finding(
            "HS-TLS-PROTOCOL-0001",
            Severity::Critical,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
            9.1,
        )],
        metadata: serde_json::json!({}),
    };
    let score = aggregate_scores(&[res]).unwrap();
    assert_eq!(score.grade, "F", "SSLv2 should cap grade to F");
}

#[test]
fn score_invalid_cert_caps_to_c_or_lower() {
    let res = ScanResult {
        target: make_target(),
        findings: vec![make_finding(
            "HS-TLS-CERT-0001",
            Severity::Critical,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
            9.1,
        )],
        metadata: serde_json::json!({}),
    };
    let score = aggregate_scores(&[res]).unwrap();
    let grade_order = ["A+", "A", "B", "C", "D", "F"];
    let idx = grade_order.iter().position(|g| *g == score.grade).unwrap_or(5);
    assert!(idx >= 3, "expired cert should cap at C or lower, got {}", score.grade);
}

#[test]
fn score_clean_scan_gets_high_grade() {
    let res = ScanResult {
        target: make_target(),
        findings: vec![],
        metadata: serde_json::json!({}),
    };
    let score = aggregate_scores(&[res]).unwrap();
    assert!(
        score.grade == "A+" || score.grade == "A",
        "clean scan should get A/A+, got {}",
        score.grade
    );
}

#[test]
fn cvss_aggregate_max_and_weighted() {
    use handshaker::scoring::aggregate::aggregate_cvss;
    let res = ScanResult {
        target: make_target(),
        findings: vec![
            make_finding("HS-TLS-PROTOCOL-0001", Severity::Critical, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", 9.1),
            make_finding("HS-TLS-CIPHER-0004", Severity::High, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", 5.9),
        ],
        metadata: serde_json::json!({}),
    };
    let cvss = aggregate_cvss(&[res]);
    assert!(cvss.risk_max >= 9.0, "risk_max should be highest CVSS score");
    // risk_weighted is a decaying sum of top-N scores so it can exceed risk_max
    assert!(cvss.risk_weighted > 0.0, "risk_weighted must be positive");
}
