use handshaker::cli::{OutputFormat, ScanArgs};
use handshaker::diff::compare;
use handshaker::input::load_targets;
use handshaker::models::{FindingInstance, Protocol, ScanResult, Severity, Target};
use handshaker::output::json;
use handshaker::scoring::aggregate::aggregate_cvss;

fn make_target(host: &str) -> Target {
    Target {
        raw: format!("{host}:443"),
        host: host.into(),
        port: 443,
        scheme: None,
    }
}

fn make_finding(id: &str) -> FindingInstance {
    FindingInstance {
        id: id.into(),
        title: id.into(),
        protocol: Protocol::Tls,
        severity: Severity::Medium,
        details: "test".into(),
        cvss_vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N".into(),
        cvss_score: 3.7,
    }
}

fn empty_scan_args() -> ScanArgs {
    ScanArgs {
        target: None,
        file: None,
        stdin: false,
        ports: vec![],
        output: OutputFormat::Json,
        out: None,
        concurrency: 32,
        timeout_secs: 10,
        policy: None,
        fail_on_noncompliant: false,
        benchmark: None,
        db: None,
    }
}

#[test]
fn load_targets_without_any_input_returns_error() {
    let args = empty_scan_args();
    assert!(load_targets(&args).is_err());
}

#[test]
fn aggregate_cvss_is_zero_for_empty_results() {
    let summary = aggregate_cvss(&[]);
    assert_eq!(summary.risk_max, 0.0);
    assert_eq!(summary.risk_weighted, 0.0);
}

#[test]
fn json_writer_emits_valid_json() {
    let results = vec![ScanResult {
        target: make_target("writer.example"),
        findings: vec![make_finding("HS-TLS-PROTOCOL-0003")],
        metadata: serde_json::json!({"protocol": "tls"}),
    }];
    let mut buf = Vec::new();
    json::write(&results, Some(&mut buf)).unwrap();
    let parsed: Vec<ScanResult> = serde_json::from_slice(&buf).unwrap();
    assert_eq!(parsed.len(), 1);
    assert_eq!(parsed[0].target.host, "writer.example");
}

#[test]
fn diff_deduplicates_duplicate_finding_ids_across_targets() {
    let left = vec![
        ScanResult {
            target: make_target("a.example"),
            findings: vec![make_finding("HS-TLS-CIPHER-0004")],
            metadata: serde_json::json!({}),
        },
        ScanResult {
            target: make_target("b.example"),
            findings: vec![make_finding("HS-TLS-CIPHER-0004")],
            metadata: serde_json::json!({}),
        },
    ];
    let right = vec![];
    let diff = compare(&left, &right);
    assert_eq!(diff.removed.len(), 1);
    assert_eq!(diff.removed[0], "HS-TLS-CIPHER-0004");
}
