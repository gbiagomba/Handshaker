use handshaker::findings::catalog::ALL_FINDINGS;
use handshaker::scoring::cvss::score;

#[test]
fn finding_count_is_still_68() {
    assert_eq!(ALL_FINDINGS.len(), 68);
}

#[test]
fn tls_protocol_finding_count_is_10() {
    assert_eq!(
        ALL_FINDINGS
            .iter()
            .filter(|f| f.id.starts_with("HS-TLS-PROTOCOL-"))
            .count(),
        10
    );
}

#[test]
fn tls_cipher_finding_count_is_12() {
    assert_eq!(
        ALL_FINDINGS
            .iter()
            .filter(|f| f.id.starts_with("HS-TLS-CIPHER-"))
            .count(),
        12
    );
}

#[test]
fn tls_cert_finding_count_is_13() {
    assert_eq!(
        ALL_FINDINGS
            .iter()
            .filter(|f| f.id.starts_with("HS-TLS-CERT-"))
            .count(),
        13
    );
}

#[test]
fn tls_scenario_finding_count_is_11() {
    assert_eq!(
        ALL_FINDINGS
            .iter()
            .filter(|f| f.id.starts_with("HS-TLS-SCENARIO-"))
            .count(),
        11
    );
}

#[test]
fn tls_extension_finding_count_is_2() {
    assert_eq!(
        ALL_FINDINGS
            .iter()
            .filter(|f| f.id.starts_with("HS-TLS-EXTENSION-"))
            .count(),
        2
    );
}

#[test]
fn ssh_finding_count_is_10() {
    assert_eq!(
        ALL_FINDINGS
            .iter()
            .filter(|f| f.id.starts_with("HS-SSH-"))
            .count(),
        10
    );
}

#[test]
fn rdp_finding_count_is_5() {
    assert_eq!(
        ALL_FINDINGS
            .iter()
            .filter(|f| f.id.starts_with("HS-RDP-"))
            .count(),
        5
    );
}

#[test]
fn general_finding_count_is_5() {
    assert_eq!(
        ALL_FINDINGS
            .iter()
            .filter(|f| f.id.starts_with("HS-GENERAL-"))
            .count(),
        5
    );
}

#[test]
fn all_reference_urls_are_https() {
    for finding in ALL_FINDINGS {
        for reference in finding.references {
            assert!(
                reference.starts_with("https://"),
                "non-https reference on {}: {}",
                finding.id,
                reference
            );
        }
    }
}

#[test]
fn info_findings_have_zero_cvss() {
    for finding in ALL_FINDINGS.iter().filter(|f| format!("{}", f.severity) == "Info") {
        assert_eq!(score(finding.cvss_vector).unwrap(), 0.0, "{}", finding.id);
    }
}

#[test]
fn low_findings_have_sub_four_positive_cvss() {
    for finding in ALL_FINDINGS.iter().filter(|f| format!("{}", f.severity) == "Low") {
        let s = score(finding.cvss_vector).unwrap();
        assert!(s > 0.0 && s < 4.0, "{} -> {}", finding.id, s);
    }
}

#[test]
fn critical_finding_count_is_2() {
    assert_eq!(
        ALL_FINDINGS
            .iter()
            .filter(|f| format!("{}", f.severity) == "Critical")
            .count(),
        2
    );
}

#[test]
fn high_finding_count_is_4() {
    assert_eq!(
        ALL_FINDINGS
            .iter()
            .filter(|f| format!("{}", f.severity) == "High")
            .count(),
        4
    );
}

#[test]
fn medium_finding_count_is_34() {
    assert_eq!(
        ALL_FINDINGS
            .iter()
            .filter(|f| format!("{}", f.severity) == "Medium")
            .count(),
        34
    );
}

#[test]
fn low_finding_count_is_9() {
    assert_eq!(
        ALL_FINDINGS
            .iter()
            .filter(|f| format!("{}", f.severity) == "Low")
            .count(),
        9
    );
}

#[test]
fn info_finding_count_is_19() {
    assert_eq!(
        ALL_FINDINGS
            .iter()
            .filter(|f| format!("{}", f.severity) == "Info")
            .count(),
        19
    );
}

#[test]
fn critical_findings_score_at_least_nine() {
    for finding in ALL_FINDINGS.iter().filter(|f| format!("{}", f.severity) == "Critical") {
        assert!(score(finding.cvss_vector).unwrap() >= 9.0, "{}", finding.id);
    }
}

#[test]
fn high_findings_score_in_high_band() {
    for finding in ALL_FINDINGS.iter().filter(|f| format!("{}", f.severity) == "High") {
        let s = score(finding.cvss_vector).unwrap();
        assert!((7.0..9.0).contains(&s), "{} -> {}", finding.id, s);
    }
}

#[test]
fn medium_findings_score_in_medium_band() {
    for finding in ALL_FINDINGS.iter().filter(|f| format!("{}", f.severity) == "Medium") {
        let s = score(finding.cvss_vector).unwrap();
        assert!((4.0..7.0).contains(&s), "{} -> {}", finding.id, s);
    }
}

#[test]
fn references_are_unique_within_each_finding() {
    use std::collections::HashSet;
    for finding in ALL_FINDINGS {
        let refs: HashSet<&str> = finding.references.iter().copied().collect();
        assert_eq!(refs.len(), finding.references.len(), "{}", finding.id);
    }
}

#[test]
fn finding_titles_are_unique() {
    use std::collections::HashSet;
    let titles: HashSet<&str> = ALL_FINDINGS.iter().map(|f| f.title).collect();
    assert_eq!(titles.len(), ALL_FINDINGS.len());
}
