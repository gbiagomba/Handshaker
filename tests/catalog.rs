use handshaker::findings::catalog::{find_by_id, ALL_FINDINGS};

#[test]
fn all_findings_have_valid_ids() {
    for f in ALL_FINDINGS {
        assert!(
            f.id.starts_with("HS-"),
            "finding ID must start with HS-: {}",
            f.id
        );
        let parts: Vec<&str> = f.id.split('-').collect();
        assert!(
            parts.len() >= 4,
            "finding ID must have at least 4 dash-separated parts: {}",
            f.id
        );
        // Last part must be 4-digit numeric
        let last = parts[parts.len() - 1];
        assert_eq!(last.len(), 4, "last ID segment must be 4 digits: {}", f.id);
        assert!(
            last.chars().all(|c| c.is_ascii_digit()),
            "last ID segment must be numeric: {}",
            f.id
        );
    }
}

#[test]
fn all_findings_have_non_empty_fields() {
    for f in ALL_FINDINGS {
        assert!(!f.title.is_empty(), "empty title for {}", f.id);
        assert!(!f.description.is_empty(), "empty description for {}", f.id);
        assert!(!f.impact.is_empty(), "empty impact for {}", f.id);
        assert!(!f.remediation.is_empty(), "empty remediation for {}", f.id);
        assert!(
            f.cvss_vector.starts_with("CVSS:3.1/"),
            "invalid CVSS vector for {}",
            f.id
        );
    }
}

#[test]
fn catalog_has_minimum_50_findings() {
    assert!(
        ALL_FINDINGS.len() >= 50,
        "catalog must have at least 50 findings, found {}",
        ALL_FINDINGS.len()
    );
}

#[test]
fn find_by_id_returns_correct_finding() {
    let f = find_by_id("HS-TLS-PROTOCOL-0003").unwrap();
    assert_eq!(f.id, "HS-TLS-PROTOCOL-0003");
    assert!(f.title.contains("TLS 1.0"));
}

#[test]
fn find_by_id_unknown_returns_none() {
    assert!(find_by_id("HS-FAKE-THING-9999").is_none());
}

#[test]
fn all_finding_ids_are_unique() {
    use std::collections::HashSet;
    let ids: HashSet<&str> = ALL_FINDINGS.iter().map(|f| f.id).collect();
    assert_eq!(
        ids.len(),
        ALL_FINDINGS.len(),
        "duplicate finding IDs detected"
    );
}

#[test]
fn all_cvss_vectors_compute_valid_score() {
    use handshaker::scoring::cvss::score;
    for f in ALL_FINDINGS {
        let s = score(f.cvss_vector)
            .unwrap_or_else(|_| panic!("invalid CVSS vector for {}: {}", f.id, f.cvss_vector));
        assert!(
            (0.0..=10.0).contains(&s),
            "CVSS score out of range for {}: {}",
            f.id,
            s
        );
    }
}

#[test]
fn catalog_severity_aligns_with_cvss_guidelines() {
    use handshaker::scoring::cvss::{score, severity};
    for f in ALL_FINDINGS {
        let computed = severity(score(f.cvss_vector).unwrap());
        assert_eq!(
            f.severity, computed,
            "severity/CVSS mismatch for {}: declared {:?}, computed {:?}",
            f.id, f.severity, computed
        );
    }
}
