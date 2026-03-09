use handshaker::scoring::cvss::score;

#[test]
fn cvss_known_vector() {
    // AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H = 9.8 (Critical)
    let s = score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H").unwrap();
    assert!((s - 9.8).abs() < 0.2, "expected ~9.8, got {s}");
}

#[test]
fn cvss_medium_vector() {
    // AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N = 4.8
    let s = score("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N").unwrap();
    assert!(s > 0.0 && s < 7.0, "expected medium range, got {s}");
}

#[test]
fn cvss_scope_changed() {
    // AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H = 9.9
    let s = score("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H").unwrap();
    assert!(s >= 9.0, "expected high score with scope changed, got {s}");
}

#[test]
fn cvss_zero_impact() {
    // All C/I/A = N → base score = 0
    let s = score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N").unwrap();
    assert_eq!(s, 0.0, "expected 0.0 for no impact, got {s}");
}

#[test]
fn cvss_invalid_vector_rejected() {
    assert!(score("CVSS:3.0/AV:N").is_err());
    assert!(score("not a cvss vector").is_err());
}

#[test]
fn cvss_all_catalog_vectors_parse() {
    use handshaker::findings::catalog::ALL_FINDINGS;
    for f in ALL_FINDINGS {
        let s = score(f.cvss_vector);
        assert!(
            s.is_ok(),
            "failed to parse CVSS vector for {}: {}",
            f.id,
            f.cvss_vector
        );
    }
}
