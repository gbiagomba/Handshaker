use handshaker::scoring::cvss::{score, severity};

#[test]
fn severity_maps_zero_to_info() {
    assert_eq!(format!("{}", severity(0.0)), "Info");
}

#[test]
fn severity_maps_three_seven_to_low() {
    assert_eq!(format!("{}", severity(3.7)), "Low");
}

#[test]
fn severity_maps_four_zero_to_medium() {
    assert_eq!(format!("{}", severity(4.0)), "Medium");
}

#[test]
fn severity_maps_seven_zero_to_high() {
    assert_eq!(format!("{}", severity(7.0)), "High");
}

#[test]
fn severity_maps_nine_zero_to_critical() {
    assert_eq!(format!("{}", severity(9.0)), "Critical");
}

#[test]
fn score_supports_exact_low_boundary_vector() {
    let v = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N";
    assert_eq!(score(v).unwrap(), 3.7);
}

#[test]
fn score_supports_exact_medium_boundary_vector() {
    let v = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:N/I:N/A:L";
    assert_eq!(score(v).unwrap(), 4.0);
}

#[test]
fn score_supports_exact_high_boundary_vector() {
    let v = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:H";
    assert_eq!(score(v).unwrap(), 7.0);
}

#[test]
fn invalid_av_metric_is_rejected() {
    assert!(score("CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H").is_err());
}

#[test]
fn missing_scope_metric_is_rejected() {
    assert!(score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/C:H/I:H/A:H").is_err());
}

#[test]
fn invalid_ui_metric_is_rejected() {
    assert!(score("CVSS:3.1/AV:N/AC:L/PR:N/UI:X/S:U/C:H/I:H/A:H").is_err());
}

#[test]
fn scope_changed_low_privileges_scores_higher() {
    let unchanged = score("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H").unwrap();
    let changed = score("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H").unwrap();
    assert!(changed > unchanged);
}
