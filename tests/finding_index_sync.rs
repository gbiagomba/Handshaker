use std::process::Command;

#[test]
fn finding_index_stays_in_sync_with_catalog() {
    let output = Command::new("python3")
        .arg("scripts/check_finding_index_sync.py")
        .output()
        .expect("failed to run sync check");

    assert!(
        output.status.success(),
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
