use crate::models::{DiffResult, ScanResult};
use std::collections::HashSet;

pub fn compare(left: &[ScanResult], right: &[ScanResult]) -> DiffResult {
    let left_ids = collect_ids(left);
    let right_ids = collect_ids(right);
    let added = right_ids.difference(&left_ids).cloned().collect();
    let removed = left_ids.difference(&right_ids).cloned().collect();
    let changed = Vec::new();
    DiffResult {
        added,
        removed,
        changed,
    }
}

fn collect_ids(results: &[ScanResult]) -> HashSet<String> {
    let mut ids = HashSet::new();
    for r in results {
        for f in &r.findings {
            ids.insert(f.id.clone());
        }
    }
    ids
}
