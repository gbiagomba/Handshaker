pub mod evaluator;

use crate::errors::Result;
use crate::models::{BenchmarkResult, ScanResult};

pub fn evaluate(profile: &str, results: &[ScanResult]) -> Result<BenchmarkResult> {
    evaluator::evaluate(profile, results)
}
