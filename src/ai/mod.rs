pub mod prompt;
pub mod providers;
pub mod redaction;

use crate::errors::Result;
use crate::models::ScanResult;

pub fn run(results: &[ScanResult], provider: Option<&str>) -> Result<()> {
    let redacted = redaction::redact(results);
    let prompt = prompt::build_prompt(&redacted);
    let provider = provider.unwrap_or("local");
    println!("AI provider: {provider}");
    println!("{prompt}");
    Ok(())
}
