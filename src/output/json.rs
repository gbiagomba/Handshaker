use crate::errors::Result;
use crate::models::ScanResult;
use std::io::Write;

pub fn write(results: &[ScanResult], out: Option<&mut dyn Write>) -> Result<()> {
    let data = serde_json::to_string_pretty(results)?;
    match out {
        Some(w) => {
            writeln!(w, "{data}")?;
        }
        None => {
            println!("{data}");
        }
    }
    Ok(())
}
