use crate::errors::Result;
use crate::models::ScanResult;
use std::io::Write;

pub fn write(results: &[ScanResult], out: Option<&mut dyn Write>) -> Result<()> {
    let mut buf = String::new();
    for r in results {
        buf.push_str(&format!("Target: {}:{}\n", r.target.host, r.target.port));
        for f in &r.findings {
            buf.push_str(&format!(
                "- {} [{}] {} ({})\n",
                f.id, f.severity, f.title, f.details
            ));
        }
    }
    match out {
        Some(w) => w.write_all(buf.as_bytes())?,
        None => print!("{buf}"),
    }
    Ok(())
}
