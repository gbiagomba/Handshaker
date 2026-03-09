use crate::errors::Result;
use crate::models::ScanResult;
use csv::Writer;
use std::io::Write;

pub fn write(results: &[ScanResult], out: Option<&mut dyn Write>) -> Result<()> {
    let mut buffer = Vec::new();
    {
        let mut wtr = Writer::from_writer(&mut buffer);
        wtr.write_record(["target", "finding_id", "severity", "title", "details"])?;
        for r in results {
            for f in &r.findings {
                wtr.write_record([
                    format!("{}:{}", r.target.host, r.target.port),
                    f.id.clone(),
                    format!("{:?}", f.severity),
                    f.title.clone(),
                    f.details.clone(),
                ])?;
            }
        }
        wtr.flush()?;
    }
    match out {
        Some(w) => {
            w.write_all(&buffer)?;
        }
        None => {
            std::io::stdout().write_all(&buffer)?;
        }
    }
    Ok(())
}
