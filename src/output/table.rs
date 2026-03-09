use crate::errors::Result;
use crate::models::ScanResult;
use comfy_table::{Cell, Table};
use std::io::Write;

pub fn write(results: &[ScanResult], out: Option<&mut dyn Write>) -> Result<()> {
    let mut table = Table::new();
    table.set_header(vec!["Target", "Finding ID", "Severity", "Title"]);
    for r in results {
        for f in &r.findings {
            table.add_row(vec![
                Cell::new(format!("{}:{}", r.target.host, r.target.port)),
                Cell::new(&f.id),
                Cell::new(format!("{:?}", f.severity)),
                Cell::new(&f.title),
            ]);
        }
    }
    let output = table.to_string();
    match out {
        Some(w) => writeln!(w, "{output}")?,
        None => println!("{output}"),
    }
    Ok(())
}
