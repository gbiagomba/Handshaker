use crate::errors::Result;
use crate::models::ScanResult;
use html_escape::encode_text;
use std::io::Write;

pub fn write(results: &[ScanResult], out: Option<&mut dyn Write>) -> Result<()> {
    let mut html = String::new();
    html.push_str("<!doctype html><html><head><meta charset=\"utf-8\"><title>Handshaker Report</title></head><body>");
    html.push_str("<h1>Handshaker Report</h1>");
    for r in results {
        html.push_str(&format!(
            "<h2>Target: {}:{}</h2><ul>",
            encode_text(&r.target.host),
            r.target.port
        ));
        for f in &r.findings {
            html.push_str(&format!(
                "<li><strong>{}</strong> {} - {}</li>",
                encode_text(&f.id),
                encode_text(&f.title),
                encode_text(&f.details)
            ));
        }
        html.push_str("</ul>");
    }
    html.push_str("</body></html>");
    match out {
        Some(w) => writeln!(w, "{html}")?,
        None => println!("{html}"),
    }
    Ok(())
}
