pub mod csv;
pub mod html;
pub mod json;
pub mod sqlite;
pub mod table;
pub mod text;

use crate::cli::OutputFormat;
use crate::errors::{HandshakerError, Result};
use crate::models::{BenchmarkResult, ComplianceResult, DiffResult, ScanResult, ScoreSummary};
use std::fs::File;
use std::io::{self, Write};

pub struct OutputWriter {
    format: OutputFormat,
    out: Option<File>,
}

impl OutputWriter {
    pub fn new(format: OutputFormat, out_path: Option<String>) -> Result<Self> {
        let out = if let Some(p) = out_path {
            Some(File::create(p)?)
        } else {
            None
        };
        Ok(Self { format, out })
    }

    pub fn write_scan(&mut self, results: &[ScanResult]) -> Result<()> {
        let out = self.out.as_mut().map(|f| f as &mut dyn Write);
        match self.format {
            OutputFormat::Json => json::write(results, out),
            OutputFormat::Text => text::write(results, out),
            OutputFormat::Table => table::write(results, out),
            OutputFormat::Html => html::write(results, out),
            OutputFormat::Csv => csv::write(results, out),
            OutputFormat::Sqlite => {
                Err(HandshakerError::Config("Use --db for sqlite output".into()))
            }
        }
    }

    pub fn write_compliance(&mut self, result: &ComplianceResult) -> Result<()> {
        let mut w = self.writer();
        writeln!(
            w,
            "Compliance: {} => compliant={}",
            result.profile, result.compliant
        )?;
        if !result.failed_controls.is_empty() {
            writeln!(w, "Failed controls:")?;
            for c in &result.failed_controls {
                writeln!(w, "- {}", c)?;
            }
        }
        Ok(())
    }

    pub fn write_benchmark(&mut self, result: &BenchmarkResult) -> Result<()> {
        let mut w = self.writer();
        writeln!(w, "Benchmark: {} => score={}", result.profile, result.score)?;
        if !result.failures.is_empty() {
            writeln!(w, "Failures:")?;
            for c in &result.failures {
                writeln!(w, "- {}", c)?;
            }
        }
        Ok(())
    }

    pub fn writer(&mut self) -> Box<dyn Write + '_> {
        match self.out.as_mut() {
            Some(f) => Box::new(f),
            None => Box::new(io::stdout()),
        }
    }
}

pub fn read_json<T: serde::de::DeserializeOwned>(path: &str) -> Result<T> {
    let data = std::fs::read_to_string(path)?;
    Ok(serde_json::from_str(&data)?)
}

pub fn write_explain(meta: &crate::findings::types::FindingMeta) -> Result<()> {
    let mut out = io::stdout();
    writeln!(out, "{} - {}", meta.id, meta.title)?;
    writeln!(
        out,
        "Protocol: {:?} | Severity: {:?}",
        meta.protocol, meta.severity
    )?;
    writeln!(out, "Description: {}", meta.description)?;
    writeln!(out, "Impact: {}", meta.impact)?;
    writeln!(out, "Remediation: {}", meta.remediation)?;
    if !meta.references.is_empty() {
        writeln!(out, "References:")?;
        for r in meta.references {
            writeln!(out, "- {}", r)?;
        }
    }
    let cvss_score = crate::scoring::cvss::score(meta.cvss_vector).unwrap_or(0.0);
    writeln!(out, "CVSS: {} (score: {:.1})", meta.cvss_vector, cvss_score)?;
    Ok(())
}

pub fn write_score(score: &ScoreSummary) -> Result<()> {
    let mut out = io::stdout();
    writeln!(
        out,
        "Certificate: {} | Protocol: {} | Key Exchange: {} | Cipher: {}",
        score.certificate, score.protocol, score.key_exchange, score.cipher_strength
    )?;
    writeln!(out, "Overall: {} | Grade: {}", score.overall, score.grade)?;
    if !score.caps.is_empty() {
        writeln!(out, "Caps:")?;
        for c in &score.caps {
            writeln!(out, "- {}", c)?;
        }
    }
    Ok(())
}

pub fn write_benchmark(result: &BenchmarkResult) -> Result<()> {
    let mut out = io::stdout();
    writeln!(
        out,
        "Benchmark: {} => score={}",
        result.profile, result.score
    )?;
    if !result.failures.is_empty() {
        writeln!(out, "Failures:")?;
        for c in &result.failures {
            writeln!(out, "- {}", c)?;
        }
    }
    Ok(())
}

pub fn write_diff(diff: &DiffResult) -> Result<()> {
    let mut out = io::stdout();
    writeln!(out, "Added: {}", diff.added.len())?;
    for a in &diff.added {
        writeln!(out, "+ {}", a)?;
    }
    writeln!(out, "Removed: {}", diff.removed.len())?;
    for r in &diff.removed {
        writeln!(out, "- {}", r)?;
    }
    writeln!(out, "Changed: {}", diff.changed.len())?;
    for c in &diff.changed {
        writeln!(out, "* {}", c)?;
    }
    Ok(())
}
