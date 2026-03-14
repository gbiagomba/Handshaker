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

pub fn write_manual(cmd: Option<&str>) -> Result<()> {
    let mut out = io::stdout();
    match cmd {
        None => {
            writeln!(out, "HANDSHAKER - Native secure-transport posture engine")?;
            writeln!(out)?;
            writeln!(out, "SUBCOMMANDS")?;
            writeln!(out, "  scan        Probe targets for TLS/SSH/RDP security posture")?;
            writeln!(out, "  explain     Print full explanation for a finding ID")?;
            writeln!(out, "  score       Compute SSL Labs-style scores from results JSON")?;
            writeln!(out, "  benchmark   Evaluate results against a benchmark profile")?;
            writeln!(out, "  diff        Compare two results files for changes")?;
            writeln!(out, "  ai          Run AI-powered analysis on results")?;
            writeln!(out, "  db          Manage the SQLite results database")?;
            writeln!(out)?;
            writeln!(out, "Use 'handshaker help <subcommand>' for detailed documentation.")?;
        }
        Some("scan") => {
            writeln!(out, "NAME")?;
            writeln!(out, "  handshaker scan -- probe targets for TLS/SSH/RDP security posture")?;
            writeln!(out)?;
            writeln!(out, "SYNOPSIS")?;
            writeln!(out, "  handshaker scan [OPTIONS]")?;
            writeln!(out)?;
            writeln!(out, "DESCRIPTION")?;
            writeln!(out, "  The scan command connects to one or more hosts and performs native")?;
            writeln!(out, "  protocol probing over TLS, STARTTLS, SSH, and RDP. It produces a")?;
            writeln!(out, "  structured findings list keyed by stable IDs (HS-*). Results can")?;
            writeln!(out, "  be written to multiple output formats and optionally persisted to")?;
            writeln!(out, "  a SQLite database for longitudinal tracking.")?;
            writeln!(out)?;
            writeln!(out, "OPTIONS")?;
            writeln!(out, "  -t, --target <HOST>        Single target: hostname, IP, host:port, or URL")?;
            writeln!(out, "  -f, --file <PATH>          File input: plain targets, nmap grep/XML, nuclei JSON(L), or testssl JSON")?;
            writeln!(out, "      --stdin                Read targets from stdin (one per line)")?;
            writeln!(out, "  -p, --ports <LIST>         Comma-separated ports (e.g. 443,8443,25)")?;
            writeln!(out, "      --output <FMT>         json|text|table|html|csv|sqlite  [default: json]")?;
            writeln!(out, "  -o, --out <PATH>           Write output to file instead of stdout")?;
            writeln!(out, "      --concurrency <N>      Max parallel scans  [default: 32]")?;
            writeln!(out, "      --timeout-secs <N>     Per-target timeout in seconds  [default: 10]")?;
            writeln!(out, "      --policy <PATH>        YAML policy file for compliance evaluation")?;
            writeln!(out, "      --fail-on-noncompliant Exit non-zero when any policy finding fails")?;
            writeln!(out, "      --benchmark <PATH>     YAML benchmark profile to evaluate against")?;
            writeln!(out, "      --db <PATH>            SQLite database path to persist results")?;
            writeln!(out)?;
            writeln!(out, "EXAMPLES")?;
            writeln!(out, "  # Scan a single HTTPS target and print JSON to stdout")?;
            writeln!(out, "  handshaker scan --target example.com --ports 443")?;
            writeln!(out)?;
            writeln!(out, "  # Scan a list of hosts and write HTML report")?;
            writeln!(out, "  handshaker scan --file hosts.txt --output html --out report.html")?;
            writeln!(out)?;
            writeln!(out, "  # Import targets from nmap XML and save to SQLite")?;
            writeln!(out, "  handshaker scan --file scan.xml --db results.db")?;
            writeln!(out)?;
            writeln!(out, "  # Import targets from nuclei JSONL")?;
            writeln!(out, "  handshaker scan --file nuclei.jsonl")?;
            writeln!(out)?;
            writeln!(out, "  # STARTTLS probe on SMTP port")?;
            writeln!(out, "  handshaker scan --target mail.example.com --ports 25,587")?;
            writeln!(out)?;
            writeln!(out, "  # Scan with compliance check; fail CI on violation")?;
            writeln!(out, "  handshaker scan --target example.com --policy pci.yaml --fail-on-noncompliant")?;
        }
        Some("explain") => {
            writeln!(out, "NAME")?;
            writeln!(out, "  handshaker explain -- print the full catalog entry for a finding ID")?;
            writeln!(out)?;
            writeln!(out, "SYNOPSIS")?;
            writeln!(out, "  handshaker explain <ID>")?;
            writeln!(out)?;
            writeln!(out, "DESCRIPTION")?;
            writeln!(out, "  Looks up a finding by its stable ID in the embedded catalog and prints")?;
            writeln!(out, "  the title, protocol, severity, description, impact, remediation steps,")?;
            writeln!(out, "  CVSS v3.1 vector with computed score, and reference links.")?;
            writeln!(out)?;
            writeln!(out, "OPTIONS")?;
            writeln!(out, "  <ID>  Finding ID (e.g. HS-TLS-PROTOCOL-0003)")?;
            writeln!(out)?;
            writeln!(out, "EXAMPLES")?;
            writeln!(out, "  handshaker explain HS-TLS-PROTOCOL-0003")?;
            writeln!(out, "  handshaker explain HS-SSH-HOSTKEY-0105")?;
            writeln!(out, "  handshaker explain HS-TLS-CIPHER-0001")?;
        }
        Some("score") => {
            writeln!(out, "NAME")?;
            writeln!(out, "  handshaker score -- compute SSL Labs-style scores from a results file")?;
            writeln!(out)?;
            writeln!(out, "SYNOPSIS")?;
            writeln!(out, "  handshaker score --input <PATH>")?;
            writeln!(out)?;
            writeln!(out, "DESCRIPTION")?;
            writeln!(out, "  Reads a JSON results file produced by 'handshaker scan' and computes")?;
            writeln!(out, "  SSL Labs-style category scores (Certificate, Protocol, Key Exchange,")?;
            writeln!(out, "  Cipher Strength) plus an overall grade (A+/A/B/C/D/F). Also prints")?;
            writeln!(out, "  CVSS-aligned configuration risk scores (max and weighted).")?;
            writeln!(out)?;
            writeln!(out, "OPTIONS")?;
            writeln!(out, "  --input <PATH>  Path to JSON results file")?;
            writeln!(out)?;
            writeln!(out, "EXAMPLES")?;
            writeln!(out, "  handshaker score --input results.json")?;
            writeln!(out, "  handshaker scan --target example.com | handshaker score --input /dev/stdin")?;
        }
        Some("benchmark") => {
            writeln!(out, "NAME")?;
            writeln!(out, "  handshaker benchmark -- evaluate results against a benchmark profile")?;
            writeln!(out)?;
            writeln!(out, "SYNOPSIS")?;
            writeln!(out, "  handshaker benchmark --input <PATH> --profile <PATH>")?;
            writeln!(out)?;
            writeln!(out, "DESCRIPTION")?;
            writeln!(out, "  Reads a JSON results file and a YAML benchmark profile, then evaluates")?;
            writeln!(out, "  each target against the profile's expected posture. Reports a pass/fail")?;
            writeln!(out, "  score and lists any controls that were not met.")?;
            writeln!(out)?;
            writeln!(out, "OPTIONS")?;
            writeln!(out, "  --input   <PATH>  Path to JSON results file")?;
            writeln!(out, "  --profile <PATH>  Path to YAML benchmark profile")?;
            writeln!(out)?;
            writeln!(out, "EXAMPLES")?;
            writeln!(out, "  handshaker benchmark --input results.json --profile default.yaml")?;
            writeln!(out, "  handshaker benchmark --input results.json --profile pci-dss.yaml")?;
        }
        Some("diff") => {
            writeln!(out, "NAME")?;
            writeln!(out, "  handshaker diff -- compare two results files and show changes")?;
            writeln!(out)?;
            writeln!(out, "SYNOPSIS")?;
            writeln!(out, "  handshaker diff --left <PATH> --right <PATH>")?;
            writeln!(out)?;
            writeln!(out, "DESCRIPTION")?;
            writeln!(out, "  Compares two JSON results files produced by 'handshaker scan' and")?;
            writeln!(out, "  reports findings that were added, removed, or changed between runs.")?;
            writeln!(out, "  Useful for tracking remediation progress or detecting regressions.")?;
            writeln!(out)?;
            writeln!(out, "OPTIONS")?;
            writeln!(out, "  --left  <PATH>  Baseline JSON results file")?;
            writeln!(out, "  --right <PATH>  New JSON results file to compare against baseline")?;
            writeln!(out)?;
            writeln!(out, "EXAMPLES")?;
            writeln!(out, "  # Compare before and after a remediation")?;
            writeln!(out, "  handshaker diff --left before.json --right after.json")?;
            writeln!(out)?;
            writeln!(out, "  # Track week-over-week changes")?;
            writeln!(out, "  handshaker diff --left week1.json --right week2.json")?;
        }
        Some("ai") => {
            writeln!(out, "NAME")?;
            writeln!(out, "  handshaker ai -- run AI-powered analysis on scan results")?;
            writeln!(out)?;
            writeln!(out, "SYNOPSIS")?;
            writeln!(out, "  handshaker ai --input <PATH> [--provider <NAME>]")?;
            writeln!(out)?;
            writeln!(out, "DESCRIPTION")?;
            writeln!(out, "  Sends redacted scan results to an LLM provider for automated")?;
            writeln!(out, "  security analysis and remediation guidance. Sensitive data such")?;
            writeln!(out, "  as hostnames and IPs is redacted before transmission. Uses the")?;
            writeln!(out, "  built-in provider by default; a custom provider name can be")?;
            writeln!(out, "  supplied to select an alternate backend.")?;
            writeln!(out)?;
            writeln!(out, "OPTIONS")?;
            writeln!(out, "  --input    <PATH>  Path to JSON results file")?;
            writeln!(out, "  --provider <NAME>  AI provider name (default: built-in)")?;
            writeln!(out)?;
            writeln!(out, "EXAMPLES")?;
            writeln!(out, "  handshaker ai --input results.json")?;
            writeln!(out, "  handshaker ai --input results.json --provider openai")?;
        }
        Some("db") => {
            writeln!(out, "NAME")?;
            writeln!(out, "  handshaker db -- manage the SQLite results database")?;
            writeln!(out)?;
            writeln!(out, "SYNOPSIS")?;
            writeln!(out, "  handshaker db <SUBCOMMAND>")?;
            writeln!(out)?;
            writeln!(out, "DESCRIPTION")?;
            writeln!(out, "  Provides subcommands for initializing, listing, and exporting")?;
            writeln!(out, "  scan runs stored in a SQLite database. Results are persisted")?;
            writeln!(out, "  via 'handshaker scan --db <PATH>' and queried here.")?;
            writeln!(out)?;
            writeln!(out, "SUBCOMMANDS")?;
            writeln!(out, "  init   --path <PATH>              Initialize a new database")?;
            writeln!(out, "  list   --path <PATH>              List all stored scan runs")?;
            writeln!(out, "  export --path <PATH> --run-id <ID>  Export a run as JSON")?;
            writeln!(out)?;
            writeln!(out, "EXAMPLES")?;
            writeln!(out, "  # Initialize a new database")?;
            writeln!(out, "  handshaker db init --path handshaker.db")?;
            writeln!(out)?;
            writeln!(out, "  # Store scan results")?;
            writeln!(out, "  handshaker scan --target example.com --db handshaker.db")?;
            writeln!(out)?;
            writeln!(out, "  # List all stored runs")?;
            writeln!(out, "  handshaker db list --path handshaker.db")?;
            writeln!(out)?;
            writeln!(out, "  # Export a specific run as JSON")?;
            writeln!(out, "  handshaker db export --path handshaker.db --run-id <RUN-ID>")?;
        }
        Some(unknown) => {
            writeln!(out, "Unknown command: '{}'. Try: scan, explain, score, benchmark, diff, ai, db", unknown)?;
        }
    }
    Ok(())
}
