use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Protocol {
    Tls,
    Ssh,
    Rdp,
    General,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Severity::Info => "Info",
            Severity::Low => "Low",
            Severity::Medium => "Medium",
            Severity::High => "High",
            Severity::Critical => "Critical",
        };
        write!(f, "{s}")
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub id: &'static str,
    pub title: &'static str,
    pub protocol: Protocol,
    pub severity: Severity,
    pub description: &'static str,
    pub impact: &'static str,
    pub remediation: &'static str,
    pub references: &'static [&'static str],
    pub cvss_vector: &'static str,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Target {
    pub raw: String,
    pub host: String,
    pub port: u16,
    pub scheme: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingInstance {
    pub id: String,
    pub title: String,
    pub protocol: Protocol,
    pub severity: Severity,
    pub details: String,
    pub cvss_vector: String,
    pub cvss_score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub target: Target,
    pub findings: Vec<FindingInstance>,
    pub metadata: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoreSummary {
    pub certificate: u32,
    pub protocol: u32,
    pub key_exchange: u32,
    pub cipher_strength: u32,
    pub overall: u32,
    pub grade: String,
    pub caps: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CvssSummary {
    pub risk_max: f64,
    pub risk_weighted: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceResult {
    pub profile: String,
    pub compliant: bool,
    pub failed_controls: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkResult {
    pub profile: String,
    pub score: u32,
    pub failures: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffResult {
    pub added: Vec<String>,
    pub removed: Vec<String>,
    pub changed: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunSummary {
    pub run_id: String,
    pub started_at: DateTime<Utc>,
    pub targets: usize,
    pub findings: usize,
}
