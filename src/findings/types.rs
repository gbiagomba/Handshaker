use crate::models::{Protocol, Severity};

#[derive(Debug, Clone)]
pub struct FindingMeta {
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
