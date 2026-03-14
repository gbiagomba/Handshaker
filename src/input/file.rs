use crate::errors::Result;
use crate::models::Target;
use std::fs;

use super::{nmap_grep, nmap_xml, scan_json, target_parse::parse_targets};

pub fn load_file(path: &str, ports: &[u16]) -> Result<Vec<Target>> {
    let data = fs::read_to_string(path)?;
    match detect_kind(&data) {
        FileKind::NmapXml => nmap_xml::load_nmap_xml(path),
        FileKind::NmapGrep => nmap_grep::load_gnmap(path),
        FileKind::ScanJson => scan_json::load_scan_json(path),
        FileKind::Targets => load_plain_targets(&data, ports),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FileKind {
    Targets,
    NmapGrep,
    NmapXml,
    ScanJson,
}

fn detect_kind(data: &str) -> FileKind {
    let trimmed = data.trim_start();
    if trimmed.starts_with("<?xml") || trimmed.starts_with("<nmaprun") || trimmed.contains("<nmaprun")
    {
        return FileKind::NmapXml;
    }

    if data.lines().any(|line| {
        let line = line.trim_start();
        line.starts_with("Host: ") && line.contains("Ports:")
    }) {
        return FileKind::NmapGrep;
    }

    if scan_json::looks_like_scan_json(data) {
        return FileKind::ScanJson;
    }

    FileKind::Targets
}

fn load_plain_targets(data: &str, ports: &[u16]) -> Result<Vec<Target>> {
    let mut targets = Vec::new();
    for line in data.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        targets.extend(parse_targets(line, ports)?);
    }
    Ok(targets)
}

#[cfg(test)]
mod tests {
    use super::{detect_kind, FileKind};

    #[test]
    fn detects_nmap_xml() {
        assert_eq!(detect_kind("<nmaprun></nmaprun>"), FileKind::NmapXml);
    }

    #[test]
    fn detects_nmap_grep() {
        assert_eq!(
            detect_kind("Host: 127.0.0.1 ()\tPorts: 443/open/tcp////"),
            FileKind::NmapGrep
        );
    }

    #[test]
    fn detects_scan_json() {
        assert_eq!(
            detect_kind(r#"{"host":"example.com","port":443,"template-id":"ssl-tls"}"#),
            FileKind::ScanJson
        );
    }
}
