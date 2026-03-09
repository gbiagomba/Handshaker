use crate::errors::Result;
use crate::models::Target;
use std::fs::File;
use std::io::{BufRead, BufReader};

pub fn load_gnmap(path: &str) -> Result<Vec<Target>> {
    let file = File::open(path)?;
    let mut targets = Vec::new();
    for line in BufReader::new(file).lines() {
        let line = line?;
        if !line.contains("Ports:") {
            continue;
        }
        if let Some(host) = extract_host(&line) {
            for port in extract_ports(&line) {
                targets.push(Target {
                    raw: format!("{host}:{port}"),
                    host: host.to_string(),
                    port,
                    scheme: None,
                });
            }
        }
    }
    Ok(targets)
}

fn extract_host(line: &str) -> Option<&str> {
    let token = "Host: ";
    let start = line.find(token)? + token.len();
    let rest = &line[start..];
    let end = rest.find(' ')?;
    Some(&rest[..end])
}

fn extract_ports(line: &str) -> Vec<u16> {
    let mut ports = Vec::new();
    if let Some(idx) = line.find("Ports:") {
        let rest = &line[idx + 6..];
        for part in rest.split(',') {
            let part = part.trim();
            if let Some(port_str) = part.split('/').next() {
                if let Ok(port) = port_str.trim().parse::<u16>() {
                    ports.push(port);
                }
            }
        }
    }
    ports
}
