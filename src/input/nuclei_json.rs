use crate::errors::Result;
use crate::models::Target;
use serde::Deserialize;
use std::fs::File;
use std::io::{BufRead, BufReader};

#[derive(Debug, Deserialize)]
struct NucleiLine {
    host: Option<String>,
    ip: Option<String>,
    port: Option<u16>,
}

pub fn load_nuclei_json(path: &str) -> Result<Vec<Target>> {
    let file = File::open(path)?;
    let mut targets = Vec::new();
    for line in BufReader::new(file).lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        if let Ok(entry) = serde_json::from_str::<NucleiLine>(&line) {
            let host = entry.host.or(entry.ip);
            if let (Some(h), Some(p)) = (host, entry.port) {
                targets.push(Target {
                    raw: format!("{h}:{p}"),
                    host: h,
                    port: p,
                    scheme: None,
                });
            }
        }
    }
    Ok(targets)
}
