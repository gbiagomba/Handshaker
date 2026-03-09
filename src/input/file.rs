use crate::errors::Result;
use crate::models::Target;
use std::fs::File;
use std::io::{BufRead, BufReader};

use super::target_parse::parse_targets;

pub fn load_file(path: &str, ports: &[u16]) -> Result<Vec<Target>> {
    let file = File::open(path)?;
    let mut targets = Vec::new();
    for line in BufReader::new(file).lines() {
        let line = line?;
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        targets.extend(parse_targets(line, ports)?);
    }
    Ok(targets)
}
