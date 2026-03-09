use crate::errors::Result;
use crate::models::Target;
use std::io::{self, Read};

use super::target_parse::parse_targets;

pub fn load_stdin(ports: &[u16]) -> Result<Vec<Target>> {
    let mut buf = String::new();
    io::stdin().read_to_string(&mut buf)?;
    let mut targets = Vec::new();
    for line in buf.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        targets.extend(parse_targets(line, ports)?);
    }
    Ok(targets)
}
