use crate::errors::{HandshakerError, Result};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Policy {
    pub name: String,
    pub forbidden_findings: Vec<String>,
}

pub fn load_policy(profile: &str) -> Result<Policy> {
    let path = format!("policies/{profile}.yml");
    let data = std::fs::read_to_string(&path)
        .map_err(|_| HandshakerError::Config(format!("Policy not found: {path}")))?;
    Ok(serde_yaml::from_str(&data)?)
}
