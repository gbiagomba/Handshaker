use crate::errors::{HandshakerError, Result};
use crate::models::Target;
use url::Url;

pub fn parse_targets(input: &str, ports: &[u16]) -> Result<Vec<Target>> {
    let mut targets = Vec::new();
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Ok(targets);
    }

    if let Ok(url) = Url::parse(trimmed) {
        let host = url
            .host_str()
            .ok_or_else(|| HandshakerError::Parse("Missing host".into()))?;
        let port = url
            .port_or_known_default()
            .ok_or_else(|| HandshakerError::Parse("Missing port".into()))?;
        targets.push(Target {
            raw: trimmed.to_string(),
            host: host.to_string(),
            port,
            scheme: Some(url.scheme().to_string()),
        });
        return Ok(targets);
    }

    if let Some((host, port)) = split_host_port(trimmed) {
        let p = port
            .parse::<u16>()
            .map_err(|_| HandshakerError::Parse("Invalid port".into()))?;
        targets.push(Target {
            raw: trimmed.to_string(),
            host: host.to_string(),
            port: p,
            scheme: None,
        });
        return Ok(targets);
    }

    let ports = if ports.is_empty() {
        vec![443u16]
    } else {
        ports.to_vec()
    };
    for p in ports {
        targets.push(Target {
            raw: format!("{trimmed}:{p}"),
            host: trimmed.to_string(),
            port: p,
            scheme: None,
        });
    }
    Ok(targets)
}

fn split_host_port(s: &str) -> Option<(&str, &str)> {
    let (host, port) = s.rsplit_once(':')?;
    if host.is_empty() || port.is_empty() {
        return None;
    }
    Some((host, port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_plain_host_with_ports() {
        let out = parse_targets("example.com", &[443, 8443]).unwrap();
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].host, "example.com");
    }
}
