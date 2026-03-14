use crate::errors::Result;
use crate::models::Target;
use serde_json::Value;
use std::fs;
use url::Url;

pub fn load_scan_json(path: &str) -> Result<Vec<Target>> {
    let data = fs::read_to_string(path)?;
    Ok(load_scan_json_from_str(&data))
}

pub fn looks_like_scan_json(data: &str) -> bool {
    let trimmed = data.trim_start();
    if trimmed.is_empty() {
        return false;
    }

    if trimmed.starts_with('[') {
        return serde_json::from_str::<Value>(trimmed)
            .ok()
            .and_then(|value| extract_targets_from_value(&value).ok())
            .map(|targets| !targets.is_empty())
            .unwrap_or(false);
    }

    let non_empty: Vec<&str> = data.lines().map(str::trim).filter(|line| !line.is_empty()).collect();
    if non_empty.is_empty() {
        return false;
    }

    non_empty.iter().all(|line| serde_json::from_str::<Value>(line).is_ok())
        && non_empty
            .iter()
            .filter_map(|line| serde_json::from_str::<Value>(line).ok())
            .any(|value| extract_target_from_value(&value).is_some())
}

fn load_scan_json_from_str(data: &str) -> Vec<Target> {
    let trimmed = data.trim_start();
    if trimmed.starts_with('[') {
        if let Ok(value) = serde_json::from_str::<Value>(trimmed) {
            return extract_targets_from_value(&value).unwrap_or_default();
        }
    }

    data.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter_map(|value| extract_target_from_value(&value))
        .collect()
}

fn extract_targets_from_value(value: &Value) -> Result<Vec<Target>> {
    let targets = match value {
        Value::Array(items) => items.iter().filter_map(extract_target_from_value).collect(),
        Value::Object(_) => extract_target_from_value(value).into_iter().collect(),
        _ => Vec::new(),
    };
    Ok(targets)
}

fn extract_target_from_value(value: &Value) -> Option<Target> {
    let obj = value.as_object()?;

    let port = ["port", "targetPort", "extracted_port"]
        .iter()
        .find_map(|key| value_as_u16(obj.get(*key)?));

    let host = ["host", "hostname", "fqdn", "targetHost", "ip", "ip-address"]
        .iter()
        .find_map(|key| value_as_string(obj.get(*key)?));

    if let (Some(host), Some(port)) = (host, port) {
        return Some(Target {
            raw: format!("{host}:{port}"),
            host,
            port,
            scheme: None,
        });
    }

    ["url", "matched-at", "matched", "target", "endpoint"]
        .iter()
        .find_map(|key| value_as_string(obj.get(*key)?))
        .and_then(|endpoint| parse_endpoint(&endpoint))
}

fn value_as_string(value: &Value) -> Option<String> {
    match value {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

fn value_as_u16(value: &Value) -> Option<u16> {
    match value {
        Value::Number(n) => n.as_u64().and_then(|v| u16::try_from(v).ok()),
        Value::String(s) => s.parse::<u16>().ok(),
        _ => None,
    }
}

fn parse_endpoint(endpoint: &str) -> Option<Target> {
    if let Ok(url) = Url::parse(endpoint) {
        let host = url.host_str()?.to_string();
        let port = url.port_or_known_default()?;
        return Some(Target {
            raw: endpoint.to_string(),
            host,
            port,
            scheme: Some(url.scheme().to_string()),
        });
    }

    let (host, port) = endpoint.rsplit_once(':')?;
    let port = port.parse::<u16>().ok()?;
    Some(Target {
        raw: endpoint.to_string(),
        host: host.to_string(),
        port,
        scheme: None,
    })
}

#[cfg(test)]
mod tests {
    use super::{extract_target_from_value, looks_like_scan_json};
    use serde_json::json;

    #[test]
    fn detects_nuclei_jsonl() {
        assert!(looks_like_scan_json(
            r#"{"host":"10.0.0.3","port":8443,"template-id":"ssl-tls"}"#
        ));
    }

    #[test]
    fn extracts_testssl_target() {
        let value = json!({
            "targetHost": "example.com",
            "ip": "203.0.113.10",
            "port": "443",
            "severity": "LOW",
            "finding": "TLS 1.0 offered"
        });
        let target = extract_target_from_value(&value).unwrap();
        assert_eq!(target.host, "example.com");
        assert_eq!(target.port, 443);
    }

    #[test]
    fn extracts_url_based_target() {
        let value = json!({
            "matched-at": "https://example.com:8443"
        });
        let target = extract_target_from_value(&value).unwrap();
        assert_eq!(target.host, "example.com");
        assert_eq!(target.port, 8443);
    }
}
