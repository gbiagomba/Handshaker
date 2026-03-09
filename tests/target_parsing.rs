use handshaker::input::target_parse::parse_targets;

#[test]
fn parse_host_with_ports() {
    let targets = parse_targets("example.com", &[443, 8443]).unwrap();
    assert_eq!(targets.len(), 2);
    assert_eq!(targets[0].host, "example.com");
    assert_eq!(targets[0].port, 443);
    assert_eq!(targets[1].port, 8443);
}

#[test]
fn parse_url_with_explicit_port() {
    let targets = parse_targets("https://example.com:8443", &[]).unwrap();
    assert_eq!(targets.len(), 1);
    assert_eq!(targets[0].port, 8443);
    assert_eq!(targets[0].host, "example.com");
    assert_eq!(targets[0].scheme.as_deref(), Some("https"));
}

#[test]
fn parse_host_port_colon_format() {
    let targets = parse_targets("192.168.1.1:8080", &[]).unwrap();
    assert_eq!(targets.len(), 1);
    assert_eq!(targets[0].host, "192.168.1.1");
    assert_eq!(targets[0].port, 8080);
}

#[test]
fn parse_default_port_443() {
    let targets = parse_targets("example.com", &[]).unwrap();
    assert_eq!(targets.len(), 1);
    assert_eq!(targets[0].port, 443);
}

#[test]
fn parse_empty_returns_empty() {
    let targets = parse_targets("", &[443]).unwrap();
    assert!(targets.is_empty());
}

#[test]
fn parse_url_no_port_uses_scheme_default() {
    let targets = parse_targets("https://example.com", &[]).unwrap();
    assert_eq!(targets.len(), 1);
    assert_eq!(targets[0].port, 443);
}
