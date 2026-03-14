use handshaker::cli::{OutputFormat, ScanArgs};
use handshaker::input::{file, load_targets, nmap_grep, nmap_xml, scan_json, target_parse};
use std::io::Write;
use tempfile::NamedTempFile;

fn write_temp(content: &str) -> NamedTempFile {
    let mut f = NamedTempFile::new().unwrap();
    f.write_all(content.as_bytes()).unwrap();
    f
}

fn empty_scan_args() -> ScanArgs {
    ScanArgs {
        target: None,
        file: None,
        stdin: false,
        ports: vec![],
        output: OutputFormat::Json,
        out: None,
        concurrency: 32,
        timeout_secs: 10,
        policy: None,
        fail_on_noncompliant: false,
        benchmark: None,
        db: None,
    }
}

#[test]
fn parse_ipv6_url_target() {
    let out = target_parse::parse_targets("https://[2001:db8::1]:8443", &[]).unwrap();
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].host, "[2001:db8::1]");
    assert_eq!(out[0].port, 8443);
}

#[test]
fn parse_invalid_port_returns_error() {
    assert!(target_parse::parse_targets("example.com:notaport", &[]).is_err());
}

#[test]
fn file_plain_target_defaults_to_443() {
    let f = write_temp("example.org\n");
    let targets = file::load_file(f.path().to_str().unwrap(), &[]).unwrap();
    assert_eq!(targets.len(), 1);
    assert_eq!(targets[0].port, 443);
}

#[test]
fn nmap_grep_parses_multiple_ports() {
    let gnmap = "Host: 10.0.0.9 ()\tPorts: 22/open/tcp////, 443/open/tcp////, 8443/open/tcp////\n";
    let f = write_temp(gnmap);
    let targets = nmap_grep::load_gnmap(f.path().to_str().unwrap()).unwrap();
    assert_eq!(targets.len(), 3);
    assert_eq!(targets[0].port, 22);
    assert_eq!(targets[2].port, 8443);
}

#[test]
fn nmap_xml_ignores_mac_addresses() {
    let xml = r#"<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="00:11:22:33:44:55" addrtype="mac"/>
    <address addr="10.0.0.8" addrtype="ipv4"/>
    <ports><port protocol="tcp" portid="443"><state state="open"/></port></ports>
  </host>
</nmaprun>"#;
    let f = write_temp(xml);
    let targets = nmap_xml::load_nmap_xml(f.path().to_str().unwrap()).unwrap();
    assert_eq!(targets.len(), 1);
    assert_eq!(targets[0].host, "10.0.0.8");
}

#[test]
fn scan_json_parses_array_payload() {
    let f = write_temp(
        r#"[{"host":"array.example","port":443},{"matched-at":"https://two.example:8443"}]"#,
    );
    let targets = scan_json::load_scan_json(f.path().to_str().unwrap()).unwrap();
    assert_eq!(targets.len(), 2);
    assert_eq!(targets[0].host, "array.example");
    assert_eq!(targets[1].port, 8443);
}

#[test]
fn scan_json_prefers_hostname_over_ip() {
    let f = write_temp(r#"{"host":"named.example","ip":"203.0.113.4","port":443}"#);
    let targets = scan_json::load_scan_json(f.path().to_str().unwrap()).unwrap();
    assert_eq!(targets.len(), 1);
    assert_eq!(targets[0].host, "named.example");
}

#[test]
fn scan_json_ignores_malformed_lines() {
    let f = write_temp(
        "{\"host\":\"good.example\",\"port\":443}\nnot-json\n{\"host\":\"also.good\",\"port\":8443}\n",
    );
    let targets = scan_json::load_scan_json(f.path().to_str().unwrap()).unwrap();
    assert_eq!(targets.len(), 2);
}

#[test]
fn file_autodetects_json_array_targets() {
    let f = write_temp(r#"[{"host":"json-array.example","port":443}]"#);
    let targets = file::load_file(f.path().to_str().unwrap(), &[]).unwrap();
    assert_eq!(targets.len(), 1);
    assert_eq!(targets[0].host, "json-array.example");
}

#[test]
fn load_targets_combines_direct_target_and_file() {
    let f = write_temp("file.example\n");
    let mut args = empty_scan_args();
    args.target = Some("cli.example".into());
    args.file = Some(f.path().to_str().unwrap().to_string());
    let targets = load_targets(&args).unwrap();
    assert_eq!(targets.len(), 2);
    assert_eq!(targets[0].host, "cli.example");
    assert_eq!(targets[1].host, "file.example");
}
