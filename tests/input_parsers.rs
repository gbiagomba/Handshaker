use handshaker::input::target_parse::parse_targets;
use std::io::Write;
use tempfile::NamedTempFile;

fn write_temp(content: &str) -> NamedTempFile {
    let mut f = NamedTempFile::new().unwrap();
    f.write_all(content.as_bytes()).unwrap();
    f
}

#[test]
fn parse_url() {
    let out = parse_targets("https://example.com:8443", &[]).unwrap();
    assert_eq!(out[0].port, 8443);
}

#[test]
fn nmap_grep_parse() {
    let gnmap = "Host: 10.0.0.1 ()\tStatus: Up\nHost: 10.0.0.1 ()\tPorts: 443/open/tcp////\n";
    let f = write_temp(gnmap);
    let targets = handshaker::input::nmap_grep::load_gnmap(f.path().to_str().unwrap()).unwrap();
    assert_eq!(targets.len(), 1);
    assert_eq!(targets[0].host, "10.0.0.1");
    assert_eq!(targets[0].port, 443);
}

#[test]
fn nmap_xml_parse() {
    let xml = r#"<?xml version="1.0"?>
<nmaprun>
  <host><address addr="10.0.0.2" addrtype="ipv4"/>
    <ports><port protocol="tcp" portid="443"><state state="open"/></port></ports>
  </host>
</nmaprun>"#;
    let f = write_temp(xml);
    let targets = handshaker::input::nmap_xml::load_nmap_xml(f.path().to_str().unwrap()).unwrap();
    assert_eq!(targets.len(), 1);
    assert_eq!(targets[0].host, "10.0.0.2");
    assert_eq!(targets[0].port, 443);
}

#[test]
fn nuclei_json_parse() {
    let jsonl = r#"{"host":"10.0.0.3","port":8443,"template-id":"ssl-tls"}"#;
    let f = write_temp(jsonl);
    let targets =
        handshaker::input::nuclei_json::load_nuclei_json(f.path().to_str().unwrap()).unwrap();
    assert_eq!(targets.len(), 1);
    assert_eq!(targets[0].host, "10.0.0.3");
    assert_eq!(targets[0].port, 8443);
}

#[test]
fn file_input_parse() {
    let content = "# comment\nexample.com\n192.168.0.1:8443\n\nhttps://secure.example.com:443\n";
    let f = write_temp(content);
    let targets = handshaker::input::file::load_file(f.path().to_str().unwrap(), &[443]).unwrap();
    // example.com → port 443, 192.168.0.1:8443 → port 8443, https://secure.example.com:443 → port 443
    assert_eq!(targets.len(), 3);
}
