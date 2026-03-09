use crate::errors::{HandshakerError, Result};
use crate::models::Target;
use quick_xml::events::Event;
use quick_xml::Reader;
use std::fs::File;
use std::io::BufReader;

pub fn load_nmap_xml(path: &str) -> Result<Vec<Target>> {
    let file = File::open(path)?;
    let mut reader = Reader::from_reader(BufReader::new(file));
    reader.config_mut().trim_text(true);

    let mut buf = Vec::new();
    let mut current_host: Option<String> = None;
    let mut targets = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            // nmap uses self-closing <address .../> (Empty events) and sometimes <address ...>
            Ok(Event::Empty(ref e)) | Ok(Event::Start(ref e))
                if e.name().as_ref() == b"address" =>
            {
                let mut addr = None;
                let mut addrtype = None;
                for attr in e.attributes() {
                    let attr = attr.map_err(|e| HandshakerError::Parse(e.to_string()))?;
                    match attr.key.as_ref() {
                        b"addr" => addr = Some(String::from_utf8_lossy(&attr.value).to_string()),
                        b"addrtype" => {
                            addrtype = Some(String::from_utf8_lossy(&attr.value).to_string())
                        }
                        _ => {}
                    }
                }
                // Only use IPv4/IPv6 addresses, not MAC addresses
                let is_ip = addrtype
                    .as_deref()
                    .map(|t| t == "ipv4" || t == "ipv6")
                    .unwrap_or(true);
                if is_ip {
                    if let Some(a) = addr {
                        current_host = Some(a);
                    }
                }
            }
            // nmap uses self-closing <port .../> (Empty) or <port ...> (Start)
            Ok(Event::Empty(ref e)) | Ok(Event::Start(ref e))
                if e.name().as_ref() == b"port" =>
            {
                let mut port = None;
                for attr in e.attributes() {
                    let attr = attr.map_err(|e| HandshakerError::Parse(e.to_string()))?;
                    if attr.key.as_ref() == b"portid" {
                        port = Some(String::from_utf8_lossy(&attr.value).to_string());
                    }
                }
                if let (Some(host), Some(p)) = (current_host.clone(), port) {
                    if let Ok(port) = p.parse::<u16>() {
                        targets.push(Target {
                            raw: format!("{host}:{port}"),
                            host,
                            port,
                            scheme: None,
                        });
                    }
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => return Err(HandshakerError::Parse(e.to_string())),
            _ => {}
        }
        buf.clear();
    }
    Ok(targets)
}
