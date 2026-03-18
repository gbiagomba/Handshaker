use crate::errors::{HandshakerError, Result};
use openssl::ssl::{SslConnectorBuilder, SslStream};
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

#[derive(Debug, Clone, Copy)]
pub struct StarttlsStatus {
    pub advertised: bool,
    pub cleartext_ok: bool,
}

pub fn connect(
    target: &crate::models::Target,
    builder: SslConnectorBuilder,
) -> Result<SslStream<TcpStream>> {
    let addr = format!("{}:{}", target.host, target.port);
    let sock_addr = addr
        .to_socket_addrs()
        .map_err(|e| HandshakerError::Ssl(e.to_string()))?
        .next()
        .ok_or_else(|| HandshakerError::Ssl("DNS resolution failed".into()))?;
    let mut stream = TcpStream::connect_timeout(&sock_addr, Duration::from_secs(10))?;
    if requires_starttls(target.port) {
        perform_starttls(&mut stream, target.port)?;
    }
    let connector = builder.build();
    connector
        .connect(&target.host, stream)
        .map_err(|e| HandshakerError::Ssl(e.to_string()))
}

fn requires_starttls(port: u16) -> bool {
    matches!(port, 25 | 587 | 143 | 110 | 21 | 389)
}

pub fn check_downgrade(host: &str, port: u16) -> Result<Option<StarttlsStatus>> {
    if !requires_starttls(port) {
        return Ok(None);
    }
    let addr = format!("{host}:{port}");
    let sock_addr = addr
        .to_socket_addrs()
        .map_err(|e| HandshakerError::Ssl(e.to_string()))?
        .next()
        .ok_or_else(|| HandshakerError::Ssl("DNS resolution failed".into()))?;
    let mut stream = TcpStream::connect_timeout(&sock_addr, Duration::from_secs(10))?;
    let status = match port {
        25 | 587 => smtp_status(&mut stream)?,
        143 => imap_status(&mut stream)?,
        110 => pop3_status(&mut stream)?,
        21 => ftp_status(&mut stream)?,
        389 => ldap_status(&mut stream)?,
        _ => StarttlsStatus {
            advertised: false,
            cleartext_ok: false,
        },
    };
    Ok(Some(status))
}

fn perform_starttls(stream: &mut TcpStream, port: u16) -> Result<()> {
    match port {
        25 | 587 => smtp_starttls(stream),
        143 => imap_starttls(stream),
        110 => pop3_starttls(stream),
        21 => ftp_starttls(stream),
        389 => ldap_starttls(stream),
        _ => Ok(()),
    }
}

const MAX_LINE_BYTES: usize = 8192;

fn read_line(stream: &mut TcpStream) -> Result<String> {
    let mut buf = [0u8; 1];
    let mut out = Vec::new();
    loop {
        if out.len() >= MAX_LINE_BYTES {
            return Err(HandshakerError::Ssl("Server response line too long".into()));
        }
        let n = stream.read(&mut buf)?;
        if n == 0 {
            break;
        }
        out.push(buf[0]);
        if buf[0] == b'\n' {
            break;
        }
    }
    Ok(String::from_utf8_lossy(&out).to_string())
}

fn smtp_starttls(stream: &mut TcpStream) -> Result<()> {
    let _ = read_line(stream)?;
    stream.write_all(b"EHLO handshaker\r\n")?;
    loop {
        let line = read_line(stream)?;
        if !line.starts_with("250-") {
            break;
        }
    }
    stream.write_all(b"STARTTLS\r\n")?;
    let resp = read_line(stream)?;
    if !resp.starts_with("220") {
        return Err(HandshakerError::Ssl("SMTP STARTTLS failed".into()));
    }
    Ok(())
}

fn smtp_status(stream: &mut TcpStream) -> Result<StarttlsStatus> {
    let _ = read_line(stream)?;
    stream.write_all(b"EHLO handshaker\r\n")?;
    let mut advertised = false;
    loop {
        let line = read_line(stream)?;
        if line.to_ascii_uppercase().contains("STARTTLS") {
            advertised = true;
        }
        if !line.starts_with("250-") {
            break;
        }
    }
    stream.write_all(b"MAIL FROM:<test@example.com>\r\n")?;
    let resp = read_line(stream)?;
    let cleartext_ok = resp.starts_with("250");
    Ok(StarttlsStatus {
        advertised,
        cleartext_ok,
    })
}

fn imap_starttls(stream: &mut TcpStream) -> Result<()> {
    let _ = read_line(stream)?;
    stream.write_all(b"a STARTTLS\r\n")?;
    let resp = read_line(stream)?;
    if !resp.contains("OK") {
        return Err(HandshakerError::Ssl("IMAP STARTTLS failed".into()));
    }
    Ok(())
}

fn imap_status(stream: &mut TcpStream) -> Result<StarttlsStatus> {
    let _ = read_line(stream)?;
    stream.write_all(b"a CAPABILITY\r\n")?;
    let mut advertised = false;
    loop {
        let line = read_line(stream)?;
        if line.to_ascii_uppercase().contains("STARTTLS") {
            advertised = true;
        }
        if line.starts_with("a ") {
            break;
        }
    }
    stream.write_all(b"a LOGIN test test\r\n")?;
    let resp = read_line(stream)?;
    let cleartext_ok = resp.to_ascii_uppercase().contains("OK");
    Ok(StarttlsStatus {
        advertised,
        cleartext_ok,
    })
}

fn pop3_starttls(stream: &mut TcpStream) -> Result<()> {
    let resp = read_line(stream)?;
    if !resp.starts_with("+OK") {
        return Err(HandshakerError::Ssl("POP3 banner not OK".into()));
    }
    stream.write_all(b"STLS\r\n")?;
    let resp = read_line(stream)?;
    if !resp.starts_with("+OK") {
        return Err(HandshakerError::Ssl("POP3 STLS failed".into()));
    }
    Ok(())
}

fn pop3_status(stream: &mut TcpStream) -> Result<StarttlsStatus> {
    let resp = read_line(stream)?;
    if !resp.starts_with("+OK") {
        return Err(HandshakerError::Ssl("POP3 banner not OK".into()));
    }
    stream.write_all(b"CAPA\r\n")?;
    let mut advertised = false;
    loop {
        let line = read_line(stream)?;
        if line.to_ascii_uppercase().contains("STLS") {
            advertised = true;
        }
        if line.starts_with(".") {
            break;
        }
    }
    stream.write_all(b"USER test\r\n")?;
    let resp = read_line(stream)?;
    let cleartext_ok = resp.starts_with("+OK");
    Ok(StarttlsStatus {
        advertised,
        cleartext_ok,
    })
}

fn ftp_starttls(stream: &mut TcpStream) -> Result<()> {
    let resp = read_line(stream)?;
    if !resp.starts_with("220") {
        return Err(HandshakerError::Ssl("FTP banner not OK".into()));
    }
    stream.write_all(b"AUTH TLS\r\n")?;
    let resp = read_line(stream)?;
    if !resp.starts_with("234") {
        return Err(HandshakerError::Ssl("FTP AUTH TLS failed".into()));
    }
    Ok(())
}

fn ftp_status(stream: &mut TcpStream) -> Result<StarttlsStatus> {
    let resp = read_line(stream)?;
    if !resp.starts_with("220") {
        return Err(HandshakerError::Ssl("FTP banner not OK".into()));
    }
    stream.write_all(b"FEAT\r\n")?;
    let mut advertised = false;
    loop {
        let line = read_line(stream)?;
        if line.to_ascii_uppercase().contains("AUTH TLS") {
            advertised = true;
        }
        if line.starts_with("211") {
            break;
        }
    }
    stream.write_all(b"USER test\r\n")?;
    let resp = read_line(stream)?;
    let cleartext_ok = resp.starts_with("331") || resp.starts_with("230");
    Ok(StarttlsStatus {
        advertised,
        cleartext_ok,
    })
}

fn ldap_starttls(stream: &mut TcpStream) -> Result<()> {
    // Minimal LDAP StartTLS extended request (RFC 4511)
    let request: [u8; 31] = [
        0x30, 0x1c, // LDAPMessage sequence
        0x02, 0x01, 0x01, // messageID=1
        0x77, 0x17, // extendedRequest
        0x80, 0x15, // requestName
        0x31, 0x2e, 0x33, 0x2e, 0x36, 0x2e, 0x31, 0x2e, 0x34, 0x2e, 0x31, 0x2e, 0x31, 0x34, 0x36,
        0x36, 0x2e, 0x32, 0x30, 0x30, 0x33, 0x37,
    ];
    stream.write_all(&request)?;
    let mut buf = [0u8; 2];
    let _ = stream.read(&mut buf)?;
    Ok(())
}

fn ldap_status(_stream: &mut TcpStream) -> Result<StarttlsStatus> {
    Ok(StarttlsStatus {
        advertised: true,
        cleartext_ok: false,
    })
}
