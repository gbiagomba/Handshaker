use crate::errors::{HandshakerError, Result};
use crate::findings::catalog;
use crate::models::{FindingInstance, Target};
use foreign_types_shared::ForeignTypeRef;
use openssl::ssl::{SslConnector, SslMethod, SslMode, SslVersion};
use openssl_sys;
use std::ffi::c_void;

extern "C" {
    fn SSL_get_current_compression(ssl: *const openssl_sys::SSL) -> *const c_void;
    // SSL_ctrl is the underlying mechanism for SSL_get_secure_renegotiation_support
    // which is a C macro: SSL_ctrl(ssl, SSL_CTRL_GET_RI_SUPPORT, 0, NULL)
    fn SSL_ctrl(ssl: *mut openssl_sys::SSL, cmd: i32, larg: i64, parg: *mut c_void) -> i64;
    fn SSL_get_early_data_status(ssl: *const openssl_sys::SSL) -> i32;
}

/// SSL_CTRL_GET_RI_SUPPORT = 76 (checks RFC 5746 secure renegotiation peer support)
const SSL_CTRL_GET_RI_SUPPORT: i32 = 76;

const SSL_EARLY_DATA_NOT_SENT: i32 = 0;
use tokio::task::spawn_blocking;

use super::starttls;

pub async fn check(target: &Target) -> Result<Vec<FindingInstance>> {
    let target = target.clone();
    spawn_blocking(move || check_blocking(&target))
        .await
        .unwrap_or_else(|e| Err(HandshakerError::Ssl(format!("join error: {e}"))))
}

fn check_blocking(target: &Target) -> Result<Vec<FindingInstance>> {
    let mut findings = Vec::new();

    let tls12 = supports_tls_version(target, SslVersion::TLS1_2)?;
    let tls10 = supports_tls_version(target, SslVersion::TLS1)?;
    if tls10 {
        push(
            &mut findings,
            "HS-TLS-SCENARIO-0002",
            "TLS 1.0 accepted (downgrade risk)",
        );
    }

    if tls12 && tls10 && !supports_fallback_scsv(target)? {
        push(
            &mut findings,
            "HS-TLS-SCENARIO-0001",
            "TLS_FALLBACK_SCSV not supported",
        );
    }

    if supports_cipher_list(target, "3DES")? {
        push(
            &mut findings,
            "HS-TLS-SCENARIO-0005",
            "3DES supported (SWEET32 indicator)",
        );
    }

    if supports_tls_version(target, SslVersion::TLS1)? && supports_cipher_list(target, "CBC")? {
        push(
            &mut findings,
            "HS-TLS-SCENARIO-0006",
            "TLS 1.0 + CBC (BEAST indicator)",
        );
        push(
            &mut findings,
            "HS-TLS-SCENARIO-0007",
            "Legacy fragmentation profile observed",
        );
    }

    if weak_cipher_preference(target)? {
        push(
            &mut findings,
            "HS-TLS-SCENARIO-0008",
            "Server prefers weak cipher",
        );
    }

    if let Some(bits) = dh_temp_bits(target)? {
        if bits < 2048 {
            push(&mut findings, "HS-TLS-SCENARIO-0004", "Weak DH parameters");
        }
    }

    if session_resumption_supported(target)? {
        push(
            &mut findings,
            "HS-TLS-SCENARIO-0003",
            "Session resumption observed; rotation not verified",
        );
    }

    if let Some(comp) = tls_compression_enabled(target)? {
        if comp {
            if let Some(meta) = catalog::find_by_id("HS-TLS-PROTOCOL-0009") {
                findings.push(build(meta, "TLS compression enabled".into()));
            }
        }
    }

    if let Some(supported) = secure_renegotiation_supported(target)? {
        if !supported {
            if let Some(meta) = catalog::find_by_id("HS-TLS-PROTOCOL-0008") {
                findings.push(build(meta, "secure renegotiation not supported".into()));
            }
            if let Some(meta) = catalog::find_by_id("HS-TLS-PROTOCOL-0007") {
                findings.push(build(meta, "insecure renegotiation likely allowed".into()));
            }
        }
    }

    if let Some(status) = starttls::check_downgrade(&target.host, target.port)? {
        if !status.advertised {
            push(
                &mut findings,
                "HS-TLS-SCENARIO-0010",
                "STARTTLS not advertised",
            );
        } else if status.cleartext_ok {
            push(
                &mut findings,
                "HS-TLS-SCENARIO-0011",
                "STARTTLS is optional and cleartext accepted",
            );
        }
    }

    if tls13_early_data_enabled(target)? {
        push(
            &mut findings,
            "HS-TLS-SCENARIO-0009",
            "TLS 1.3 early data enabled",
        );
    }

    Ok(findings)
}

fn supports_tls_version(target: &Target, version: SslVersion) -> Result<bool> {
    let mut builder =
        SslConnector::builder(SslMethod::tls()).map_err(|e| HandshakerError::Ssl(e.to_string()))?;
    builder.set_min_proto_version(Some(version)).ok();
    builder.set_max_proto_version(Some(version)).ok();
    Ok(crate::protocols::tls::starttls::connect(target, builder).is_ok())
}

fn supports_fallback_scsv(target: &Target) -> Result<bool> {
    let mut builder =
        SslConnector::builder(SslMethod::tls()).map_err(|e| HandshakerError::Ssl(e.to_string()))?;
    builder.set_min_proto_version(Some(SslVersion::TLS1)).ok();
    builder.set_max_proto_version(Some(SslVersion::TLS1)).ok();
    builder.set_mode(SslMode::SEND_FALLBACK_SCSV);
    Ok(crate::protocols::tls::starttls::connect(target, builder).is_err())
}

fn supports_cipher_list(target: &Target, cipher_list: &str) -> Result<bool> {
    let mut builder =
        SslConnector::builder(SslMethod::tls()).map_err(|e| HandshakerError::Ssl(e.to_string()))?;
    builder
        .set_cipher_list(cipher_list)
        .map_err(|e| HandshakerError::Ssl(e.to_string()))?;
    Ok(crate::protocols::tls::starttls::connect(target, builder).is_ok())
}

fn weak_cipher_preference(target: &Target) -> Result<bool> {
    let mut builder =
        SslConnector::builder(SslMethod::tls()).map_err(|e| HandshakerError::Ssl(e.to_string()))?;
    builder
        .set_cipher_list("ECDHE-RSA-AES256-GCM-SHA384:DES-CBC3-SHA")
        .map_err(|e| HandshakerError::Ssl(e.to_string()))?;
    let ssl = crate::protocols::tls::starttls::connect(target, builder)?;
    let cipher = ssl
        .ssl()
        .current_cipher()
        .map(|c| c.name().to_string())
        .unwrap_or_default();
    Ok(cipher.contains("3DES") || cipher.contains("DES-CBC"))
}

fn dh_temp_bits(target: &Target) -> Result<Option<u32>> {
    let mut builder =
        SslConnector::builder(SslMethod::tls()).map_err(|e| HandshakerError::Ssl(e.to_string()))?;
    builder.set_cipher_list("DHE:!aNULL").ok();
    let ssl = crate::protocols::tls::starttls::connect(target, builder)?;
    if let Ok(key) = ssl.ssl().tmp_key() {
        return Ok(Some(key.bits()));
    }
    Ok(None)
}

fn session_resumption_supported(target: &Target) -> Result<bool> {
    let connector =
        SslConnector::builder(SslMethod::tls()).map_err(|e| HandshakerError::Ssl(e.to_string()))?;
    let ssl1 = crate::protocols::tls::starttls::connect(target, connector)?;
    Ok(ssl1.ssl().session().is_some())
}

fn tls_compression_enabled(target: &Target) -> Result<Option<bool>> {
    let connector =
        SslConnector::builder(SslMethod::tls()).map_err(|e| HandshakerError::Ssl(e.to_string()))?;
    if let Ok(ssl) = crate::protocols::tls::starttls::connect(target, connector) {
        unsafe {
            let comp = SSL_get_current_compression(ssl.ssl().as_ptr());
            return Ok(Some(!comp.is_null()));
        }
    }
    Ok(None)
}

fn secure_renegotiation_supported(target: &Target) -> Result<Option<bool>> {
    let connector =
        SslConnector::builder(SslMethod::tls()).map_err(|e| HandshakerError::Ssl(e.to_string()))?;
    if let Ok(ssl) = crate::protocols::tls::starttls::connect(target, connector) {
        unsafe {
            // SSL_ctrl(ssl, SSL_CTRL_GET_RI_SUPPORT, 0, NULL) is the underlying call
            // for the C macro SSL_get_secure_renegotiation_support(ssl).
            // Returns 1 if the peer supports RFC 5746 secure renegotiation, 0 otherwise.
            let supported = SSL_ctrl(
                ssl.ssl().as_ptr() as *mut openssl_sys::SSL,
                SSL_CTRL_GET_RI_SUPPORT,
                0,
                std::ptr::null_mut(),
            );
            return Ok(Some(supported == 1));
        }
    }
    Ok(None)
}

fn tls13_early_data_enabled(target: &Target) -> Result<bool> {
    let mut builder =
        SslConnector::builder(SslMethod::tls()).map_err(|e| HandshakerError::Ssl(e.to_string()))?;
    builder.set_min_proto_version(Some(SslVersion::TLS1_3)).ok();
    builder.set_max_proto_version(Some(SslVersion::TLS1_3)).ok();
    if let Ok(ssl) = crate::protocols::tls::starttls::connect(target, builder) {
        unsafe {
            let status = SSL_get_early_data_status(ssl.ssl().as_ptr());
            return Ok(status != SSL_EARLY_DATA_NOT_SENT);
        }
    }
    Ok(false)
}

fn push(findings: &mut Vec<FindingInstance>, id: &str, details: &str) {
    if let Some(meta) = catalog::find_by_id(id) {
        findings.push(build(meta, details.to_string()));
    }
}

fn build(meta: &'static crate::findings::catalog::FindingMeta, details: String) -> FindingInstance {
    FindingInstance {
        id: meta.id.to_string(),
        title: meta.title.to_string(),
        protocol: meta.protocol,
        severity: meta.severity,
        details,
        cvss_vector: meta.cvss_vector.to_string(),
        cvss_score: crate::scoring::cvss::score(meta.cvss_vector).unwrap_or(0.0),
    }
}
