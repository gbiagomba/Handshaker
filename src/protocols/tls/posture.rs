use serde::Serialize;

#[derive(Default, Serialize)]
pub struct TlsPosture {
    pub protocols_accepted: Vec<String>,
    pub protocols_rejected: Vec<String>,
    pub fallback_scsv: Option<bool>,
    pub secure_renegotiation: Option<bool>,
    pub compression: Option<bool>,
    pub cipher_categories: Vec<CipherCategory>,
    pub certificate: Option<CertSummary>,
    pub alpn_protocols: Vec<String>,
}

#[derive(Serialize)]
pub struct CipherCategory {
    pub name: String,
    pub accepted: bool,
}

#[derive(Serialize)]
pub struct CertSummary {
    pub subject: String,
    pub issuer: String,
    pub not_before: String,
    pub not_after: String,
    pub key_type: String,
    pub key_bits: u32,
    pub sig_algorithm: String,
    pub sans: Vec<String>,
}
