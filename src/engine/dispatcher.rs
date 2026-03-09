use crate::errors::Result;
use crate::models::{ScanResult, Target};
use crate::protocols::{rdp, ssh, tls};

#[derive(Clone)]
pub struct Dispatcher;

impl Dispatcher {
    pub fn new() -> Self {
        Self
    }

    pub async fn dispatch(&self, target: Target) -> Result<ScanResult> {
        let port = target.port;
        let scheme = target.scheme.clone().unwrap_or_default();
        if scheme.starts_with("ssh") || port == 22 {
            return ssh::probe(target).await;
        }
        if scheme.starts_with("rdp") || port == 3389 {
            return rdp::probe(target).await;
        }
        tls::probe(target).await
    }
}

impl Default for Dispatcher {
    fn default() -> Self {
        Self::new()
    }
}
