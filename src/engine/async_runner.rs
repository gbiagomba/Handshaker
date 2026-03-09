use crate::errors::Result;
use crate::models::{ScanResult, Target};
use futures::stream::{self, StreamExt};
use tokio::time::{timeout, Duration};

pub struct AsyncRunner {
    concurrency: usize,
    timeout_secs: u64,
}

impl AsyncRunner {
    pub fn new(concurrency: usize, timeout_secs: u64) -> Self {
        Self {
            concurrency: concurrency.max(1),
            timeout_secs: timeout_secs.max(1),
        }
    }

    pub async fn run<F, Fut>(&self, targets: &[Target], f: F) -> Result<Vec<ScanResult>>
    where
        F: Fn(Target) -> Fut + Clone + Send + Sync + 'static,
        Fut: std::future::Future<Output = Result<ScanResult>> + Send,
    {
        let dur = Duration::from_secs(self.timeout_secs);
        let results = stream::iter(targets.to_vec())
            .map(|t| {
                let f = f.clone();
                async move {
                    let tclone = t.clone();
                    let res = timeout(dur, f(tclone.clone())).await;
                    (tclone, res)
                }
            })
            .buffer_unordered(self.concurrency)
            .collect::<Vec<_>>()
            .await;

        let mut out = Vec::new();
        for (target, res) in results {
            match res {
                Ok(Ok(scan)) => out.push(scan),
                Ok(Err(_e)) => {
                    out.push(error_result(target, "HS-GENERAL-CONFIG-0902", "scan error"));
                }
                Err(_elapsed) => {
                    out.push(error_result(
                        target,
                        "HS-GENERAL-CONFIG-0902",
                        "connection timeout",
                    ));
                }
            }
        }
        Ok(out)
    }
}

fn error_result(target: Target, id: &str, details: &str) -> ScanResult {
    let mut findings = Vec::new();
    if let Some(meta) = crate::findings::catalog::find_by_id(id) {
        findings.push(crate::models::FindingInstance {
            id: meta.id.to_string(),
            title: meta.title.to_string(),
            protocol: meta.protocol,
            severity: meta.severity,
            details: details.to_string(),
            cvss_vector: meta.cvss_vector.to_string(),
            cvss_score: crate::scoring::cvss::score(meta.cvss_vector).unwrap_or(0.0),
        });
    }
    ScanResult {
        target,
        findings,
        metadata: serde_json::json!({"protocol": "general"}),
    }
}
