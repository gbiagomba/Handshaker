pub mod async_runner;
pub mod dispatcher;

use crate::errors::Result;
use crate::models::{ScanResult, Target};
use async_runner::AsyncRunner;
use dispatcher::Dispatcher;

pub struct Engine {
    dispatcher: Dispatcher,
    runner: AsyncRunner,
}

impl Engine {
    pub fn new(concurrency: usize, timeout_secs: u64) -> Self {
        Self {
            dispatcher: Dispatcher::new(),
            runner: AsyncRunner::new(concurrency, timeout_secs),
        }
    }

    pub async fn scan_targets(&self, targets: &[Target]) -> Result<Vec<ScanResult>> {
        let dispatcher = self.dispatcher.clone();
        self.runner
            .run(targets, move |t| {
                let dispatcher = dispatcher.clone();
                async move { dispatcher.dispatch(t).await }
            })
            .await
    }
}
