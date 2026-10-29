//! A shared wall-clock budget across recovery, optimization and emission.
use anyhow::{Context, Result, ensure};
use std::time::{Duration, Instant};

#[derive(Clone)]
pub(crate) struct Budget {
    started: Instant,
    limit: Duration,
}
impl Budget {
    pub fn new() -> Result<Self> {
        let seconds = match std::env::var("ENIGMA_DEVIRT_TIMEOUT_SECONDS") {
            Ok(value) => value
                .parse::<u64>()
                .context("ENIGMA_DEVIRT_TIMEOUT_SECONDS must be an integer")?,
            Err(std::env::VarError::NotPresent) => 60,
            Err(error) => return Err(error.into()),
        };
        ensure!(
            (1..=3600).contains(&seconds),
            "devirt timeout must be between 1 and 3600 seconds"
        );
        Ok(Self {
            started: Instant::now(),
            limit: Duration::from_secs(seconds),
        })
    }
    pub fn check(&self, stage: &str, detail: impl std::fmt::Display) -> Result<()> {
        let elapsed = self.started.elapsed();
        ensure!(
            elapsed < self.limit,
            "devirt timed out after {:.1}s (limit {}s), stage={stage}: {detail}",
            elapsed.as_secs_f64(),
            self.limit.as_secs()
        );
        Ok(())
    }
}
