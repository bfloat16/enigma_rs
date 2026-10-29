use anyhow::{Context, Result, bail};
use indicatif::{ProgressBar, ProgressDrawTarget, ProgressStyle};

use super::extract::{StoredSection, verify_all};

pub const UINT32_END: u64 = 1u64 << 32;

type GpuSearch = fn(&[StoredSection], &StoredSection) -> Result<Option<u32>>;

#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum Mode {
    Cuda,
    Wgpu,
    Cpu,
}

pub(crate) fn progress(backend: &'static str, total: u64) -> ProgressBar {
    ProgressBar::with_draw_target(Some(total), ProgressDrawTarget::stderr_with_hz(10))
        .with_prefix(backend)
        .with_style(
            ProgressStyle::with_template(
                "{prefix} [{wide_bar:.cyan/blue}] {percent:>3}% {human_pos}/{human_len} {speed} ETA {eta_precise}",
            )
            .expect("static progress template")
            .with_key("speed", |state: &indicatif::ProgressState, out: &mut dyn std::fmt::Write| {
                let _ = write!(out, "{:.1}M/s", state.per_sec() / 1_000_000.0);
            })
            .progress_chars("=>-"),
        )
}

pub(crate) fn finish_progress(progress: &ProgressBar) {
    let seconds = progress.elapsed().as_secs_f64();
    let count = progress.position();
    progress.finish_and_clear();
    eprintln!(
        "{} search complete: {seconds:.3} s, {:.2}M candidates/s ({count} candidates)",
        progress.prefix(),
        count as f64 / seconds / 1_000_000.0,
    );
}

pub fn search(sections: &[StoredSection], mode: Option<Mode>) -> Result<Option<u32>> {
    if verify_all(sections, None).is_ok() {
        return Ok(None);
    }
    let screen = sections
        .iter()
        .filter(|s| s.descriptor.flags & 8 != 0 && !s.ciphertext.is_empty())
        .min_by_key(|s| s.ciphertext.len())
        .context("no nonempty RC4 section to search")?;

    let backends: &[(Mode, &str, GpuSearch)] = &[
        #[cfg(all(feature = "cuda", cuda_available))]
        (Mode::Cuda, "CUDA", super::cuda_search::search),
        #[cfg(feature = "wgpu")]
        (Mode::Wgpu, "WGPU", super::wgpu_search::search),
    ];
    for &(selected, backend, search) in backends {
        if mode.is_some_and(|m| m != selected) {
            continue;
        }
        // CubeCL also reports driver and shader compilation errors as panics.
        let result =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| search(sections, screen)));
        match result {
            Ok(Ok(salt)) => {
                return salt
                    .map(Some)
                    .context("no salt passed section verification");
            }
            Ok(Err(error)) => {
                if mode.is_some() {
                    return Err(error).with_context(|| format!("{backend} search failed"));
                }
                eprintln!("{backend} failed: {error:#}; trying next backend");
            }
            Err(_) => {
                if mode.is_some() {
                    bail!("{backend} driver failed");
                }
                eprintln!("{backend} driver failed; trying next backend");
            }
        }
    }
    if let Some(mode) = mode.filter(|m| *m != Mode::Cpu) {
        bail!("requested {mode:?} backend is not enabled in this build");
    }
    super::cpu_search::search(sections, screen).map(Some)
}
