//! Enigma Loader decoding, section recovery and executable reconstruction.

pub mod config;
pub mod cpu_search;
pub(crate) mod entry;
pub mod extract;
pub mod imports;
pub mod rebuild;
pub mod search;
mod task;

#[cfg(all(feature = "cuda", cuda_available))]
pub mod cuda_search;
#[cfg(any(all(feature = "cuda", cuda_available), feature = "wgpu"))]
pub mod gpu_kernel;
#[cfg(feature = "wgpu")]
pub mod wgpu_search;

pub use entry::extract_runtime;
pub use task::{Unpacked, run, run_runtime, unpack};
