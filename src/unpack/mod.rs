//! Enigma Loader decoding, section recovery and executable reconstruction.

pub mod config;
pub mod cpu_search;
mod entry;
pub mod extract;
pub mod imports;
pub mod rebuild;
pub mod search;
mod task;
mod x64;
mod x86;

#[cfg(all(feature = "cuda", cuda_available))]
#[allow(unsafe_code)]
pub mod cuda_search;
#[cfg(any(all(feature = "cuda", cuda_available), feature = "wgpu"))]
#[allow(unsafe_code)]
pub mod gpu_kernel;
#[cfg(feature = "wgpu")]
pub mod wgpu_search;

pub use entry::extract_runtime;
pub use task::{Unpacked, run, run_runtime, unpack};
