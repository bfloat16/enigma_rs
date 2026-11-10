//! Architecture-specific static analysis and Enigma recovery.

mod analysis;
mod budget;
mod partition;
pub mod x64;
pub mod x86;

pub use analysis::{Analysis, Architecture, NativeCode};
