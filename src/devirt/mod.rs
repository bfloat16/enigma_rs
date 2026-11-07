//! Static x86 analysis and Enigma VM/template recovery.

mod analysis;
mod budget;
mod codegen;
mod demand;
mod graph;
mod ir;
mod lift;
mod loader;
pub(crate) mod native;
mod native_layout;
mod optimize;
mod partition;
pub(crate) mod static_x64;
pub(crate) mod static_x86;
mod switch;
pub mod vm;
pub(crate) mod x64;

pub use analysis::{Analysis, X86};
