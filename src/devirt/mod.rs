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
pub(crate) mod static_x86;
mod switch;
pub mod vm;

pub use analysis::{Analysis, X86};
