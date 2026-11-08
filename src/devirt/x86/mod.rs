//! i386 token VM analysis, symbolic CFG recovery and native code generation.

mod analysis;
use super::{budget, partition};
mod codegen;
pub(crate) mod cpu;
mod demand;
mod graph;
mod ir;
mod lift;
mod loader;
mod memory;
pub(crate) mod native;
mod native_layout;
mod optimize;
mod switch;
pub mod vm;

pub use analysis::Analysis;
