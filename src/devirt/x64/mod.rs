//! AMD64 static interpretation, symbolic VM recovery and native code generation.
mod analysis;
use super::{budget, partition};
mod codegen;
pub(crate) mod cpu;
mod demand;
mod graph;
mod ir;
mod lift;
mod native;
mod optimize;
mod profile;
pub(crate) mod runtime;
mod switch;

pub use analysis::Analysis;
