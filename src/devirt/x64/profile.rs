//! Owned template metadata shared by x64 CFG recovery sessions.
use super::runtime::Runtime;
use anyhow::{Context, Result, ensure};
use iced_x86::{Decoder, DecoderOptions, FlowControl};
use std::collections::HashMap;

pub(crate) struct Profile {
    pub base: u64,
    pub runtime_rva: u64,
    pub streams: Vec<(u64, u64, usize)>,
    pub handlers: HashMap<u64, Vec<u8>>,
    pub patch: [u64; 12],
    pub dispatcher: Vec<u8>,
    pub decoder: u64,
}

impl Profile {
    pub fn parse(loader: &[u8], base: u64, runtime_rva: u64) -> Result<Self> {
        let runtime = Runtime::parse(loader)?;
        let last = Decoder::with_ip(64, &runtime.dispatcher, 0, DecoderOptions::NONE)
            .into_iter()
            .last()
            .context("empty x64 dispatcher")?;
        ensure!(
            last.flow_control() == FlowControl::UnconditionalBranch
                && last.near_branch64() < u64::from(runtime.patch[10]),
            "x64 continuation does not return to the decoder"
        );
        Ok(Self {
            base,
            runtime_rva,
            streams: runtime
                .streams
                .into_iter()
                .map(|(r, a, n)| (u64::from(r), u64::from(a), n))
                .collect(),
            handlers: runtime
                .handlers
                .into_iter()
                .map(|(k, v)| (u64::from(k), v))
                .collect(),
            patch: runtime.patch.map(u64::from),
            dispatcher: runtime.dispatcher,
            decoder: last.near_branch64(),
        })
    }
}
