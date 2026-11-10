//! x64 VM inspection and native function recovery.
use super::{graph::Start, native, profile::Profile, runtime::Runtime};
use crate::{
    common::{
        io::{take, u16_at},
        pe::Pe,
    },
    devirt::{Architecture, NativeCode},
};
use anyhow::{Context, Result, ensure};
use std::sync::Arc;

pub struct Analysis {
    loader: Vec<u8>,
    header: Option<Vec<u8>>,
    profile: Arc<Profile>,
    output_rva: u32,
}

impl std::fmt::Debug for Analysis {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Analysis")
            .field("loader_len", &self.loader.len())
            .field("has_header", &self.header.is_some())
            .field("output_rva", &self.output_rva)
            .finish_non_exhaustive()
    }
}

impl Analysis {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let pe = Pe::parse(bytes)?;
        ensure!(pe.is_64, "expected x64 PE32+");
        let runtime = u16_at(bytes, pe.nt + 22)? & 0x2000 != 0 && Runtime::parse(bytes).is_ok();
        let loader = if runtime {
            bytes.to_vec()
        } else {
            crate::unpack::extract_runtime(&pe)?
        };
        let runtime_rva = if runtime {
            0
        } else {
            u64::from(crate::unpack::imports::engine_section(&pe, &loader)?.rva)
        };
        let profile = Arc::new(Profile::parse(&loader, pe.image_base, runtime_rva)?);
        let extent = profile
            .streams
            .iter()
            .map(|s| s.0)
            .max()
            .unwrap_or(0)
            .max(u64::from(pe.image_size));
        let output_rva = u32::try_from(
            extent
                .checked_add(0x1000)
                .context("analysis RVA overflow")?
                & !0xfff,
        )?;
        pe.image_base
            .checked_add(u64::from(output_rva))
            .context("x64 analysis VA overflow")?;
        Ok(Self {
            loader,
            header: if runtime {
                None
            } else {
                Some(take(bytes, 0, pe.headers_size as usize)?.to_vec())
            },
            profile,
            output_rva,
        })
    }

    pub fn entries(&self) -> Vec<u32> {
        let mut entries = self
            .profile
            .streams
            .iter()
            .map(|s| s.0 as u32)
            .collect::<Vec<_>>();
        entries.sort_unstable();
        entries.dedup();
        entries
    }

    pub fn devirtualize(&self, rva: u32) -> Result<NativeCode> {
        ensure!(
            self.profile.streams.iter().any(|s| s.0 == u64::from(rva)),
            "RVA {rva:#x} is not a registered vm_enter; use --mode scan"
        );
        let program = native::compile(
            &self.loader,
            self.header.as_deref(),
            self.profile.clone(),
            &[u64::from(rva)],
            u64::from(rva),
            self.profile.base,
            u64::from(self.output_rva),
        )
        .with_context(|| format!("devirt x64 vm_enter RVA {rva:#010x}"))?;
        let labels = program
            .entries
            .iter()
            .map(|(&start, &rva)| {
                let label = match start {
                    Start::Function(at) => format!("vm_{at:08x}"),
                    Start::Continuation(at) => format!("continuation_{at:08x}"),
                };
                Ok((u32::try_from(rva)?, label))
            })
            .collect::<Result<_>>()?;
        Ok(NativeCode {
            architecture: Architecture::X64,
            source: rva,
            image_base: self.profile.base,
            rva: self.output_rva,
            code: program.bytes,
            labels,
            relocations: program
                .relocations
                .into_iter()
                .map(u32::try_from)
                .collect::<std::result::Result<_, _>>()?,
        })
    }
}
