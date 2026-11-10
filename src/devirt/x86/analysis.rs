//! VM inspection without section-key search or configuration ABI tables.
use super::{
    graph::Start,
    native,
    vm::{Profile, Tokens},
};
use crate::common::{
    io::{take, u16_at},
    pe::Pe,
};
use crate::devirt::{Architecture, NativeCode};
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
    /// Accept a protected EXE or an extracted RVA-mapped
    /// runtime DLL. Stream RVAs use the packer's original host coordinates.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let pe = Pe::parse(bytes)?;
        ensure!(!pe.is_64, "VM analysis supports x86 only");
        let runtime = u16_at(bytes, pe.nt + 22)? & 0x2000 != 0 && Tokens::parse(bytes).is_ok();
        let loader = if runtime {
            bytes.to_vec()
        } else {
            crate::unpack::extract_runtime(&pe)?
        };
        let mut profile = Profile::parse(&Tokens::parse(&loader)?)?;
        if !runtime {
            let trampoline = profile
                .trampoline
                .checked_sub(profile.base)
                .context("invalid trampoline base")?;
            profile.base = pe.image_base.try_into()?;
            profile.trampoline = profile
                .base
                .checked_add(trampoline)
                .context("trampoline VA overflow")?;
        }
        let extent = profile
            .streams
            .iter()
            .map(|s| s.0)
            .max()
            .unwrap_or(0)
            .max(pe.image_size);
        let output_rva = extent
            .checked_add(0x1000)
            .context("analysis output RVA overflow")?
            & !0xfff;
        ensure!(
            profile.base.checked_add(output_rva).is_some(),
            "analysis output VA overflow"
        );
        Ok(Self {
            loader,
            header: if runtime {
                None
            } else {
                Some(take(bytes, 0, pe.headers_size as usize)?.to_vec())
            },
            profile: Arc::new(profile),
            output_rva,
        })
    }

    /// All registered template-VM enters, including Loader-internal functions.
    pub fn entries(&self) -> Vec<u32> {
        let mut entries = self.profile.streams.iter().map(|s| s.0).collect::<Vec<_>>();
        entries.sort_unstable();
        entries.dedup();
        entries
    }

    pub fn devirtualize(&self, rva: u32) -> Result<NativeCode> {
        ensure!(
            self.profile.streams.iter().any(|s| s.0 == rva),
            "RVA {rva:#x} is not a registered vm_enter; use --mode scan"
        );
        let program = native::compile(
            &self.loader,
            self.header.as_deref(),
            self.profile.clone(),
            &[rva],
            rva,
            self.profile.base,
            self.output_rva,
        )
        .with_context(|| format!("devirt vm_enter RVA {rva:#010x}"))?;
        let labels = program
            .entries
            .iter()
            .map(|(&start, &rva)| {
                let label = match start {
                    Start::Function(at) => format!("vm_{at:08x}"),
                    Start::Continuation(at) => format!("continuation_{at:08x}"),
                    Start::Code(at) => format!("bytecode_{at:08x}"),
                };
                (rva, label)
            })
            .collect();
        Ok(NativeCode {
            architecture: Architecture::X86,
            source: rva,
            image_base: u64::from(self.profile.base),
            rva: self.output_rva,
            code: program.bytes,
            labels,
            relocations: program.relocations,
        })
    }
}
