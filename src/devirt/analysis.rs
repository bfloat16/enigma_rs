//! VM inspection without section-key search or configuration ABI tables.
use super::{
    codegen::Program,
    graph::Start,
    native,
    vm::{Profile, Tokens},
};
use crate::common::{
    io::{take, u16_at},
    pe::Pe,
};
use anyhow::{Context, Result, ensure};
use iced_x86::{Decoder, DecoderOptions, Formatter, IntelFormatter};
use std::{collections::BTreeMap, fmt::Write, sync::Arc};

pub struct Analysis {
    loader: Vec<u8>,
    header: Option<Vec<u8>>,
    profile: Arc<Profile>,
    output_rva: u32,
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

    pub fn devirtualize(&self, rva: u32) -> Result<X86> {
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
        Ok(X86 {
            source: rva,
            image_base: self.profile.base,
            rva: self.output_rva,
            program,
        })
    }
}

/// Generated i386 code at an analysis RVA, without modifying the input PE.
pub struct X86 {
    pub source: u32,
    pub image_base: u32,
    pub rva: u32,
    program: Program,
}

impl X86 {
    pub fn bytes(&self) -> &[u8] {
        &self.program.bytes
    }

    pub fn assembly(&self) -> Result<String> {
        let base = self
            .image_base
            .checked_add(self.rva)
            .context("x86 output VA overflow")?;
        let mut out = format!(
            "; vm_enter RVA: {:#010x}\n; image base: {:#010x}, generated code RVA: {:#010x}\n; Standalone analysis listing; external addresses still refer to the input image.\nBITS 32\nORG {base:#010x}\n\n",
            self.source, self.image_base, self.rva
        );
        let labels = self
            .program
            .entries
            .iter()
            .map(|(&start, &rva)| {
                let label = match start {
                    Start::Function(at) => format!("vm_{at:08x}"),
                    Start::Continuation(at) => format!("continuation_{at:08x}"),
                    Start::Code(at) => format!("bytecode_{at:08x}"),
                };
                (u64::from(self.image_base) + u64::from(rva), label)
            })
            .collect::<BTreeMap<_, _>>();
        let mut formatter = IntelFormatter::new();
        formatter.options_mut().set_hex_prefix("0x");
        formatter.options_mut().set_hex_suffix("");
        formatter.options_mut().set_uppercase_hex(false);
        let mut text = String::new();
        let mut decoder = Decoder::with_ip(
            32,
            &self.program.bytes,
            u64::from(base),
            DecoderOptions::NONE,
        );
        while decoder.can_decode() {
            let instruction = decoder.decode();
            ensure!(
                !instruction.is_invalid(),
                "invalid generated x86 at {:#x}",
                instruction.ip()
            );
            if let Some(label) = labels.get(&instruction.ip()) {
                writeln!(out, "{label}:")?;
            }
            text.clear();
            formatter.format(&instruction, &mut text);
            write!(out, "    {text:<48} ; {:08x}  ", instruction.ip())?;
            let offset = (instruction.ip() - u64::from(base)) as usize;
            for byte in &self.program.bytes[offset..offset + instruction.len()] {
                write!(out, "{byte:02x}")?;
            }
            out.push('\n');
        }
        if !self.program.relocations.is_empty() {
            out.push_str("\n; HIGHLOW fixup RVAs:");
            for rva in &self.program.relocations {
                write!(out, " {rva:#x}")?;
            }
            out.push('\n');
        }
        Ok(out)
    }
}
