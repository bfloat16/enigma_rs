//! Architecture dispatch and disassembly for recovered native code.
use super::{x64, x86};
use crate::common::pe::Pe;
use anyhow::{Context, Result, ensure};
use iced_x86::{Decoder, DecoderOptions, Formatter, IntelFormatter};
use std::{collections::BTreeMap, fmt::Write};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Architecture {
    X86,
    X64,
}

impl Architecture {
    pub fn name(self) -> &'static str {
        match self {
            Self::X86 => "x86",
            Self::X64 => "x64",
        }
    }

    pub fn bitness(self) -> u32 {
        match self {
            Self::X86 => 32,
            Self::X64 => 64,
        }
    }
}

pub enum Analysis {
    X86(x86::Analysis),
    X64(x64::Analysis),
}

impl Analysis {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if Pe::parse(bytes)?.is_64 {
            Ok(Self::X64(x64::Analysis::parse(bytes)?))
        } else {
            Ok(Self::X86(x86::Analysis::parse(bytes)?))
        }
    }

    pub fn entries(&self) -> Vec<u32> {
        match self {
            Self::X86(analysis) => analysis.entries(),
            Self::X64(analysis) => analysis.entries(),
        }
    }

    pub fn devirtualize(&self, rva: u32) -> Result<NativeCode> {
        match self {
            Self::X86(analysis) => analysis.devirtualize(rva),
            Self::X64(analysis) => analysis.devirtualize(rva),
        }
    }
}

/// Native code at an analysis RVA; external addresses refer to the input image.
pub struct NativeCode {
    pub architecture: Architecture,
    pub source: u32,
    pub image_base: u64,
    pub rva: u32,
    pub(crate) code: Vec<u8>,
    pub(crate) labels: BTreeMap<u32, String>,
    pub(crate) relocations: Vec<u32>,
}

impl NativeCode {
    pub fn bytes(&self) -> &[u8] {
        &self.code
    }

    pub fn assembly(&self) -> Result<String> {
        let base = self
            .image_base
            .checked_add(u64::from(self.rva))
            .context("native output VA overflow")?;
        let end = base
            .checked_add(self.code.len() as u64)
            .context("native output extent overflow")?;
        let bitness = self.architecture.bitness();
        ensure!(
            bitness == 64 || end <= 1 << 32,
            "x86 output exceeds 32-bit addresses"
        );
        let address_width = (bitness / 4) as usize;
        let hex_width = address_width + 2;
        let mut out = format!(
            "; vm_enter RVA: {:#010x}\n; image base: {:#0hex_width$x}, generated code RVA: {:#010x}\n; Standalone analysis listing; external addresses still refer to the input image.\nBITS {bitness}\nORG {base:#0hex_width$x}\n\n",
            self.source, self.image_base, self.rva
        );
        let mut formatter = IntelFormatter::new();
        formatter.options_mut().set_hex_prefix("0x");
        formatter.options_mut().set_hex_suffix("");
        formatter.options_mut().set_uppercase_hex(false);
        let mut text = String::new();
        let mut decoder = Decoder::with_ip(bitness, &self.code, base, DecoderOptions::NONE);
        while decoder.can_decode() {
            let instruction = decoder.decode();
            ensure!(
                !instruction.is_invalid(),
                "invalid generated {} at {:#x}",
                self.architecture.name(),
                instruction.ip()
            );
            let rva = u32::try_from(instruction.ip() - self.image_base)?;
            if let Some(label) = self.labels.get(&rva) {
                writeln!(out, "{label}:")?;
            }
            text.clear();
            formatter.format(&instruction, &mut text);
            write!(
                out,
                "    {text:<48} ; {:0address_width$x}  ",
                instruction.ip()
            )?;
            let offset = (instruction.ip() - base) as usize;
            for byte in &self.code[offset..offset + instruction.len()] {
                write!(out, "{byte:02x}")?;
            }
            out.push('\n');
        }
        if !self.relocations.is_empty() {
            let kind = match self.architecture {
                Architecture::X86 => "HIGHLOW",
                Architecture::X64 => "DIR64",
            };
            write!(out, "\n; {kind} fixup RVAs:")?;
            for rva in &self.relocations {
                write!(out, " {rva:#x}")?;
            }
            out.push('\n');
        }
        Ok(out)
    }
}

#[cfg(test)]
#[path = "../../test/devirt/analysis.rs"]
mod tests;
