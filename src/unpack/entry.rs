//! Dispatch bootstrap recovery by the PE machine type.
use crate::common::{io::u16_at, pe::Pe};
use anyhow::{Context, Result, ensure};

pub(crate) struct Entry {
    pub loader: Option<Vec<u8>>,
    pub metadata: u32,
}

impl Entry {
    pub(super) fn parse(pe: &Pe<'_>) -> Result<Self> {
        if pe.is_64 {
            super::x64::entry::parse(pe)
        } else {
            super::x86::entry::parse(pe)
        }
    }
}

/// Extract the decoded RVA-mapped DLL without configuration-layout recovery.
pub fn extract_runtime(pe: &Pe<'_>) -> Result<Vec<u8>> {
    let runtime = Entry::parse(pe)?
        .loader
        .context("input contains no embedded runtime")?;
    let dll = Pe::parse(&runtime)?;
    ensure!(
        u16_at(&runtime, dll.nt + 22)? & 0x2000 != 0,
        "runtime has no DLL characteristic"
    );
    Ok(runtime)
}
