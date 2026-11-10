#![deny(unsafe_code)]

use std::{
    io::{self, Write},
    path::PathBuf,
};

use anyhow::{Context, Result, ensure};
use clap::{Parser, ValueEnum};
use enigma_rs::{
    common::io::{read_file, write_new_file},
    devirt::Analysis,
    unpack::{self, search::Mode as Backend},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum Mode {
    Unpack,
    Scan,
    Devirt,
    Runtime,
}

#[derive(Debug, Parser)]
#[command(version, about = "Static Enigma unpacking and VM analysis")]
struct Args {
    /// Protected EXE or extracted RVA-mapped runtime DLL.
    input: PathBuf,
    /// Hexadecimal vm_enter RVA (devirt only).
    rva: Option<String>,
    /// Operation; runtime extracts the decoded DLL, scan lists template-VM RVAs.
    #[arg(long, value_enum, default_value = "unpack")]
    mode: Mode,
    /// Output path: scan/devirt default to stdout; runtime to adjacent unpack/runtime.dll.
    #[arg(short, long)]
    output: Option<PathBuf>,
    /// Unpack search backend; omit to try CUDA, WGPU, then CPU.
    #[arg(long = "mod", value_enum)]
    backend: Option<Backend>,
}

impl Args {
    fn validate(&self) -> Result<Option<u32>> {
        if self.mode != Mode::Unpack {
            ensure!(self.backend.is_none(), "--mod requires --mode unpack");
        }
        match self.mode {
            Mode::Unpack => {
                ensure!(
                    self.rva.is_none() && self.output.is_none(),
                    "unpack takes only INPUT and writes to its adjacent unpack directory; -o is for scan/devirt/runtime"
                );
                Ok(None)
            }
            Mode::Scan | Mode::Runtime => {
                ensure!(
                    self.rva.is_none(),
                    "scan/runtime take only INPUT; use -o to select an output file"
                );
                Ok(None)
            }
            Mode::Devirt => {
                let value = self
                    .rva
                    .as_deref()
                    .context("devirt requires a hexadecimal RVA: INPUT --mode devirt 0xRVA")?;
                let value = value
                    .strip_prefix("0x")
                    .or_else(|| value.strip_prefix("0X"))
                    .unwrap_or(value);
                Ok(Some(
                    u32::from_str_radix(value, 16).context("invalid 32-bit hexadecimal RVA")?,
                ))
            }
        }
    }
}

fn main() -> Result<()> {
    let args = Args::parse();
    let rva = args.validate()?;
    match args.mode {
        Mode::Unpack => return unpack::run(&args.input, args.backend),
        Mode::Runtime => return unpack::run_runtime(&args.input, args.output.as_deref()),
        Mode::Scan | Mode::Devirt => {}
    }
    let bytes = read_file(&args.input)?;
    let analysis = Analysis::parse(&bytes)?;
    let output = if let Some(rva) = rva {
        let code = analysis.devirtualize(rva)?;
        eprintln!(
            "{}: {} bytes, image base={:#x}, code RVA={:#x}",
            code.architecture.name(),
            code.bytes().len(),
            code.image_base,
            code.rva
        );
        if args
            .output
            .as_ref()
            .and_then(|p| p.extension())
            .is_some_and(|ext| ext.eq_ignore_ascii_case("bin"))
        {
            code.bytes().to_vec()
        } else {
            code.assembly()?.into_bytes()
        }
    } else {
        analysis
            .entries()
            .iter()
            .map(|rva| format!("{rva:#010x}\n"))
            .collect::<String>()
            .into_bytes()
    };
    if let Some(path) = args.output {
        write_new_file(&path, &output)
    } else {
        match io::stdout().lock().write_all(&output) {
            Err(e) if e.kind() == io::ErrorKind::BrokenPipe => Ok(()),
            result => result.context("write analysis output"),
        }
    }
}

#[cfg(test)]
#[path = "../tests/main.rs"]
mod tests;
