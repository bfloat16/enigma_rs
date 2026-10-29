//! Unpacking workflow and output handling for the command-line task.
use super::{config, extract, rebuild, search};
use crate::{
    common::{
        io::{check_new_directory, publish_directory, read_file, write_new_file},
        pe::Pe,
    },
    evb,
};
use anyhow::{Context, Result, ensure};
use std::path::Path;

pub struct Unpacked {
    pub executable: Vec<u8>,
    pub files: Vec<evb::File>,
}

/// Recover the executable and embedded virtual files without executing the input.
pub fn unpack(input: &[u8], mode: Option<search::Mode>) -> Result<Unpacked> {
    let pe = Pe::parse(input)?;
    ensure!(
        !pe.is_64,
        "unpacking supports the validated x86 Loader profile"
    );
    let config = config::parse(&pe)?;
    let ctx = config.ctx.as_ref().context("unknown ctx layout")?;
    let layout = config.layout.as_ref().context("unknown Loader layout")?;
    ensure!(
        ctx[layout.machine_suffix] == 0,
        "machine-dependent section key suffix is not supported"
    );
    // Release packed and expanded host sections before extracting EVB files.
    let executable = {
        let sections = extract::stored_sections(&pe, &config)?;
        let salt = search::search(&sections, mode)?;
        if let Some(salt) = salt {
            eprintln!("Salt: {salt:#010x}");
        }
        let recovered = extract::recover(&sections, salt)?;
        rebuild::rebuild(&pe, &config, &recovered)?
    };
    let files = evb::extract(&pe, &config)?;
    Ok(Unpacked { executable, files })
}

/// Run the file-based task, including CUDA runtime setup and EVB output checks.
pub fn run(input: &Path, mode: Option<search::Mode>) -> Result<()> {
    #[cfg(all(feature = "cuda", cuda_available))]
    if (mode.is_none() || mode == Some(search::Mode::Cuda))
        && let Some(status) = super::cuda_search::runtime_relaunch()?
    {
        std::process::exit(status.code().unwrap_or(1));
    }
    let directory = input.with_file_name("unpack");
    check_new_directory(&directory)?;
    let name = input.file_name().context("input has no file name")?;
    let bytes = read_file(input)?;
    let unpacked = unpack(&bytes, mode)?;
    publish_directory(&directory, |stage| {
        write_new_file(&stage.join(name), &unpacked.executable)?;
        for file in &unpacked.files {
            ensure!(
                file.path.to_string_lossy().to_lowercase() != name.to_string_lossy().to_lowercase(),
                "EVB file conflicts with output executable"
            );
            write_new_file(&stage.join(&file.path), &file.data)?;
        }
        Ok(())
    })?;
    eprintln!("Saved {}", directory.join(name).display());
    Ok(())
}

/// Extract only the runtime; no section-key search, VM compilation or EVB work.
pub fn run_runtime(input: &Path, target: Option<&Path>) -> Result<()> {
    let directory = input.with_file_name("unpack");
    if target.is_none() {
        check_new_directory(&directory)?;
    }
    let bytes = read_file(input)?;
    let runtime = super::extract_runtime(&Pe::parse(&bytes)?)?;
    let saved = if let Some(target) = target {
        write_new_file(target, &runtime)?;
        target.to_path_buf()
    } else {
        publish_directory(&directory, |stage| {
            write_new_file(&stage.join("runtime.dll"), &runtime)
        })?;
        directory.join("runtime.dll")
    };
    eprintln!("Saved {} ({} bytes)", saved.display(), runtime.len());
    Ok(())
}
