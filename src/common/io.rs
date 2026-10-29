//! Checked binary access and filesystem reads/writes.
use anyhow::{Context, Result, bail};
use std::{
    ffi::OsString,
    fs,
    io::{ErrorKind, Write},
    path::Path,
};

pub fn take(data: &[u8], offset: usize, size: usize) -> Result<&[u8]> {
    let end = offset.checked_add(size).context("offset overflow")?;
    data.get(offset..end).with_context(|| {
        format!(
            "out of bounds: offset={offset:#x}, size={size:#x}, total={:#x}",
            data.len()
        )
    })
}

pub fn u16_at(data: &[u8], offset: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(take(data, offset, 2)?.try_into()?))
}

pub fn u32_at(data: &[u8], offset: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(take(data, offset, 4)?.try_into()?))
}

pub fn u64_at(data: &[u8], offset: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(take(data, offset, 8)?.try_into()?))
}

pub fn put_u32_at(data: &mut [u8], offset: usize, value: u32) -> Result<()> {
    let end = offset.checked_add(4).context("offset overflow")?;
    data.get_mut(offset..end)
        .context("write outside buffer")?
        .copy_from_slice(&value.to_le_bytes());
    Ok(())
}

pub fn read_file(path: &Path) -> Result<Vec<u8>> {
    fs::read(path).with_context(|| format!("read {}", path.display()))
}

pub fn write_new_file(path: &Path, data: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent)
            .with_context(|| format!("create directory {}", parent.display()))?;
    }
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?
        .write_all(data)
        .with_context(|| format!("write {}", path.display()))
}

pub fn check_new_directory(directory: &Path) -> Result<()> {
    match fs::symlink_metadata(directory) {
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("inspect {}", directory.display())),
        Ok(_) => bail!(
            "output directory already exists; preserved: {}",
            directory.display()
        ),
    }
}

/// Write into a fresh sibling directory, then publish it without merging results.
/// The callback owns file layout; failures clean only our newly created staging directory.
pub fn publish_directory(directory: &Path, write: impl FnOnce(&Path) -> Result<()>) -> Result<()> {
    check_new_directory(directory)?;
    let name = directory
        .file_name()
        .context("output directory has no name")?;
    let mut stage_name = OsString::from(".");
    stage_name.push(name);
    stage_name.push(format!("-{}.tmp", std::process::id()));
    let stage = directory.with_file_name(stage_name);
    fs::create_dir(&stage)
        .with_context(|| format!("create staging directory {}", stage.display()))?;
    let result = (|| {
        write(&stage)?;
        check_new_directory(directory)?;
        fs::rename(&stage, directory).with_context(|| format!("publish {}", directory.display()))
    })();
    if result.is_err()
        && let Err(error) = fs::remove_dir_all(&stage)
    {
        eprintln!(
            "Could not remove staging directory {}: {error}",
            stage.display()
        );
    }
    result
}

#[cfg(test)]
#[path = "../../test/output.rs"]
mod tests;
