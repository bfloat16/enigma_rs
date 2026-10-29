//! CUDA device selection for the shared GPU salt search.
use super::{extract::StoredSection, gpu_kernel};
use anyhow::{Context, Result, ensure};
use cubecl::prelude::*;
use cubecl_cuda::{CudaDevice, CudaRuntime};
use std::{
    process::{Command, ExitStatus},
    sync::OnceLock,
};

pub type GpuProbe = gpu_kernel::GpuProbe<CudaRuntime>;

/// Relaunch once with process-local CUDA paths, before CubeCL loads libraries.
/// Setting LD_LIBRARY_PATH in a running Linux process does not update dlopen's
/// search path, so this also works for Linux without global environment edits.
pub fn runtime_relaunch() -> Result<Option<ExitStatus>> {
    let executable = std::env::current_exe()?;
    let directory = executable.parent().context("executable directory")?;
    let folder = format!("runtime/cuda-{}", env!("ENIGMA_CUDA_RELEASE"));
    let root = [
        directory.join(&folder),
        directory.parent().unwrap_or(directory).join(&folder),
    ]
    .into_iter()
    .find(|p| p.join("include/cuda_runtime.h").is_file());
    let Some(root) = root else {
        return Ok(None);
    };
    let root = root.canonicalize()?;
    if std::env::var_os("ENIGMA_CUDA_RUNTIME").is_some_and(|p| p == root.as_os_str()) {
        return Ok(None);
    }
    let library_path = if cfg!(windows) {
        "PATH"
    } else {
        "LD_LIBRARY_PATH"
    };
    let paths = std::iter::once(root.join("bin"))
        .chain(std::env::split_paths(
            &std::env::var_os(library_path).unwrap_or_default(),
        ))
        .collect::<Vec<_>>();
    let status = Command::new(executable)
        .args(std::env::args_os().skip(1))
        .env("CUDA_PATH", &root)
        .env("ENIGMA_CUDA_RUNTIME", &root)
        .env(library_path, std::env::join_paths(paths)?)
        .status()
        .context("launch with bundled CUDA runtime")?;
    Ok(Some(status))
}

pub fn probe(section: &StoredSection) -> Result<GpuProbe> {
    // Probe optional libraries before CubeCL's lazy loader can panic.
    ensure!(
        unsafe { cudarc::driver::sys::is_culib_present() },
        "CUDA driver library is unavailable"
    );
    ensure!(
        unsafe { cudarc::nvrtc::sys::is_culib_present() },
        "CUDA NVRTC library is unavailable; install CUDA Toolkit and add its libraries to the system search path"
    );
    let root =
        cubecl_cuda::install::cuda_path().context("CUDA Toolkit not found; set CUDA_PATH")?;
    ensure!(
        root.join("include/cuda_runtime.h").is_file(),
        "CUDA headers not found under {}; set CUDA_PATH to the CUDA Toolkit directory",
        root.display()
    );
    static CLIENT: OnceLock<ComputeClient<CudaRuntime>> = OnceLock::new();
    let client = CLIENT.get_or_init(|| {
        let device = CudaDevice::default();
        let client = CudaRuntime::client(&device);
        eprintln!("CUDA: device {}", device.index);
        client
    });
    GpuProbe::new(section, client.clone())
}

pub fn search(sections: &[StoredSection], screen: &StoredSection) -> Result<Option<u32>> {
    gpu_kernel::search("CUDA", sections, probe(screen)?)
}
