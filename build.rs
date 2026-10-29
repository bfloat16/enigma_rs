use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    env, fs,
    io::{Read, Write},
    path::{Component, Path, PathBuf},
    process::Command,
};

const NVIDIA: &str = "https://developer.download.nvidia.com/compute/cuda/redist/";
const MAX_CUDA: (u32, u32) = (13, 4);

fn main() {
    println!("cargo::rustc-check-cfg=cfg(cuda_available)");
    println!("cargo::rerun-if-changed=build.rs");
    println!("cargo::rerun-if-env-changed=ENIGMA_CUDA");
    println!("cargo::rerun-if-env-changed=PATH");
    if env::var_os("CARGO_FEATURE_CUDA").is_none()
        || env::var("ENIGMA_CUDA").is_ok_and(|v| v == "0")
    {
        return;
    }
    match prepare() {
        Ok(Some(release)) => {
            println!("cargo::rustc-cfg=cuda_available");
            println!("cargo::rustc-env=ENIGMA_CUDA_RELEASE={release}");
            println!("cargo::warning=CUDA {release} prepared in runtime/cuda-{release}");
        }
        Ok(None) => println!("cargo::warning=No supported local NVIDIA GPU; skipping CUDA setup"),
        Err(error) => println!("cargo::warning=CUDA setup failed: {error:#}; using WGPU/CPU"),
    }
}

fn version(text: &str) -> Option<(u32, u32, u32)> {
    let mut parts = text.split('.');
    let result = (
        parts.next()?.parse().ok()?,
        parts.next()?.parse().ok()?,
        parts.next().unwrap_or("0").parse().ok()?,
    );
    parts.next().is_none().then_some(result)
}

fn driver_limit(text: &str) -> Option<(u32, u32)> {
    let text = text
        .split_once("CUDA Version:")
        .or_else(|| text.split_once("CUDA UMD Version:"))?
        .1
        .split_whitespace()
        .next()?;
    let (major, minor, _) = version(text)?;
    Some((major, minor))
}

fn select_release(index: &str, limit: (u32, u32)) -> Option<String> {
    index
        .split("redistrib_")
        .skip(1)
        .filter_map(|s| s.split_once(".json").map(|(s, _)| s))
        .filter_map(|s| version(s).map(|v| (v, s)))
        .filter(|(v, _)| (v.0, v.1) <= limit && v.0 >= 12)
        .max_by_key(|(v, _)| *v)
        .map(|(_, label)| label.to_owned())
}

fn download(url: &str, output: &Path) -> Result<()> {
    let partial = output.with_extension("part");
    let result = Command::new("curl")
        .args([
            "--fail",
            "--location",
            "--silent",
            "--show-error",
            "--retry",
            "2",
        ])
        .args(["--connect-timeout", "20", "--max-time", "900", "--output"])
        .arg(&partial)
        .arg(url)
        .status()
        .context("run curl (required for CUDA downloads)")?;
    ensure!(result.success(), "download {url}");
    fs::rename(partial, output)?;
    Ok(())
}

fn checksum(path: &Path) -> Result<String> {
    let mut hash = Sha256::new();
    let mut file = fs::File::open(path)?;
    let mut buffer = [0; 65536];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
    }
    Ok(format!("{:x}", hash.finalize()))
}

fn package(cache: &Path, metadata: &Value) -> Result<PathBuf> {
    let relative = metadata["relative_path"]
        .as_str()
        .context("missing package URL")?;
    ensure!(
        !relative.starts_with('/')
            && !relative.contains("..")
            && !relative.contains(':')
            && !relative.contains('\\'),
        "invalid NVIDIA package path"
    );
    let expected = metadata["sha256"]
        .as_str()
        .context("missing package SHA256")?;
    let name = Path::new(relative)
        .file_name()
        .context("missing package filename")?;
    let cached = cache.join(name);
    // Reuse an official archive already downloaded by the user, after hashing.
    let downloads = env::var_os("USERPROFILE")
        .or_else(|| env::var_os("HOME"))
        .map(|p| PathBuf::from(p).join("Downloads").join(name));
    for candidate in std::iter::once(Some(cached.clone()))
        .chain(std::iter::once(downloads))
        .flatten()
    {
        if candidate.is_file() && checksum(&candidate)? == expected {
            return Ok(candidate);
        }
    }
    println!("cargo::warning=Downloading CUDA component {relative}");
    download(&format!("{NVIDIA}{relative}"), &cached)?;
    ensure!(
        checksum(&cached)? == expected,
        "SHA256 mismatch: {}",
        cached.display()
    );
    Ok(cached)
}

fn destination(package: &str, archive_path: &Path) -> Result<Option<PathBuf>> {
    ensure!(
        archive_path
            .components()
            .all(|c| matches!(c, Component::Normal(_))),
        "unsafe CUDA archive path: {}",
        archive_path.display()
    );
    let relative: PathBuf = archive_path.components().skip(1).collect();
    let parts: Vec<_> = relative.components().collect();
    if parts.is_empty() {
        return Ok(None);
    }
    let name = relative.file_name().unwrap().to_string_lossy();
    if name.to_ascii_uppercase().starts_with("LICENSE") {
        return Ok(Some(
            PathBuf::from("licenses").join(package).join(name.as_ref()),
        ));
    }
    if parts[0].as_os_str() == "include" {
        return Ok(Some(if package == "cccl" || package == "cuda_cccl" {
            PathBuf::from("include/cccl").join(relative.strip_prefix("include")?)
        } else {
            relative
        }));
    }
    // Only NVRTC and builtins are needed. Never bundle the NVIDIA driver.
    if package == "cuda_nvrtc"
        && name.contains("nvrtc")
        && (name.ends_with(".dll") || name.contains(".so"))
    {
        return Ok(Some(PathBuf::from("bin").join(name.as_ref())));
    }
    Ok(None)
}

fn unpack(package: &str, archive: &Path, root: &Path) -> Result<()> {
    if archive.extension().is_some_and(|s| s == "zip") {
        let mut zip = zip::ZipArchive::new(fs::File::open(archive)?)?;
        for i in 0..zip.len() {
            let mut entry = zip.by_index(i)?;
            if entry.is_dir() {
                continue;
            }
            let path = entry.enclosed_name().context("unsafe ZIP entry")?;
            if let Some(relative) = destination(package, &path)? {
                let target = root.join(relative);
                fs::create_dir_all(target.parent().unwrap())?;
                std::io::copy(&mut entry, &mut fs::File::create(target)?)?;
            }
        }
    } else {
        let reader = lzma_rust2::XzReader::new(fs::File::open(archive)?, false);
        let mut tar = tar::Archive::new(reader);
        for entry in tar.entries()? {
            let mut entry = entry?;
            let kind = entry.header().entry_type();
            if !kind.is_file() && !kind.is_symlink() {
                continue;
            }
            let path = entry.path()?.into_owned();
            if let Some(relative) = destination(package, &path)? {
                let target = root.join(relative);
                fs::create_dir_all(target.parent().unwrap())?;
                if kind.is_file() {
                    std::io::copy(&mut entry, &mut fs::File::create(target)?)?;
                } else {
                    let link = entry.link_name()?.context("missing CUDA symlink target")?;
                    ensure!(
                        link.components().all(|c| matches!(c, Component::Normal(_))),
                        "unsafe CUDA symlink"
                    );
                    #[cfg(unix)]
                    {
                        if target.symlink_metadata().is_ok() {
                            fs::remove_file(&target)?;
                        }
                        std::os::unix::fs::symlink(link.as_ref(), target)?;
                    }
                    #[cfg(not(unix))]
                    anyhow::bail!("cross-platform CUDA archive extraction is unsupported");
                }
            }
        }
    }
    Ok(())
}

fn prepare() -> Result<Option<String>> {
    if env::var("HOST")? != env::var("TARGET")? {
        return Ok(None);
    }
    let platform = match (
        env::var("CARGO_CFG_TARGET_OS")?.as_str(),
        env::var("CARGO_CFG_TARGET_ARCH")?.as_str(),
    ) {
        ("windows", "x86_64") => "windows-x86_64",
        ("linux", "x86_64") => "linux-x86_64",
        ("linux", "aarch64") => "linux-sbsa",
        _ => return Ok(None),
    };
    let Ok(smi) = Command::new("nvidia-smi").output() else {
        return Ok(None);
    };
    if !smi.status.success() {
        return Ok(None);
    }
    let Some(limit) = driver_limit(&String::from_utf8_lossy(&smi.stdout)) else {
        return Ok(None);
    };
    let limit = limit.min(MAX_CUDA);
    if limit.0 < 12 {
        return Ok(None);
    }
    let driver_file = if cfg!(windows) {
        PathBuf::from(env::var_os("SystemRoot").unwrap_or("C:/Windows".into()))
            .join("System32/nvcuda.dll")
    } else {
        PathBuf::from("/proc/driver/nvidia/version")
    };
    if driver_file.exists() {
        println!("cargo::rerun-if-changed={}", driver_file.display());
    }

    let out = PathBuf::from(env::var_os("OUT_DIR").context("OUT_DIR")?);
    let profile = out.ancestors().nth(3).context("Cargo profile directory")?;
    let runtime = profile.join("runtime");
    let marker = runtime.join("cuda.json");
    println!("cargo::rerun-if-changed={}", marker.display());
    if let Ok(bytes) = fs::read(&marker) {
        let info: Value = serde_json::from_slice(&bytes)?;
        if info["layout"] == 1
            && info["driver_limit"] == json!([limit.0, limit.1])
            && info["platform"] == platform
        {
            let release = info["release"].as_str().context("CUDA runtime release")?;
            let root = runtime.join(format!("cuda-{release}"));
            println!("cargo::rerun-if-changed={}", root.display());
            let library = if platform.starts_with("windows") {
                "bin/nvrtc.dll"
            } else {
                "bin/libnvrtc.so"
            };
            if root.join("include/cuda_runtime.h").is_file()
                && root.join("include/crt/host_config.h").is_file()
                && root.join(library).is_file()
            {
                return Ok(Some(release.to_owned()));
            }
        }
    }
    let cache = profile
        .parent()
        .context("Cargo target directory")?
        .join("cuda-cache");
    fs::create_dir_all(&cache)?;
    let index = cache.join("index.html");
    download(NVIDIA, &index)?;
    let release = select_release(&fs::read_to_string(index)?, limit)
        .context("no compatible NVIDIA redistributable")?;
    let manifest = cache.join(format!("redistrib_{release}.json"));
    if !manifest.exists() {
        download(&format!("{NVIDIA}redistrib_{release}.json"), &manifest)?;
    }
    let metadata: Value = serde_json::from_slice(&fs::read(&manifest)?)?;
    let root = runtime.join(format!("cuda-{release}"));
    println!("cargo::rerun-if-changed={}", root.display());
    fs::create_dir_all(&root)?;
    let cccl = if metadata.get("cccl").is_some() {
        "cccl"
    } else {
        "cuda_cccl"
    };
    let crt = if metadata.get("cuda_crt").is_some() {
        "cuda_crt"
    } else {
        "cuda_nvcc"
    };
    for name in ["cuda_nvrtc", "cuda_cudart", crt, cccl] {
        let component = metadata[name]
            .get(platform)
            .with_context(|| format!("missing {name}/{platform}"))?;
        let archive = package(&cache, component)?;
        unpack(name, &archive, &root)?;
    }
    ensure!(
        root.join("include/cuda_runtime.h").is_file()
            && root.join("include/crt/host_config.h").is_file(),
        "CUDA headers incomplete"
    );
    let nvrtc = fs::read_dir(root.join("bin"))?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .find(|p| {
            let n = p.file_name().unwrap().to_string_lossy();
            !n.contains("builtins")
                && n != "nvrtc.dll"
                && n != "libnvrtc.so"
                && (n.ends_with(".dll") || n.starts_with("libnvrtc.so"))
        })
        .context("NVRTC library missing")?;
    // A stable filename lets the fixed Rust API bindings load either CUDA 12 or 13.
    let alias = root.join("bin").join(if platform.starts_with("windows") {
        "nvrtc.dll"
    } else {
        "libnvrtc.so"
    });
    if nvrtc != alias {
        #[cfg(windows)]
        fs::rename(&nvrtc, &alias)?;
        #[cfg(unix)]
        if !alias.exists() {
            std::os::unix::fs::symlink(nvrtc.file_name().unwrap(), &alias)?;
        }
    }
    fs::copy(manifest, root.join("redistrib.json"))?;
    fs::File::create(&marker)?.write_all(
        serde_json::to_string_pretty(&json!({
                "layout": 1, "release": release, "driver_limit": [limit.0, limit.1], "platform": platform
        }))?
        .as_bytes(),
    )?;
    Ok(Some(release))
}

#[cfg(test)]
#[path = "test/cuda_build.rs"]
mod tests;
