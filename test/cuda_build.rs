use super::*;

#[test]
fn chooses_highest_release_within_driver_limit() {
    let index = "redistrib_12.9.0.json redistrib_13.4.1.json redistrib_12.9.1.json \
                 redistrib_13.4.3.json redistrib_13.5.0.json redistrib_broken.json";
    assert_eq!(driver_limit("CUDA Version: 12.9 |"), Some((12, 9)));
    assert_eq!(driver_limit("CUDA UMD Version: 13.4 |"), Some((13, 4)));
    assert_eq!(driver_limit("CUDA Version: N/A"), None);
    assert_eq!(select_release(index, (12, 9)).as_deref(), Some("12.9.1"));
    assert_eq!(select_release(index, (13, 4)).as_deref(), Some("13.4.3"));
    assert_eq!(select_release(index, (11, 8)), None);
}

#[test]
fn extracts_only_headers_nvrtc_and_licenses() {
    for (package, input, output) in [
        (
            "cuda_cudart",
            "pkg/include/cuda_runtime.h",
            "include/cuda_runtime.h",
        ),
        (
            "cuda_crt",
            "pkg/include/crt/host_config.h",
            "include/crt/host_config.h",
        ),
        (
            "cccl",
            "pkg/include/cuda/std/utility",
            "include/cccl/cuda/std/utility",
        ),
        (
            "cuda_nvrtc",
            "pkg/bin/x64/nvrtc64_130_0.dll",
            "bin/nvrtc64_130_0.dll",
        ),
        (
            "cuda_nvrtc",
            "pkg/lib/libnvrtc.so.12.9",
            "bin/libnvrtc.so.12.9",
        ),
        ("cuda_nvrtc", "pkg/LICENSE", "licenses/cuda_nvrtc/LICENSE"),
    ] {
        assert_eq!(
            destination(package, Path::new(input)).unwrap(),
            Some(PathBuf::from(output))
        );
    }
    for (package, input) in [
        ("cuda_nvcc", "pkg/bin/nvcc.exe"),
        ("cuda_cudart", "pkg/bin/cudart64_13.dll"),
        ("cuda_nvrtc", "pkg/lib/nvrtc_static.lib"),
        ("cuda_nvrtc", "pkg/lib/libnvrtc_static.a"),
        ("cuda_nvrtc", "pkg/lib/libcuda.so.1"),
    ] {
        assert_eq!(destination(package, Path::new(input)).unwrap(), None);
    }
    for path in ["../escape", "/tmp/escape", "pkg/include/../../escape"] {
        assert!(destination("cuda_cudart", Path::new(path)).is_err());
    }
}

#[test]
fn archive_cannot_write_outside_runtime() {
    let root = env::temp_dir().join(format!("enigma-cuda-archive-{}", std::process::id()));
    fs::create_dir_all(&root).unwrap();
    let archive = root.join("invalid.zip");
    let mut zip = zip::ZipWriter::new(fs::File::create(&archive).unwrap());
    zip.start_file("../../escape", zip::write::SimpleFileOptions::default())
        .unwrap();
    zip.write_all(b"invalid").unwrap();
    zip.finish().unwrap();
    assert!(unpack("cuda_cudart", &archive, &root.join("runtime")).is_err());
    fs::remove_file(archive).unwrap();
    fs::remove_dir(root).unwrap();
}
