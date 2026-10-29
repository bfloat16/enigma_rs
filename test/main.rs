mod algorithms;
#[allow(dead_code)] // Exercise the build script's selection and extraction rules.
#[path = "../build.rs"]
mod cuda_build;
#[cfg(any(all(feature = "cuda", cuda_available), feature = "wgpu"))]
mod gpu;
mod imports;
mod pe_config;
mod static_vm;

fn bytes(text: &str) -> Vec<u8> {
    text.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}
