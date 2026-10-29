//! WGPU device selection for the shared GPU salt search.
use super::{extract::StoredSection, gpu_kernel};
use anyhow::Result;
use cubecl::prelude::*;
use cubecl_wgpu::{AutoGraphicsApi, RuntimeOptions, WgpuDevice, WgpuRuntime, init_setup};
use std::sync::OnceLock;

pub type GpuProbe = gpu_kernel::GpuProbe<WgpuRuntime>;

pub fn probe(section: &StoredSection) -> Result<GpuProbe> {
    static CLIENT: OnceLock<ComputeClient<WgpuRuntime>> = OnceLock::new();
    let client = CLIENT.get_or_init(|| {
        let device = WgpuDevice::DiscreteGpu(0);
        let setup = init_setup::<AutoGraphicsApi>(&device, RuntimeOptions::default());
        eprintln!(
            "WGPU: {} ({:?})",
            setup.adapter.get_info().name,
            setup.backend
        );
        WgpuRuntime::client(&device)
    });
    GpuProbe::new(section, client.clone())
}

pub fn search(sections: &[StoredSection], screen: &StoredSection) -> Result<Option<u32>> {
    gpu_kernel::search("WGPU", sections, probe(screen)?)
}
