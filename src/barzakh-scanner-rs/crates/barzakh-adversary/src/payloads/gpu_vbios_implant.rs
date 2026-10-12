use anyhow::Result;

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

pub struct GpuVbiosImplantPayload;

impl Payload for GpuVbiosImplantPayload {
    fn name(&self) -> &str {
        "gpu_vbios_implant"
    }

    fn arch(&self) -> Arch {
        Arch::X86_64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x8000);
        let mut data = vec![0u8; size];

        // PCI Expansion ROM header
        data[0] = 0x55;
        data[1] = 0xAA;
        // ROM size in 512-byte blocks
        data[2] = 0x40; // 32KB
        // Initialization entry point (offset 0x03, u16 LE) points beyond the
        // declared ROM size — the tampered init vector of the implant
        data[3..5].copy_from_slice(&0x9000u16.to_le_bytes());

        // PCIR data structure pointer at offset 0x18
        data[0x18..0x1A].copy_from_slice(&0x0040u16.to_le_bytes());

        // PCIR signature at 0x40
        data[0x40..0x44].copy_from_slice(b"PCIR");
        // Vendor ID: NVIDIA (0x10DE)
        data[0x44..0x46].copy_from_slice(&0x10DEu16.to_le_bytes());
        // Device ID
        data[0x46..0x48].copy_from_slice(&0x2684u16.to_le_bytes());
        // Class code: VGA (0x030000)
        data[0x4D] = 0x03;

        // NVIDIA VBIOS magic
        let nvbios_marker = b"NVID";
        data[0x100..0x104].copy_from_slice(nvbios_marker);

        // Legitimate ROM ends at 0x4000, but inject DXE stub after
        let inject_offset = 0x4000;
        data[inject_offset] = b'M';
        data[inject_offset + 1] = b'Z';
        data[inject_offset + 60..inject_offset + 64].copy_from_slice(&0x80u32.to_le_bytes());
        data[inject_offset + 0x80..inject_offset + 0x84].copy_from_slice(b"PE\x00\x00");
        // x86_64 machine type
        data[inject_offset + 0x84..inject_offset + 0x86].copy_from_slice(&0x8664u16.to_le_bytes());

        // EFI_IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER = 11
        data[inject_offset + 0xC0..inject_offset + 0xC2].copy_from_slice(&11u16.to_le_bytes());

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "optionrom".to_string(),
            min_severity: Severity::High,
        }]
    }
}
