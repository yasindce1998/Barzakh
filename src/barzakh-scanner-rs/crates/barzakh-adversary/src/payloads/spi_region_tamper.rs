use anyhow::Result;

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

pub struct SpiRegionTamperPayload;

impl Payload for SpiRegionTamperPayload {
    fn name(&self) -> &str {
        "spi_region_tamper"
    }

    fn arch(&self) -> Arch {
        Arch::X86_64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x2000);
        let mut data = vec![0u8; size];

        // Intel Flash Descriptor signature 0x0FF0A55A at offset 0x10 (LE)
        data[0x10] = 0x5A;
        data[0x11] = 0xA5;
        data[0x12] = 0xF0;
        data[0x13] = 0x0F;

        // FLREG0 (BIOS region) at offset 0x54: base=0x100, limit=0x7FF
        // Format: limit<<16 | base (LE u32)
        let bios_region: u32 = (0x7FF << 16) | 0x100;
        data[0x54..0x58].copy_from_slice(&bios_region.to_le_bytes());

        // FLREG1 (ME region) at offset 0x58: base=0x800, limit=0xFFF (valid, non-overlapping)
        let me_region: u32 = (0xFFF << 16) | 0x800;
        data[0x58..0x5C].copy_from_slice(&me_region.to_le_bytes());

        // FLREG2 (GbE region) at offset 0x5C: base=0x500, limit=0x100
        // base > limit = INVALID region descriptor
        let gbe_region: u32 = (0x100 << 16) | 0x500;
        data[0x5C..0x60].copy_from_slice(&gbe_region.to_le_bytes());

        // FLMSTR1 at offset 0x80: master access bits giving BIOS write access to ME region
        // Bit pattern 0x00FF indicating full access to all regions
        let master_access: u32 = 0x00FF;
        data[0x80..0x84].copy_from_slice(&master_access.to_le_bytes());

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "spi_region".to_string(),
            min_severity: Severity::High,
        }]
    }
}
