use anyhow::Result;

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

pub struct MeSpiRegionPayload;

impl Payload for MeSpiRegionPayload {
    fn name(&self) -> &str {
        "me_spi_region"
    }

    fn arch(&self) -> Arch {
        Arch::X86_64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x2000);
        let mut data = vec![0u8; size];

        // HSFS at offset 0x04: FLOCKDN bit (bit 15) CLEAR = 0x0000
        // Triggers lockdown check — leaving as zero means flash not locked
        data[0x04] = 0x00;
        data[0x05] = 0x00;

        // Intel Flash Descriptor signature 0x0FF0A55A at offset 0x10 (LE)
        data[0x10] = 0x5A;
        data[0x11] = 0xA5;
        data[0x12] = 0xF0;
        data[0x13] = 0x0F;

        // FLMAP0 at offset 0x14 (pointing to region section at 0x40)
        // Region section offset = 0x40 / 0x10 = 0x04 in bits [23:16]
        data[0x14] = 0x00;
        data[0x15] = 0x00;
        data[0x16] = 0x04;
        data[0x17] = 0x00;

        // FLMAP1 at offset 0x18
        data[0x18] = 0x00;
        data[0x19] = 0x00;
        data[0x1A] = 0x00;
        data[0x1B] = 0x00;

        // FLREG0 (BIOS region) at offset 0x54: base=0x100, limit=0x7FF
        // Format: limit[15:0] << 16 | base[15:0]
        let bios_region: u32 = (0x7FF << 16) | 0x100;
        data[0x54] = (bios_region & 0xFF) as u8;
        data[0x55] = ((bios_region >> 8) & 0xFF) as u8;
        data[0x56] = ((bios_region >> 16) & 0xFF) as u8;
        data[0x57] = ((bios_region >> 24) & 0xFF) as u8;

        // FLREG1 (ME region) at offset 0x58: base=0x050, limit=0x200
        // This OVERLAPS with BIOS region (base 0x050*0x1000 < BIOS limit)
        let me_region: u32 = (0x200 << 16) | 0x050;
        data[0x58] = (me_region & 0xFF) as u8;
        data[0x59] = ((me_region >> 8) & 0xFF) as u8;
        data[0x5A] = ((me_region >> 16) & 0xFF) as u8;
        data[0x5B] = ((me_region >> 24) & 0xFF) as u8;

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "me_spi".to_string(),
            min_severity: Severity::High,
        }]
    }
}
