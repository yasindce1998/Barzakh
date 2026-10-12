use anyhow::Result;

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

pub struct MeManufacturingModePayload;

impl Payload for MeManufacturingModePayload {
    fn name(&self) -> &str {
        "me_manufacturing_mode"
    }

    fn arch(&self) -> Arch {
        Arch::X86_64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x2000);
        let mut data = vec![0u8; size];

        // Flash Descriptor signature at offset 0x10
        let desc_offset = 0x10;
        data[desc_offset] = 0x5A;
        data[desc_offset + 1] = 0xA5;
        data[desc_offset + 2] = 0xF0;
        data[desc_offset + 3] = 0x0F;

        // FITM (Factory Init Test Mode) byte at descriptor offset + 0x40
        // Bit 1 = manufacturing mode enabled
        data[desc_offset + 0x40] = 0x02;

        // FPT header "$FPT" at offset 0x1000
        let fpt_offset = 0x1000;
        data[fpt_offset] = 0x24;
        data[fpt_offset + 1] = 0x46;
        data[fpt_offset + 2] = 0x50;
        data[fpt_offset + 3] = 0x54;

        // FPT num entries = 4
        data[fpt_offset + 4..fpt_offset + 8].copy_from_slice(&4u32.to_le_bytes());
        // FPT version
        data[fpt_offset + 8] = 0x20;
        // FPT header flags at fpt+20 (bit 0 = debug enabled in manufacturing mode)
        data[fpt_offset + 20..fpt_offset + 24].copy_from_slice(&0x01u32.to_le_bytes());

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "me_manufacturing_mode".to_string(),
            min_severity: Severity::High,
        }]
    }
}
