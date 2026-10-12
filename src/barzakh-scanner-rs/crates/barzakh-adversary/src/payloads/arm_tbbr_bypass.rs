use anyhow::Result;

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

pub struct ArmTbbrBypassPayload;

impl Payload for ArmTbbrBypassPayload {
    fn name(&self) -> &str {
        "arm_tbbr_bypass"
    }

    fn arch(&self) -> Arch {
        Arch::Aarch64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x4000);
        let mut data = vec![0u8; size];

        // FIP (Firmware Image Package) TOC header
        let fip_magic: u32 = 0x4E0A64AA; // ARM FIP magic
        data[0..4].copy_from_slice(&fip_magic.to_le_bytes());

        // Serial number
        data[4..8].copy_from_slice(&0x12345678u32.to_le_bytes());
        // Flags (0 = normal)
        data[8..16].copy_from_slice(&0u64.to_le_bytes());

        // TOC entry 1: BL2 image (zeroed hash — TBBR bypass!)
        // The detector matches the 8-byte UUID prefix and reads the 32-byte
        // SHA-256 hash field at uuid+24, so the entry layout is:
        // uuid(8) + offset(8) + size(8) + hash(32)
        let bl2_uuid: [u8; 8] = [0x5F, 0xF9, 0xEC, 0x0B, 0x4D, 0x22, 0x3E, 0x4D];
        let entry1_offset = 16;
        data[entry1_offset..entry1_offset + 8].copy_from_slice(&bl2_uuid);
        // Offset to data
        data[entry1_offset + 8..entry1_offset + 16].copy_from_slice(&0x1000u64.to_le_bytes());
        // Size
        data[entry1_offset + 16..entry1_offset + 24].copy_from_slice(&0x2000u64.to_le_bytes());
        // Hash: 32 zero bytes (should hold the SHA-256 measurement)

        // TOC entry 2: BL31 image (also zeroed hash)
        let bl31_uuid: [u8; 8] = [0x63, 0xB4, 0xC3, 0xE6, 0x26, 0x0E, 0x11, 0xE3];
        let entry2_offset = entry1_offset + 48;
        data[entry2_offset..entry2_offset + 8].copy_from_slice(&bl31_uuid);
        data[entry2_offset + 8..entry2_offset + 16].copy_from_slice(&0x3000u64.to_le_bytes());
        data[entry2_offset + 16..entry2_offset + 24].copy_from_slice(&0x1000u64.to_le_bytes());
        // Hash: 32 zero bytes (should hold the SHA-256 measurement)

        // NV counter area — zeroed (anti-rollback protection disabled)
        let nv_counter_offset = 0x500;
        // NV_COUNTER marker
        let nv_marker = b"NV_CTR";
        data[nv_counter_offset..nv_counter_offset + nv_marker.len()].copy_from_slice(nv_marker);
        // Counter value: 0 (should be > 0 if rollback protection active)

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "arm_tbbr".to_string(),
            min_severity: Severity::Critical,
        }]
    }
}
