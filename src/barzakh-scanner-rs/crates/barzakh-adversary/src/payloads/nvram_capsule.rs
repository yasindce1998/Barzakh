use anyhow::Result;

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

pub struct NvramCapsulePayload;

impl Payload for NvramCapsulePayload {
    fn name(&self) -> &str {
        "nvram_capsule"
    }

    fn arch(&self) -> Arch {
        Arch::X86_64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x2000);
        let mut data = vec![0u8; size];

        // At offset 0x000: NVRAM variable header
        // Signature 0xAAF8 (2 bytes)
        let offset = 0x000;
        data[offset] = 0xF8;
        data[offset + 1] = 0xAA;
        // State byte
        data[offset + 2] = 0x3F;
        // Attributes (4 bytes) — NV + BS + RT
        data[offset + 4] = 0x07;
        data[offset + 5] = 0x00;
        data[offset + 6] = 0x00;
        data[offset + 7] = 0x00;
        // DataSize = 0x00010000 (64KB — too large for normal boot variable)
        data[offset + 8] = 0x00;
        data[offset + 9] = 0x00;
        data[offset + 10] = 0x01;
        data[offset + 11] = 0x00;

        // At offset 0x100: EFI Capsule Header
        // GUID: EFI_FIRMWARE_MANAGEMENT_CAPSULE_ID_GUID
        // {6B0582B9-3EE2-46CE-9903-D9A7B1B78600}
        // (the detector's forgery check keys on this GUID)
        let offset = 0x100;
        let capsule_guid: [u8; 16] = [
            0xB9, 0x82, 0x05, 0x6B, // Data1 LE
            0xE2, 0x3E, // Data2 LE
            0xCE, 0x46, // Data3 LE
            0x99, 0x03, // Data4[0..2]
            0xD9, 0xA7, 0xB1, 0xB7, 0x86, 0x00, // Data4[2..8]
        ];
        data[offset..offset + 16].copy_from_slice(&capsule_guid);
        // HeaderSize = 0x1C (4 bytes LE)
        let header_size: u32 = 0x1C;
        data[offset + 16..offset + 20].copy_from_slice(&header_size.to_le_bytes());
        // Flags = 0x00000000 (no processing flag)
        let flags: u32 = 0x00000000;
        data[offset + 20..offset + 24].copy_from_slice(&flags.to_le_bytes());
        // CapsuleImageSize = 0x00050000 (large size)
        let capsule_size: u32 = 0x00050000;
        data[offset + 24..offset + 28].copy_from_slice(&capsule_size.to_le_bytes());

        // At offset 0x200-0x400: 512 bytes of pseudo-random high-entropy data
        // PRNG: seed=0xDEADBEEF, each byte = (seed * 1103515245 + 12345) >> 16 & 0xFF
        let offset = 0x200;
        let mut seed: u32 = 0xDEADBEEF;
        for i in 0..512 {
            seed = seed.wrapping_mul(1103515245).wrapping_add(12345);
            data[offset + i] = ((seed >> 16) & 0xFF) as u8;
        }

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "nvram_entropy".to_string(),
            min_severity: Severity::High,
        }]
    }
}
