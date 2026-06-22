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
        // GUID: {3B6686BD-0D76-4030-B70E-B5519E2FC5A0}
        let offset = 0x100;
        let capsule_guid: [u8; 16] = [
            0xBD, 0x86, 0x66, 0x3B, // Data1 LE
            0x76, 0x0D, // Data2 LE
            0x30, 0x40, // Data3 LE
            0xB7, 0x0E, // Data4[0..2]
            0xB5, 0x51, 0x9E, 0x2F, 0xC5, 0xA0, // Data4[2..8]
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
