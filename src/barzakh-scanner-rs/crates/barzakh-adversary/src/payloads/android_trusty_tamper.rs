use anyhow::Result;
use byteorder::{LittleEndian, WriteBytesExt};

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

pub struct AndroidTrustyTamperPayload;

impl Payload for AndroidTrustyTamperPayload {
    fn name(&self) -> &str {
        "android_trusty_tamper"
    }

    fn arch(&self) -> Arch {
        Arch::Aarch64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x4000);
        let mut data = vec![0u8; size];

        // Trusty OS image header magic "TRUSTY"
        data[0] = b'T';
        data[1] = b'R';
        data[2] = b'U';
        data[3] = b'S';
        data[4] = b'T';
        data[5] = b'Y';

        // Image version
        let mut cursor = std::io::Cursor::new(&mut data[6..10]);
        cursor.write_u32::<LittleEndian>(0x0003)?;

        // Image size
        let mut cursor = std::io::Cursor::new(&mut data[10..14]);
        cursor.write_u32::<LittleEndian>(size as u32)?;

        // Load address OUTSIDE secure memory (normal world address)
        // Secure range is 0xB0000000 - 0xC0000000
        // Set to 0x80000000 (normal world DRAM)
        let mut cursor = std::io::Cursor::new(&mut data[16..24]);
        cursor.write_u64::<LittleEndian>(0x0000_0000_8000_0000)?;

        // Signature field at offset 64 — zeroed (256 bytes, already zero in vec)

        // LK bootloader header "ANDROID" at offset 0x1000
        let lk_offset = 0x1000;
        let lk_magic = b"ANDROID";
        data[lk_offset..lk_offset + lk_magic.len()].copy_from_slice(lk_magic);

        // Patched entry point with branch + NOP sled at offset 0x1020 (lk_offset + 32)
        let entry_offset = lk_offset + 32;
        // ARM64 unconditional branch: B #0x100 = 0x14000040
        let mut cursor = std::io::Cursor::new(&mut data[entry_offset..entry_offset + 4]);
        cursor.write_u32::<LittleEndian>(0x1400_0040)?;

        // NOP sled (4 x NOP = 0xD503201F)
        for i in 0..4 {
            let nop_off = entry_offset + 4 + (i * 4);
            let mut cursor = std::io::Cursor::new(&mut data[nop_off..nop_off + 4]);
            cursor.write_u32::<LittleEndian>(0xD503_201F)?;
        }

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "android_trusty".to_string(),
            min_severity: Severity::High,
        }]
    }
}
