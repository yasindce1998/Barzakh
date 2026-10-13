use anyhow::Result;
use byteorder::{BigEndian, LittleEndian, WriteBytesExt};

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

pub struct TrampolinePayload;

impl Payload for TrampolinePayload {
    fn name(&self) -> &str {
        "trampoline"
    }

    fn arch(&self) -> Arch {
        Arch::X86_64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x1000);
        let mut data = vec![0u8; size];

        match config.arch {
            Arch::X86_64 => {
                // JMP [RIP+0] trampoline at offset 0x100
                let offset = 0x100;
                data[offset] = 0xFF;
                data[offset + 1] = 0x25;
                data[offset + 2] = 0x00;
                data[offset + 3] = 0x00;
                data[offset + 4] = 0x00;
                data[offset + 5] = 0x00;
                // 8-byte target address (must be non-zero, non-MAX)
                let target: u64 = 0xDEAD_BEEF_CAFE_0000;
                let mut cursor = std::io::Cursor::new(&mut data[offset + 6..offset + 14]);
                cursor.write_u64::<LittleEndian>(target)?;

                // Second trampoline at different offset
                let offset2 = 0x200;
                data[offset2] = 0xFF;
                data[offset2 + 1] = 0x25;
                data[offset2 + 2] = 0x00;
                data[offset2 + 3] = 0x00;
                data[offset2 + 4] = 0x00;
                data[offset2 + 5] = 0x00;
                let target2: u64 = 0x0000_FFFF_8000_1000;
                let mut cursor2 = std::io::Cursor::new(&mut data[offset2 + 6..offset2 + 14]);
                cursor2.write_u64::<LittleEndian>(target2)?;
            }
            Arch::Aarch64 => {
                // LDR X16, [PC, #8]; BR X16
                let offset = 0x100;
                let arm64_trampoline: [u8; 8] = [0x50, 0x00, 0x00, 0x58, 0x00, 0x02, 0x1F, 0xD6];
                data[offset..offset + 8].copy_from_slice(&arm64_trampoline);
                // 8-byte target address follows
                let target: u64 = 0xFFFF_0000_0800_0000;
                let mut cursor = std::io::Cursor::new(&mut data[offset + 8..offset + 16]);
                cursor.write_u64::<LittleEndian>(target)?;

                // Second ARM64 trampoline
                let offset2 = 0x280;
                data[offset2..offset2 + 8].copy_from_slice(&arm64_trampoline);
                let target2: u64 = 0xFFFF_0000_0900_0000;
                let mut cursor2 = std::io::Cursor::new(&mut data[offset2 + 8..offset2 + 16]);
                cursor2.write_u64::<LittleEndian>(target2)?;
            }
            Arch::RiscV64 => {
                // AUIPC t1, 0 + LD t1, 8(t1) + JALR x0, t1, 0 + 8-byte target
                let offset = 0x100;
                let mut cursor = std::io::Cursor::new(&mut data[offset..offset + 20]);
                cursor.write_u32::<LittleEndian>(0x0000_0317)?; // AUIPC t1, 0
                cursor.write_u32::<LittleEndian>(0x0083_3303)?; // LD t1, 8(t1)
                cursor.write_u32::<LittleEndian>(0x0003_0067)?; // JALR x0, t1, 0
                cursor.write_u64::<LittleEndian>(0xFFFF_FFE0_0000_1000)?; // target

                // Second RISC-V trampoline
                let offset2 = 0x280;
                let mut cursor2 = std::io::Cursor::new(&mut data[offset2..offset2 + 20]);
                cursor2.write_u32::<LittleEndian>(0x0000_0317)?;
                cursor2.write_u32::<LittleEndian>(0x0083_3303)?;
                cursor2.write_u32::<LittleEndian>(0x0003_0067)?;
                cursor2.write_u64::<LittleEndian>(0xFFFF_FFE0_0080_0000)?;
            }
            Arch::Power64 => {
                // PPC64: addis r11, 0; ld r11, 8(r11); mtctr r11; bctr + 8-byte target
                let offset = 0x100;
                let mut cursor = std::io::Cursor::new(&mut data[offset..offset + 24]);
                cursor.write_u32::<BigEndian>(0x3D60_0000)?; // addis r11, 0
                cursor.write_u32::<BigEndian>(0xE96B_0008)?; // ld r11, 8(r11)
                cursor.write_u32::<BigEndian>(0x7D69_03A6)?; // mtctr r11
                cursor.write_u32::<BigEndian>(0x4E80_0420)?; // bctr
                cursor.write_u64::<BigEndian>(0xFFFF_E000_0000_1000)?;
            }
            Arch::Armv7 => {
                // ARM32: ldr pc, [pc, #-4]; .word target
                let offset = 0x100;
                let mut cursor = std::io::Cursor::new(&mut data[offset..offset + 8]);
                cursor.write_u32::<LittleEndian>(0xE51F_F004)?; // ldr pc, [pc, #-4]
                cursor.write_u32::<LittleEndian>(0xFFFF_8000)?;
            }
        }

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "memory".to_string(),
            min_severity: Severity::High,
        }]
    }
}
