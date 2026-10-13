use anyhow::Result;
use byteorder::{LittleEndian, WriteBytesExt};

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

pub struct PeInjectPayload;

impl Payload for PeInjectPayload {
    fn name(&self) -> &str {
        "pe_inject"
    }

    fn arch(&self) -> Arch {
        Arch::X86_64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        // PE must be at page-aligned offset (0x1000 increments)
        let pe_offset = 0x2000;
        let size = config.size.max(pe_offset + 0x1000);
        let mut data = vec![0u8; size];

        // MZ header at page-aligned offset
        data[pe_offset] = b'M';
        data[pe_offset + 1] = b'Z';

        // e_lfanew at offset 0x3C — pointer to PE signature
        let pe_sig_offset: u32 = 0x80;
        let mut cursor = std::io::Cursor::new(&mut data[pe_offset + 0x3C..pe_offset + 0x40]);
        cursor.write_u32::<LittleEndian>(pe_sig_offset)?;

        // PE\0\0 signature at the pointed-to offset
        let abs_pe_sig = pe_offset + pe_sig_offset as usize;
        data[abs_pe_sig] = b'P';
        data[abs_pe_sig + 1] = b'E';
        data[abs_pe_sig + 2] = 0x00;
        data[abs_pe_sig + 3] = 0x00;

        // Minimal COFF header after PE sig
        let coff_offset = abs_pe_sig + 4;
        // Machine type based on architecture
        let machine: u16 = match config.arch {
            Arch::X86_64 => 0x8664,
            Arch::Aarch64 => 0xAA64,
            Arch::RiscV64 => 0x5064,
            // IBM POWER / OpenPOWER (PowerPC 64-bit, big endian)
            Arch::Power64 => 0x01F2,
            // ARM Thumb-2 (32-bit)
            Arch::Armv7 => 0x01C4,
        };
        data[coff_offset] = machine as u8;
        data[coff_offset + 1] = (machine >> 8) as u8;
        // NumberOfSections: 1
        data[coff_offset + 2] = 0x01;
        data[coff_offset + 3] = 0x00;

        // Place a second PE at another page boundary
        let pe_offset2 = 0x4000;
        if size > pe_offset2 + 0x100 {
            data[pe_offset2] = b'M';
            data[pe_offset2 + 1] = b'Z';
            let mut cursor2 = std::io::Cursor::new(&mut data[pe_offset2 + 0x3C..pe_offset2 + 0x40]);
            cursor2.write_u32::<LittleEndian>(pe_sig_offset)?;
            let abs2 = pe_offset2 + pe_sig_offset as usize;
            data[abs2] = b'P';
            data[abs2 + 1] = b'E';
            data[abs2 + 2] = 0x00;
            data[abs2 + 3] = 0x00;
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
