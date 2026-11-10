use anyhow::Result;

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

pub struct OptionromInjectPayload;

impl Payload for OptionromInjectPayload {
    fn name(&self) -> &str {
        "optionrom_inject"
    }

    fn arch(&self) -> Arch {
        Arch::X86_64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x2000);
        let mut data = vec![0u8; size];

        // At offset 0x000: PCI Option ROM header
        // Signature 0x55AA (2 bytes)
        data[0x000] = 0x55;
        data[0x001] = 0xAA;
        // Size = 0x04 (in 512-byte units = 2KB declared)
        data[0x002] = 0x04;

        // At offset 0x003: Init entry point offset that points BEYOND declared size
        // 0x0900 (offset 0x900, but ROM is only 2KB = 0x800)
        let init_offset: u16 = 0x0900;
        data[0x003..0x005].copy_from_slice(&init_offset.to_le_bytes());

        // Header checksum byte at 0x06 is computed last so the 2KB ROM
        // image sums to zero mod 256 — a ROM only loads with a valid
        // checksum, and a realistic implant keeps it valid.

        // At offset 0x018: PCI Data Structure pointer = 0x001C
        let pcir_ptr: u16 = 0x001C;
        data[0x018..0x01A].copy_from_slice(&pcir_ptr.to_le_bytes());

        // At offset 0x01C: PCI Data Structure
        // "PCIR" signature (4 bytes)
        data[0x01C..0x020].copy_from_slice(b"PCIR");
        // Vendor ID = 0x8086
        let vendor: u16 = 0x8086;
        data[0x020..0x022].copy_from_slice(&vendor.to_le_bytes());
        // Device ID = 0x1234
        let device: u16 = 0x1234;
        data[0x022..0x024].copy_from_slice(&device.to_le_bytes());
        // VPD pointer
        data[0x024] = 0x00;
        data[0x025] = 0x00;
        // PCI Data Structure length = 0x18
        let pcir_len: u16 = 0x0018;
        data[0x026..0x028].copy_from_slice(&pcir_len.to_le_bytes());
        // PCI Data Structure revision
        data[0x028] = 0x03;
        // Class code (display controller)
        data[0x029] = 0x00;
        data[0x02A] = 0x00;
        data[0x02B] = 0x03;
        // Image length (same as size field: 0x04 * 512 bytes)
        let image_len: u16 = 0x0004;
        data[0x02C..0x02E].copy_from_slice(&image_len.to_le_bytes());
        // Code type = 0x03 (EFI)
        data[0x030] = 0x03;
        // Last image indicator
        data[0x031] = 0x80;

        // At offset 0x900 (beyond declared 2KB ROM): high-entropy data
        // Alternating 0xDE 0xAD bytes for 256 bytes to trigger
        // "data beyond declared boundary"
        let offset = 0x900;
        for i in 0..256 {
            if i % 2 == 0 {
                data[offset + i] = 0xDE;
            } else {
                data[offset + i] = 0xAD;
            }
        }

        // Compute the ROM checksum over the declared 2KB image so it sums
        // to zero mod 256 (bypassing any host-side "would this ROM load"
        // structural gating in the detector).
        let rom_end = 0x04 * 512;
        let sum: u8 = data[0..rom_end]
            .iter()
            .fold(0u8, |acc, &b| acc.wrapping_add(b));
        data[0x006] = sum.wrapping_neg(); // checksum byte at header offset 0x06

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "optionrom".to_string(),
            min_severity: Severity::High,
        }]
    }
}
