use anyhow::Result;

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

pub struct S3BootscriptInjectPayload;

impl Payload for S3BootscriptInjectPayload {
    fn name(&self) -> &str {
        "s3_bootscript_inject"
    }

    fn arch(&self) -> Arch {
        Arch::X86_64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x2000);
        let mut data = vec![0u8; size];

        // At offset 0x100: S3 boot script opcodes
        let offset = 0x100;
        // MEM_WRITE opcode (0x00) with length 0x10
        data[offset] = 0x00; // MEM_WRITE
        data[offset + 1] = 0x10; // length
        data[offset + 2] = 0x00;
        data[offset + 3] = 0x00;
        data[offset + 4] = 0x00;
        // IO_WRITE opcode (0x01) with length 0x08
        data[offset + 0x10] = 0x01; // IO_WRITE
        data[offset + 0x11] = 0x08; // length
        data[offset + 0x12] = 0x00;
        data[offset + 0x13] = 0x00;
        data[offset + 0x14] = 0x00;
        // DISPATCH opcode (0x03) with entry point at suspicious location
        data[offset + 0x18] = 0x03; // DISPATCH
        data[offset + 0x19] = 0x10; // length
        data[offset + 0x1A] = 0x00;
        data[offset + 0x1B] = 0x00;
        data[offset + 0x1C] = 0x00;
        // Entry point address (suspicious — points outside firmware)
        let entry_point: u64 = 0x41414141_DEADBEEF;
        data[offset + 0x20..offset + 0x28].copy_from_slice(&entry_point.to_le_bytes());

        // At offset 0x200: EFI Runtime Services table pattern
        let offset = 0x200;
        // Signature "RUNTSERV"
        data[offset..offset + 8].copy_from_slice(b"RUNTSERV");
        // Table header fields (revision, size)
        let revision: u32 = 0x00020070;
        data[offset + 8..offset + 12].copy_from_slice(&revision.to_le_bytes());
        let header_size: u32 = 0x00000058;
        data[offset + 12..offset + 16].copy_from_slice(&header_size.to_le_bytes());
        // Function pointer at suspicious address (outside normal firmware range)
        let bad_ptr: u64 = 0x41414141_00000000;
        data[offset + 0x18..offset + 0x20].copy_from_slice(&bad_ptr.to_le_bytes());
        // Another suspicious function pointer
        data[offset + 0x20..offset + 0x28].copy_from_slice(&bad_ptr.to_le_bytes());

        // At offset 0x300: Boot script entry with length=0x00000000 (corruption)
        let offset = 0x300;
        data[offset] = 0x00; // MEM_WRITE opcode
                             // length = 0x00000000 (zero length = corruption indicator)
        data[offset + 1] = 0x00;
        data[offset + 2] = 0x00;
        data[offset + 3] = 0x00;
        data[offset + 4] = 0x00;

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "s3_bootscript".to_string(),
            min_severity: Severity::High,
        }]
    }
}
