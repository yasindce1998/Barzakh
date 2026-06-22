use anyhow::Result;

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

pub struct MeDmaInjectPayload;

impl Payload for MeDmaInjectPayload {
    fn name(&self) -> &str {
        "me_dma_inject"
    }

    fn arch(&self) -> Arch {
        Arch::X86_64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x2000);
        let mut data = vec![0u8; size];

        // DMA descriptor at offset 0x100
        // Source: 0xFED40000 (ME PAVP base, 8 bytes LE)
        let source: u64 = 0xFED40000;
        data[0x100..0x108].copy_from_slice(&source.to_le_bytes());
        // Destination: 0xFFFF800000001000 (kernel space page-aligned, 8 bytes LE)
        let destination: u64 = 0xFFFF800000001000;
        data[0x108..0x110].copy_from_slice(&destination.to_le_bytes());
        // Length: 0x1000 (4 bytes LE)
        let length: u32 = 0x1000;
        data[0x110..0x114].copy_from_slice(&length.to_le_bytes());
        // Status: 0x01 (complete, 4 bytes LE)
        let status: u32 = 0x01;
        data[0x114..0x118].copy_from_slice(&status.to_le_bytes());

        // UMA base register reference at offset 0x200
        // 0x7890 as LE u16
        let uma_base: u16 = 0x7890;
        data[0x200..0x202].copy_from_slice(&uma_base.to_le_bytes());
        // PAVP base 0xFED40000 (8 bytes LE)
        let pavp_base: u64 = 0xFED40000;
        data[0x202..0x20A].copy_from_slice(&pavp_base.to_le_bytes());

        // DMA descriptor pointing to offset 0x1000 (placed just before shellcode)
        let shellcode_offset: u64 = 0x1000;
        // Source (ME PAVP)
        data[0xFF0..0xFF8].copy_from_slice(&source.to_le_bytes());
        // Destination pointing to shellcode offset (as if it were a physical address)
        data[0xFF8..0x1000].copy_from_slice(&shellcode_offset.to_le_bytes());

        // x86_64 shellcode prologue at offset 0x1000 (page-aligned)
        // 0x48 0x31 0xC0 - xor rax, rax
        data[0x1000] = 0x48;
        data[0x1001] = 0x31;
        data[0x1002] = 0xC0;
        // 0x48 0x89 0xE5 - mov rbp, rsp
        data[0x1003] = 0x48;
        data[0x1004] = 0x89;
        data[0x1005] = 0xE5;
        // 0x50 - push rax
        data[0x1006] = 0x50;

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "me_dma".to_string(),
            min_severity: Severity::High,
        }]
    }
}
