use anyhow::Result;

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

pub struct CxlDmaAttackPayload;

impl Payload for CxlDmaAttackPayload {
    fn name(&self) -> &str {
        "cxl_dma_attack"
    }

    fn arch(&self) -> Arch {
        Arch::X86_64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x2000);
        let mut data = vec![0u8; size];

        // PCIe Configuration Space with CXL DVSEC
        let offset = 0x000;

        // Standard PCI header
        // Vendor ID = 0x1234 (non-standard/suspicious)
        data[offset] = 0x34;
        data[offset + 1] = 0x12;
        // Device ID
        data[offset + 2] = 0x00;
        data[offset + 3] = 0xCE;

        // PCIe Extended Capability at offset 0x100
        let ext_cap_offset = 0x100;
        // Extended Cap ID = 0x0023 (CXL DVSEC)
        data[ext_cap_offset] = 0x23;
        data[ext_cap_offset + 1] = 0x00;
        // Cap Version (4 bits) | Next Cap Pointer (12 bits)
        // Version = 1, Next = 0x200
        let ver_next: u32 = (1 << 16) | 0x200;
        data[ext_cap_offset + 2..ext_cap_offset + 4]
            .copy_from_slice(&((ver_next >> 16) as u16).to_le_bytes());

        // DVSEC Header 1 at ext_cap_offset + 4
        // DVSEC Vendor ID — CXL consortium = 0x1E98
        data[ext_cap_offset + 4] = 0x98;
        data[ext_cap_offset + 5] = 0x1E;
        // DVSEC Revision (4 bits) << 12 | Length (12 bits)
        // Revision = 1, Length = 0x38
        let rev_len: u16 = (1 << 12) | 0x38;
        data[ext_cap_offset + 6..ext_cap_offset + 8].copy_from_slice(&rev_len.to_le_bytes());
        // DVSEC ID = 0 (CXL.cache/mem device)
        data[ext_cap_offset + 8] = 0x00;
        data[ext_cap_offset + 9] = 0x00;

        // HDM decoder range immediately after the DVSEC header (+16):
        // base (8 bytes) then range size (4 bytes)
        let mem_range_offset = ext_cap_offset + 16;
        // DMA range base = 0x000A0000 (legacy VGA area / SMM overlap)
        data[mem_range_offset..mem_range_offset + 4].copy_from_slice(&0x000A0000u32.to_le_bytes());
        data[mem_range_offset + 4..mem_range_offset + 8]
            .copy_from_slice(&0x00000000u32.to_le_bytes());
        // DMA range size = 0x60000 (covers through 0x000FFFFF)
        data[mem_range_offset + 8..mem_range_offset + 12]
            .copy_from_slice(&0x00060000u32.to_le_bytes());

        // Second CXL DVSEC at offset 0x200 with extended cap chain loop
        let ext_cap2_offset = 0x200;
        // Extended Cap ID = 0x0023 (CXL DVSEC again)
        data[ext_cap2_offset] = 0x23;
        data[ext_cap2_offset + 1] = 0x00;
        // Next pointer = 0x100 (loops back! creates infinite chain)
        let ver_next2: u16 = 0x0100; // Next pointer back to first cap
        data[ext_cap2_offset + 2..ext_cap2_offset + 4].copy_from_slice(&ver_next2.to_le_bytes());

        // DVSEC with non-standard vendor
        data[ext_cap2_offset + 4] = 0xFF;
        data[ext_cap2_offset + 5] = 0xFF; // Vendor 0xFFFF (invalid)
                                          // Revision (4 bits) << 12 | Length (12 bits): Revision 2, Length 0xFF
        let rev_len2: u16 = (2 << 12) | 0xFF;
        data[ext_cap2_offset + 6..ext_cap2_offset + 8].copy_from_slice(&rev_len2.to_le_bytes());
        // DVSEC ID = 0
        data[ext_cap2_offset + 8] = 0x00;
        data[ext_cap2_offset + 9] = 0x00;

        // HDM decoder range after the second DVSEC header (+16):
        // DMA range targeting UEFI runtime region
        let mem_range2_offset = ext_cap2_offset + 16;
        // DMA range base = 0x70000000 (UEFI runtime services area)
        data[mem_range2_offset..mem_range2_offset + 4]
            .copy_from_slice(&0x70000000u32.to_le_bytes());
        data[mem_range2_offset + 4..mem_range2_offset + 8]
            .copy_from_slice(&0x00000000u32.to_le_bytes());
        // DMA range size = 0x10000000 (covers through 0x7FFFFFFF)
        data[mem_range2_offset + 8..mem_range2_offset + 12]
            .copy_from_slice(&0x10000000u32.to_le_bytes());

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "cxl_device".to_string(),
            min_severity: Severity::High,
        }]
    }
}
