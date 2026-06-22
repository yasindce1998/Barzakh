use anyhow::Result;

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

pub struct AcpiBackdoorPayload;

impl Payload for AcpiBackdoorPayload {
    fn name(&self) -> &str {
        "acpi_backdoor"
    }

    fn arch(&self) -> Arch {
        Arch::X86_64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x2000);
        let mut data = vec![0u8; size];

        // At offset 0x000: DSDT header
        // Signature "DSDT" (4 bytes)
        data[0x000..0x004].copy_from_slice(b"DSDT");
        // Length = 0x00000200 (512 bytes)
        let length: u32 = 0x00000200;
        data[0x004..0x008].copy_from_slice(&length.to_le_bytes());
        // Revision = 2
        data[0x008] = 0x02;
        // Checksum = 0x00 (intentionally WRONG — sum of 512 bytes won't be 0 mod 256)
        data[0x009] = 0x00;
        // OemId = "INJECT" (6 bytes)
        data[0x00A..0x010].copy_from_slice(b"INJECT");
        // OemTableId = "BADZAKH\0" (8 bytes)
        data[0x010..0x018].copy_from_slice(b"BADZAKH\0");
        // OemRevision (4 bytes)
        let oem_rev: u32 = 0x00000001;
        data[0x018..0x01C].copy_from_slice(&oem_rev.to_le_bytes());
        // CreatorId (4 bytes)
        data[0x01C..0x020].copy_from_slice(b"INTL");
        // CreatorRevision (4 bytes)
        let creator_rev: u32 = 0x20200101;
        data[0x020..0x024].copy_from_slice(&creator_rev.to_le_bytes());

        // At offset 0x100: Suspicious AML OperationRegion opcode
        let offset = 0x100;
        // ExtOpPrefix + OpRegionOp
        data[offset] = 0x5B;
        data[offset + 1] = 0x80;
        // Name "HACK" (4 bytes)
        data[offset + 2..offset + 6].copy_from_slice(b"HACK");
        // RegionSpace = 0x00 (SystemMemory)
        data[offset + 6] = 0x00;
        // Address = 0xFFFF800000000000 (kernel space, 8 bytes LE)
        let kernel_addr: u64 = 0xFFFF_8000_0000_0000;
        // AML encodes integers with prefix byte; use raw bytes for the address
        data[offset + 7] = 0x0E; // QWordPrefix in AML
        data[offset + 8..offset + 16].copy_from_slice(&kernel_addr.to_le_bytes());
        // Length = 0x1000
        data[offset + 16] = 0x0B; // WordPrefix in AML
        let region_len: u16 = 0x1000;
        data[offset + 17..offset + 19].copy_from_slice(&region_len.to_le_bytes());

        // At offset 0x200-0x600: 15+ additional "SSDT" signatures
        // spaced 64 bytes apart with minimal table headers between them
        // to trigger "Abnormal SSDT table count"
        let base_offset = 0x200;
        for i in 0..16 {
            let table_offset = base_offset + (i * 64);
            if table_offset + 36 > size {
                break;
            }
            // Signature "SSDT"
            data[table_offset..table_offset + 4].copy_from_slice(b"SSDT");
            // Length (minimal: 36 bytes = header only)
            let tbl_length: u32 = 0x00000024;
            data[table_offset + 4..table_offset + 8].copy_from_slice(&tbl_length.to_le_bytes());
            // Revision
            data[table_offset + 8] = 0x02;
            // Checksum (intentionally wrong)
            data[table_offset + 9] = 0xFF;
            // OemId
            data[table_offset + 10..table_offset + 16].copy_from_slice(b"INJECT");
            // OemTableId with index
            let table_id = format!("SSDT{:04}", i);
            data[table_offset + 16..table_offset + 24].copy_from_slice(&table_id.as_bytes()[..8]);
        }

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "acpi_integrity".to_string(),
            min_severity: Severity::High,
        }]
    }
}
