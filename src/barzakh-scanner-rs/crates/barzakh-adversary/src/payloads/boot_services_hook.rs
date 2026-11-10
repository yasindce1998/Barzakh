use anyhow::Result;
use byteorder::{LittleEndian, WriteBytesExt};

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

const EFI_BOOT_SERVICES_SIGNATURE: u64 = 0x56524553_544F4F42;
const BST_REVISION: u32 = 0x0002_0046; // UEFI 2.70
const BST_HEADER_SIZE: u32 = 24;
const NUM_BOOT_SERVICES: usize = 28;

pub struct BootServicesHookPayload;

impl Payload for BootServicesHookPayload {
    fn name(&self) -> &str {
        "boot_services_hook"
    }

    fn arch(&self) -> Arch {
        Arch::X86_64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let table_offset = 0x1000;
        let total_size = table_offset + BST_HEADER_SIZE as usize + NUM_BOOT_SERVICES * 8 + 0x100;
        let size = config.size.max(total_size);
        let mut data = vec![0u8; size];

        // EFI_TABLE_HEADER.CRC32 covers the header with the CRC field
        // itself zeroed — exactly what the `hook` detector recomputes.
        let mut crc_input = [0u8; BST_HEADER_SIZE as usize];
        crc_input[0..8].copy_from_slice(&EFI_BOOT_SERVICES_SIGNATURE.to_le_bytes());
        crc_input[8..12].copy_from_slice(&BST_REVISION.to_le_bytes());
        crc_input[12..16].copy_from_slice(&BST_HEADER_SIZE.to_le_bytes());
        let healthy_crc = crc32fast::hash(&crc_input);

        let mut cursor = std::io::Cursor::new(&mut data[table_offset..]);

        // EFI_TABLE_HEADER: Signature (8) + Revision (4) + HeaderSize (4) + CRC32 (4) + Reserved (4)
        cursor.write_u64::<LittleEndian>(EFI_BOOT_SERVICES_SIGNATURE)?;
        cursor.write_u32::<LittleEndian>(BST_REVISION)?;
        cursor.write_u32::<LittleEndian>(BST_HEADER_SIZE)?;
        // The armed variant carries a deliberately WRONG CRC32 (tamper
        // evidence); the kill-switched variant carries the genuine
        // healthy checksum a legitimately-formed table would have.
        cursor.write_u32::<LittleEndian>(if config.dormant {
            healthy_crc
        } else {
            0xDEAD_BEEF
        })?;
        // Reserved
        cursor.write_u32::<LittleEndian>(0)?;

        // Write 28 function pointers. A legitimately-formed table keeps
        // every entry point inside the DXE core load range
        // (0x0600_0000-0x0800_0000); the armed variant hooks three
        // services to far-away attacker addresses.
        for i in 0..NUM_BOOT_SERVICES {
            let legitimate = 0x0650_0000u64 + (i as u64 * 0x40);
            let ptr: u64 = if config.dormant {
                // Kill-switched variant: the implant never armed — every
                // entry point stays a legitimate DXE address.
                legitimate
            } else {
                match i {
                    // AllocatePool (index 5) — hooked to suspicious address
                    5 => 0x0000_4000_DEAD_0000,
                    // LoadImage (index 22) — hooked
                    22 => 0x0000_7000_CAFE_0000,
                    // ExitBootServices (index 26) — hooked
                    26 => 0x0000_5000_BABE_0000,
                    // All others — legitimate DXE address
                    _ => legitimate,
                }
            };
            cursor.write_u64::<LittleEndian>(ptr)?;
        }

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "hook".to_string(),
            min_severity: Severity::Critical,
        }]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use barzakh_core::BarzakhScanner;

    fn config(dormant: bool) -> PayloadConfig {
        PayloadConfig {
            arch: Arch::X86_64,
            size: 0x10000,
            dormant,
        }
    }

    fn scan(data: &[u8], name: &str) -> Vec<barzakh_core::Finding> {
        let dir = std::env::temp_dir().join("barzakh-bs-hook-tests");
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let path = dir.join(name);
        std::fs::write(&path, data).expect("write payload");
        BarzakhScanner::new(None).scan(&path, None).findings
    }

    /// The kill-switched variant must be a *well-formed* dormant table:
    /// genuine CRC32 (recomputed exactly like the `hook` detector does)
    /// and every entry point inside the legitimate DXE load range, so
    /// neither `hook` nor the `live` BST-pointer walk fires on it.
    /// Regression: the range intentional-miss suite caught the dormant
    /// variant tripping `hook` (CRC mismatch) and `live` (pointers in
    /// the flash range instead of the DXE range).
    #[test]
    fn dormant_table_is_well_formed_and_undetected() {
        let data = BootServicesHookPayload.generate(&config(true)).unwrap();

        // Header CRC must be the genuine checksum of the header with
        // the CRC field zeroed — exactly what the detector recomputes.
        let header = &data[0x1000..0x1000 + BST_HEADER_SIZE as usize];
        let mut crc_input = header.to_vec();
        crc_input[16..20].fill(0);
        assert_eq!(
            u32::from_le_bytes(header[16..20].try_into().unwrap()),
            crc32fast::hash(&crc_input),
            "dormant CRC32 must validate"
        );

        // Every entry point must sit inside the DXE core load range.
        for i in 0..NUM_BOOT_SERVICES {
            let ptr = u64::from_le_bytes(
                data[0x1000 + 24 + i * 8..0x1000 + 24 + i * 8 + 8]
                    .try_into()
                    .unwrap(),
            );
            assert!(
                (0x0600_0000..=0x0800_0000).contains(&ptr),
                "dormant pointer {ptr:#x} must stay in the DXE range"
            );
        }

        let findings = scan(&data, "dormant.bin");
        assert!(
            !findings.iter().any(|f| f.detector == "hook"),
            "hook detector must stay quiet on the dormant variant"
        );
        assert!(
            !findings.iter().any(|f| f.title.starts_with("BST hook")),
            "live BST-pointer walk must stay quiet on the dormant variant"
        );
    }

    /// The armed variant keeps the tampered CRC and the three far-away
    /// hooks, and must still be detected critically.
    #[test]
    fn armed_table_is_detected() {
        let data = BootServicesHookPayload.generate(&config(false)).unwrap();
        assert_eq!(
            u32::from_le_bytes(data[0x1010..0x1014].try_into().unwrap()),
            0xDEAD_BEEF,
            "armed CRC32 stays deliberately wrong (tamper evidence)"
        );
        let findings = scan(&data, "armed.bin");
        assert!(findings.iter().any(|f| {
            f.detector == "hook" && matches!(f.severity, barzakh_core::Severity::Critical)
        }));
    }
}
