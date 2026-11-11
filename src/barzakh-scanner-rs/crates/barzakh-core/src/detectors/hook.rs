use std::path::Path;

use byteorder::{LittleEndian, ReadBytesExt};
use std::io::Cursor;

use crate::baseline::Baseline;
use crate::detector::{Detector, DetectorError, Finding, Severity};

const EFI_BOOT_SERVICES_SIGNATURE: u64 = 0x56524553_544F4F42; // "BOOTSERV"

const BOOT_SERVICE_NAMES: &[&str] = &[
    "RaiseTPL",
    "RestoreTPL",
    "AllocatePages",
    "FreePages",
    "GetMemoryMap",
    "AllocatePool",
    "FreePool",
    "CreateEvent",
    "SetTimer",
    "WaitForEvent",
    "SignalEvent",
    "CloseEvent",
    "CheckEvent",
    "InstallProtocolInterface",
    "ReinstallProtocolInterface",
    "UninstallProtocolInterface",
    "HandleProtocol",
    "Reserved",
    "RegisterProtocolNotify",
    "LocateHandle",
    "LocateDevicePath",
    "InstallConfigurationTable",
    "LoadImage",
    "StartImage",
    "Exit",
    "UnloadImage",
    "ExitBootServices",
    "GetNextMonotonicCount",
    "Stall",
    "SetWatchdogTimer",
];

pub struct HookDetector {
    #[allow(dead_code)]
    baseline: Option<Baseline>,
}

impl HookDetector {
    pub fn new(baseline: Option<Baseline>) -> Self {
        Self { baseline }
    }

    fn find_boot_services_table(&self, data: &[u8]) -> Option<usize> {
        let sig_bytes = EFI_BOOT_SERVICES_SIGNATURE.to_le_bytes();
        data.windows(8).position(|w| w == sig_bytes)
    }

    fn verify_table_crc32(&self, data: &[u8], table_offset: usize) -> Option<(u32, u32)> {
        if table_offset + 24 > data.len() {
            return None;
        }
        let mut cursor = Cursor::new(&data[table_offset..]);
        let _signature = cursor.read_u64::<LittleEndian>().ok()?;
        let _revision = cursor.read_u32::<LittleEndian>().ok()?;
        let header_size = cursor.read_u32::<LittleEndian>().ok()? as usize;
        let stored_crc = cursor.read_u32::<LittleEndian>().ok()?;

        if table_offset + header_size > data.len() {
            return None;
        }

        // Zero out CRC field for computation
        let mut header_copy = data[table_offset..table_offset + header_size].to_vec();
        if header_copy.len() >= 20 {
            header_copy[16..20].fill(0);
        }

        let computed_crc = crc32fast::hash(&header_copy);
        Some((stored_crc, computed_crc))
    }

    fn check_function_pointers(&self, data: &[u8], table_offset: usize) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Function pointers start after the table header (24 bytes)
        let ptrs_offset = table_offset + 24;
        let ptr_size = 8; // 64-bit pointers

        for (i, name) in BOOT_SERVICE_NAMES.iter().enumerate() {
            let offset = ptrs_offset + i * ptr_size;
            if offset + ptr_size > data.len() {
                break;
            }

            let ptr =
                u64::from_le_bytes(data[offset..offset + ptr_size].try_into().unwrap_or([0; 8]));

            // Check for obviously invalid pointers
            if ptr == 0 || ptr == u64::MAX {
                continue;
            }

            // Check if pointer is suspiciously outside typical UEFI address range
            // UEFI code typically lives in 0x00000000_00000000 - 0x00000000_FFFFFFFF
            // or in high memory 0x7F000000_00000000+
            let in_low_range = ptr < 0x1_0000_0000;
            let in_high_range = ptr >= 0x7F00_0000_0000_0000;

            if !in_low_range && !in_high_range {
                findings.push(
                    Finding::new(
                        "hook",
                        Severity::Critical,
                        &format!("Boot Services hook detected: {}", name),
                        &format!(
                            "Function pointer for {} at table+0x{:X} points to \
                             suspicious address 0x{:016X} outside expected UEFI range.",
                            name,
                            i * ptr_size + 24,
                            ptr
                        ),
                    )
                    .with_confidence(0.85)
                    .with_details(serde_json::json!({
                        "service": name,
                        "index": i,
                        "pointer": format!("0x{:016X}", ptr),
                        "table_offset": format!("0x{:08X}", table_offset),
                    }))
                    .with_recommendation(
                        "Boot Services Table has been modified. Investigate for rootkit.",
                    ),
                );
            }
        }

        findings
    }
}

impl Detector for HookDetector {
    fn name(&self) -> &str {
        "hook"
    }

    fn detect(&self, target_path: &Path) -> Result<Vec<Finding>, DetectorError> {
        self.detect_context(&crate::ScanContext::load(target_path)?)
    }
    fn detect_context(&self, context: &crate::ScanContext) -> Result<Vec<Finding>, DetectorError> {
        let data = context.shared_bytes();
        let mut findings = Vec::new();

        if let Some(table_offset) = self.find_boot_services_table(&data) {
            // CRC32 verification
            if let Some((stored, computed)) = self.verify_table_crc32(&data, table_offset) {
                if stored != computed {
                    findings.push(
                        Finding::new(
                            "hook",
                            Severity::Critical,
                            "Boot Services Table CRC32 mismatch",
                            &format!(
                                "BST CRC32 verification failed. Stored: 0x{:08X}, Computed: 0x{:08X}. \
                                 The table has been modified in memory.",
                                stored, computed
                            ),
                        )
                        .with_confidence(0.95)
                        .with_details(serde_json::json!({
                            "stored_crc": format!("0x{:08X}", stored),
                            "computed_crc": format!("0x{:08X}", computed),
                            "table_offset": format!("0x{:08X}", table_offset),
                        }))
                        .with_recommendation(
                            "Boot Services Table integrity compromised. System may be infected.",
                        ),
                    );
                }
            }

            // Function pointer validation
            findings.extend(self.check_function_pointers(&data, table_offset));
        }

        Ok(findings)
    }
}
