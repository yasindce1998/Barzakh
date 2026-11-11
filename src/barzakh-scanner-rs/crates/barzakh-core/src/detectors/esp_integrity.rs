use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};

const FAT32_BOOT_SIGNATURE: &[u8] = &[0x55, 0xAA];
const EFI_BOOT_PATH: &[u8] = b"\\EFI\\Boot\\";
const BOOTX64_EFI: &[u8] = b"bootx64.efi";
const WINDOWS_BOOT_MGR_GUID: &[u8] =
    b"\x04\x06\x97\x9D\x21\x41\xB6\x40\xA2\x71\x12\x82\x88\x72\x67\x98";

pub struct EspIntegrityDetector;

impl Default for EspIntegrityDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl EspIntegrityDetector {
    pub fn new() -> Self {
        Self
    }

    fn check_multiple_boot_entries(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut boot_path_count = 0;
        let mut pos = 0;

        while pos < data.len().saturating_sub(EFI_BOOT_PATH.len()) {
            if data[pos..].starts_with(EFI_BOOT_PATH) {
                boot_path_count += 1;
                pos += EFI_BOOT_PATH.len();
            } else {
                pos += 1;
            }
        }

        if boot_path_count >= 3 {
            findings.push(
                Finding::new(
                    "esp_integrity",
                    Severity::High,
                    "Multiple EFI boot path entries suggest ESP manipulation",
                    &format!(
                        "Found {} references to \\EFI\\Boot\\ paths. Multiple boot entries may \
                         indicate ESP persistence where a rootkit registers additional bootloaders \
                         alongside the legitimate one (MosaicRegressor/FinSpy/ESPecter pattern).",
                        boot_path_count
                    ),
                )
                .with_confidence(0.78)
                .with_details(serde_json::json!({
                    "boot_path_count": boot_path_count,
                    "technique": "ESP persistence (MosaicRegressor/FinSpy/ESPecter)",
                }))
                .with_recommendation(
                    "Verify all boot entries in ESP are legitimate and signed correctly",
                ),
            );
        }

        findings
    }

    fn check_dxe_after_bootloader(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        if let Some(boot_pos) = data
            .windows(BOOTX64_EFI.len())
            .position(|w| w == BOOTX64_EFI)
        {
            let search_start = boot_pos + BOOTX64_EFI.len();
            let search_end = (search_start + 4096).min(data.len());

            if search_start < data.len() {
                let region = &data[search_start..search_end];

                let pe_magic = b"MZ";
                if let Some(pe_pos) = region.windows(2).position(|w| w == pe_magic) {
                    let abs_pe_pos = search_start + pe_pos;
                    if abs_pe_pos + 64 < data.len() {
                        let pe_offset = u32::from_le_bytes(
                            data[abs_pe_pos + 60..abs_pe_pos + 64]
                                .try_into()
                                .unwrap_or([0; 4]),
                        ) as usize;

                        if pe_offset < 0x200
                            && abs_pe_pos + pe_offset + 4 <= data.len()
                            && &data[abs_pe_pos + pe_offset..abs_pe_pos + pe_offset + 4]
                                == b"PE\x00\x00"
                        {
                            findings.push(
                                Finding::new(
                                    "esp_integrity",
                                    Severity::Critical,
                                    "DXE loader stub embedded after legitimate boot manager",
                                    &format!(
                                        "Found PE/COFF image at offset 0x{:08X}, {} bytes after \
                                         bootx64.efi path reference. This pattern matches ESP \
                                         rootkits that inject a DXE loader alongside the \
                                         legitimate Windows Boot Manager.",
                                        abs_pe_pos,
                                        abs_pe_pos - boot_pos
                                    ),
                                )
                                .with_confidence(0.88)
                                .with_details(serde_json::json!({
                                    "pe_offset": format!("0x{:08X}", abs_pe_pos),
                                    "boot_ref_offset": format!("0x{:08X}", boot_pos),
                                    "gap_bytes": abs_pe_pos - boot_pos,
                                    "technique": "ESP DXE injection",
                                }))
                                .with_recommendation(
                                    "Remove injected PE from ESP partition and restore boot manager from known-good source",
                                ),
                            );
                        }
                    }
                }
            }
        }

        findings
    }

    fn check_fat32_boot_sector_anomaly(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        if data.len() >= 512 && data[510..512] == *FAT32_BOOT_SIGNATURE {
            let has_efi_path = data
                .windows(EFI_BOOT_PATH.len())
                .any(|w| w == EFI_BOOT_PATH);
            let has_win_guid = data
                .windows(WINDOWS_BOOT_MGR_GUID.len())
                .any(|w| w == WINDOWS_BOOT_MGR_GUID);

            if has_efi_path && has_win_guid {
                let jmp_byte = data[0];
                if jmp_byte != 0xEB && jmp_byte != 0xE9 {
                    findings.push(
                        Finding::new(
                            "esp_integrity",
                            Severity::High,
                            "FAT32 boot sector with non-standard jump instruction",
                            &format!(
                                "ESP partition boot sector starts with 0x{:02X} instead of \
                                 standard JMP (0xEB/0xE9). Combined with EFI path and Windows \
                                 Boot Manager GUID presence, this suggests boot sector modification.",
                                jmp_byte
                            ),
                        )
                        .with_confidence(0.72)
                        .with_details(serde_json::json!({
                            "first_byte": format!("0x{:02X}", jmp_byte),
                            "has_efi_path": true,
                            "has_windows_guid": true,
                        })),
                    );
                }
            }
        }

        findings
    }
}

impl Detector for EspIntegrityDetector {
    fn name(&self) -> &str {
        "esp_integrity"
    }

    fn detect(&self, target_path: &Path) -> Result<Vec<Finding>, DetectorError> {
        self.detect_context(&crate::ScanContext::load(target_path)?)
    }
    fn detect_context(&self, context: &crate::ScanContext) -> Result<Vec<Finding>, DetectorError> {
        let data = context.shared_bytes();
        let mut findings = Vec::new();

        findings.extend(self.check_multiple_boot_entries(&data));
        findings.extend(self.check_dxe_after_bootloader(&data));
        findings.extend(self.check_fat32_boot_sector_anomaly(&data));

        Ok(findings)
    }
}
