use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};

const IHISI_MAGIC: &[u8] = b"$IHISI$";
const INSYDE_CAPSULE_GUID: [u8; 16] = [
    0x4F, 0x1C, 0x52, 0x31, 0x5F, 0x93, 0xAE, 0x4F, 0xB4, 0x11, 0xA2, 0x13, 0xB7, 0x64, 0xFF, 0xE5,
];
const INSYDE_FLASH_PROTECT: &[u8] = b"InsydeFlashProtect";
const INSYDE_VENDOR: &[u8] = b"Insyde Corp.";
const SW_SMI_PORT: u8 = 0xB2;

pub struct InsydeSmmDetector;

impl Default for InsydeSmmDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl InsydeSmmDetector {
    pub fn new() -> Self {
        Self
    }

    fn check_ihisi_smm_handler(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        if let Some(pos) = data
            .windows(IHISI_MAGIC.len())
            .position(|w| w == IHISI_MAGIC)
        {
            let region_end = (pos + 256).min(data.len());
            let region = &data[pos..region_end];

            let has_smi_trigger = region.contains(&SW_SMI_PORT);
            let has_insyde_smi_cmd = region.contains(&0x4F);

            if has_smi_trigger && has_insyde_smi_cmd {
                findings.push(
                    Finding::new(
                        "insyde_smm",
                        Severity::Critical,
                        "Insyde H2O IHISI SMM handler with capsule update SMI trigger",
                        &format!(
                            "Found Insyde IHISI (H2O Software Interface) marker at offset \
                             0x{:08X} with SW SMI port (0xB2) trigger and Insyde capsule \
                             command (0x4F). Vulnerable to SMM buffer overflow via malformed \
                             capsule (CVE-2022-24894, CVE-2023-27373).",
                            pos
                        ),
                    )
                    .with_confidence(0.88)
                    .with_details(serde_json::json!({
                        "offset": format!("0x{:08X}", pos),
                        "smi_port": "0xB2",
                        "insyde_cmd": "0x4F",
                        "cves": ["CVE-2022-24894", "CVE-2023-27373"],
                        "technique": "Insyde H2O IHISI SMM handler exploitation",
                    }))
                    .with_recommendation(
                        "Update Insyde H2O firmware to latest version with SMM hardening patches",
                    ),
                );
            }
        }

        findings
    }

    fn check_capsule_overflow(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        if let Some(pos) = data
            .windows(INSYDE_CAPSULE_GUID.len())
            .position(|w| w == INSYDE_CAPSULE_GUID)
        {
            // Check capsule image size field (offset +24 from GUID start)
            let size_offset = pos + 24;
            if size_offset + 4 <= data.len() {
                let capsule_size = u32::from_le_bytes([
                    data[size_offset],
                    data[size_offset + 1],
                    data[size_offset + 2],
                    data[size_offset + 3],
                ]);

                if capsule_size > 0x10000000 {
                    findings.push(
                        Finding::new(
                            "insyde_smm",
                            Severity::Critical,
                            "Insyde H2O capsule with oversized image field (SMM overflow trigger)",
                            &format!(
                                "Insyde firmware capsule at offset 0x{:08X} declares image size \
                                 0x{:08X} which exceeds SMRAM boundaries. This is a classic \
                                 trigger for SMM buffer overflow in Insyde's capsule handler.",
                                pos, capsule_size
                            ),
                        )
                        .with_confidence(0.93)
                        .with_details(serde_json::json!({
                            "capsule_offset": format!("0x{:08X}", pos),
                            "declared_size": format!("0x{:08X}", capsule_size),
                            "technique": "SMM buffer overflow via oversized capsule",
                        }))
                        .with_recommendation(
                            "Reject capsules with size exceeding SMRAM region; apply Insyde security patches",
                        ),
                    );
                }
            }
        }

        findings
    }

    fn check_flash_protect_disable(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        if let Some(pos) = data
            .windows(INSYDE_FLASH_PROTECT.len())
            .position(|w| w == INSYDE_FLASH_PROTECT)
        {
            let value_offset = pos + INSYDE_FLASH_PROTECT.len() + 0x20;
            if value_offset < data.len() && data[value_offset] == 0x00 {
                findings.push(
                    Finding::new(
                        "insyde_smm",
                        Severity::High,
                        "Insyde FlashProtect variable disabled",
                        &format!(
                            "InsydeFlashProtect variable at offset 0x{:08X} is set to disabled \
                             (0x00). This removes SPI flash write protection, allowing \
                             unauthorized firmware modification.",
                            pos
                        ),
                    )
                    .with_confidence(0.85)
                    .with_details(serde_json::json!({
                        "offset": format!("0x{:08X}", pos),
                        "flash_protect_disabled": true,
                        "technique": "Flash protection disable via NVRAM variable",
                    }))
                    .with_recommendation(
                        "Re-enable InsydeFlashProtect and audit for unauthorized NVRAM changes",
                    ),
                );
            }
        }

        findings
    }

    fn check_smm_shellcode_pattern(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        let has_insyde = data
            .windows(INSYDE_VENDOR.len())
            .any(|w| w == INSYDE_VENDOR);

        if !has_insyde {
            return findings;
        }

        // Look for NOP sled followed by x86_64 stack pivot (MOV RSP pattern: 0x48 0xBC)
        for i in 0..data.len().saturating_sub(20) {
            let nop_count = data[i..].iter().take(16).filter(|&&b| b == 0x90).count();
            if nop_count >= 8 && i + 18 < data.len() && data[i + 16] == 0x48 && data[i + 17] == 0xBC
            {
                findings.push(
                    Finding::new(
                        "insyde_smm",
                        Severity::Critical,
                        "SMM shellcode pattern detected in Insyde firmware image",
                        &format!(
                            "NOP sled followed by x86_64 RSP pivot instruction at offset \
                             0x{:08X}. Indicates SMM exploitation payload targeting Insyde \
                             H2O capsule handler vulnerability.",
                            i
                        ),
                    )
                    .with_confidence(0.82)
                    .with_details(serde_json::json!({
                        "offset": format!("0x{:08X}", i),
                        "nop_sled_length": nop_count,
                        "pivot_instruction": "MOV RSP, imm64",
                        "technique": "SMM shellcode injection via capsule overflow",
                    }))
                    .with_recommendation(
                        "Quarantine firmware image and investigate for SMM rootkit installation",
                    ),
                );
                break;
            }
        }

        findings
    }
}

impl Detector for InsydeSmmDetector {
    fn name(&self) -> &str {
        "insyde_smm"
    }

    fn detect(&self, target_path: &Path) -> Result<Vec<Finding>, DetectorError> {
        self.detect_context(&crate::ScanContext::load(target_path)?)
    }
    fn detect_context(&self, context: &crate::ScanContext) -> Result<Vec<Finding>, DetectorError> {
        let data = context.shared_bytes();
        let mut findings = Vec::new();

        findings.extend(self.check_ihisi_smm_handler(&data));
        findings.extend(self.check_capsule_overflow(&data));
        findings.extend(self.check_flash_protect_disable(&data));
        findings.extend(self.check_smm_shellcode_pattern(&data));

        Ok(findings)
    }
}
