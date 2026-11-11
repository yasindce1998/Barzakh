use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};

const BOOTCTRL_MAGIC: [u8; 4] = [0x42, 0x43, 0x48, 0x4C];
const SLOT_A_OFFSET: usize = 8;
const SLOT_B_OFFSET: usize = 16;
const MERGE_STATUS_OFFSET: usize = 32;

pub struct AndroidBootctrlDetector;

impl Default for AndroidBootctrlDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl AndroidBootctrlDetector {
    pub fn new() -> Self {
        Self
    }

    fn check_dual_slot_unbootable(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        if let Some(pos) = data
            .windows(BOOTCTRL_MAGIC.len())
            .position(|w| w == BOOTCTRL_MAGIC)
        {
            let slot_a_off = pos + SLOT_A_OFFSET;
            let slot_b_off = pos + SLOT_B_OFFSET;

            if data.len() > slot_b_off + 8 {
                let slot_a_bootable = data[slot_a_off + 2];
                let slot_b_bootable = data[slot_b_off + 2];

                if slot_a_bootable == 0 && slot_b_bootable == 0 {
                    findings.push(
                        Finding::new(
                            "android_bootctrl",
                            Severity::Critical,
                            "Boot Control metadata with both A/B slots marked unbootable",
                            &format!(
                                "Found boot_ctrl structure at offset 0x{:08X} with both slot_a \
                                 and slot_b marked as unbootable (bootable=0). This will brick \
                                 the device on next reboot as the bootloader has no valid slot \
                                 to boot from. Indicates deliberate sabotage of A/B metadata.",
                                pos
                            ),
                        )
                        .with_confidence(0.96)
                        .with_details(serde_json::json!({
                            "offset": format!("0x{:08X}", pos),
                            "slot_a_bootable": false,
                            "slot_b_bootable": false,
                            "technique": "A/B slot metadata poisoning for denial-of-boot",
                        }))
                        .with_recommendation(
                            "Restore boot_ctrl from fastboot; mark at least one slot as bootable",
                        ),
                    );
                }
            }
        }

        findings
    }

    fn check_retry_count_tampering(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        if let Some(pos) = data
            .windows(BOOTCTRL_MAGIC.len())
            .position(|w| w == BOOTCTRL_MAGIC)
        {
            let slot_a_off = pos + SLOT_A_OFFSET;
            let slot_b_off = pos + SLOT_B_OFFSET;

            if data.len() > slot_b_off + 8 {
                let slot_a_retries = data[slot_a_off + 3];
                let slot_b_retries = data[slot_b_off + 3];

                if slot_a_retries == 0 && slot_b_retries == 0 {
                    let slot_a_bootable = data[slot_a_off + 2];
                    let slot_b_bootable = data[slot_b_off + 2];

                    if slot_a_bootable == 1 || slot_b_bootable == 1 {
                        findings.push(
                            Finding::new(
                                "android_bootctrl",
                                Severity::High,
                                "Boot Control slots with zero remaining boot retries",
                                &format!(
                                    "Found boot_ctrl at offset 0x{:08X} with retry_count=0 for \
                                     both slots while at least one slot is still marked bootable. \
                                     If the next boot fails, the slot will be permanently marked \
                                     unbootable with no recovery attempts. This creates a \
                                     one-failure-away-from-brick condition.",
                                    pos
                                ),
                            )
                            .with_confidence(0.84)
                            .with_details(serde_json::json!({
                                "offset": format!("0x{:08X}", pos),
                                "slot_a_retries": 0,
                                "slot_b_retries": 0,
                                "technique": "A/B retry count exhaustion for conditional bricking",
                            }))
                            .with_recommendation(
                                "Reset retry counts to default (typically 7); investigate how they were exhausted",
                            ),
                        );
                    }
                }
            }
        }

        findings
    }

    fn check_merge_status_corruption(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        if let Some(pos) = data
            .windows(BOOTCTRL_MAGIC.len())
            .position(|w| w == BOOTCTRL_MAGIC)
        {
            let merge_off = pos + MERGE_STATUS_OFFSET;
            if data.len() > merge_off + 1 {
                let merge_status = data[merge_off];

                if merge_status > 3 {
                    findings.push(
                        Finding::new(
                            "android_bootctrl",
                            Severity::High,
                            "Boot Control merge_status contains invalid value",
                            &format!(
                                "Found boot_ctrl at offset 0x{:08X} with merge_status={} (valid \
                                 range: 0-3: NONE/UNKNOWN/SNAPSHOTTED/MERGING/CANCELLED). An \
                                 invalid merge_status can confuse the Virtual A/B update engine \
                                 and prevent OTA updates from completing.",
                                pos, merge_status
                            ),
                        )
                        .with_confidence(0.80)
                        .with_details(serde_json::json!({
                            "offset": format!("0x{:08X}", pos),
                            "merge_status": merge_status,
                            "valid_range": "0-3",
                            "technique": "Virtual A/B merge status corruption",
                        }))
                        .with_recommendation(
                            "Reset merge_status to NONE (0) via fastboot or recovery",
                        ),
                    );
                }
            }
        }

        findings
    }
}

impl Detector for AndroidBootctrlDetector {
    fn name(&self) -> &str {
        "android_bootctrl"
    }

    fn detect(&self, target_path: &Path) -> Result<Vec<Finding>, DetectorError> {
        self.detect_context(&crate::ScanContext::load(target_path)?)
    }

    fn detect_context(&self, context: &crate::ScanContext) -> Result<Vec<Finding>, DetectorError> {
        let data = context.shared_bytes();
        let mut findings = Vec::new();

        findings.extend(self.check_dual_slot_unbootable(&data));
        findings.extend(self.check_retry_count_tampering(&data));
        findings.extend(self.check_merge_status_corruption(&data));

        Ok(findings)
    }
}
