use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};

const PLUTON_GUID: &[u8] = b"\x7B\x4E\x9A\xD2\x3F\xC1\x4E\x47\x88\x2F\x43\x18\x26\xCC\x24\x1E";
const PLUTON_MAILBOX_MAGIC: &[u8] = &[0x50, 0x4C, 0x54, 0x4E];
const TPM_REDIRECT_MARKER: &[u8] = b"PlutonTPM";
const DICE_LAYER_MARKER: &[u8] = b"DICE_L";

pub struct PlutonDetector;

impl Default for PlutonDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl PlutonDetector {
    pub fn new() -> Self {
        Self
    }

    fn check_mailbox_tampering(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        if let Some(mb_pos) = data
            .windows(PLUTON_MAILBOX_MAGIC.len())
            .position(|w| w == PLUTON_MAILBOX_MAGIC)
        {
            let mailbox_end = (mb_pos + 128).min(data.len());
            let mailbox_region = &data[mb_pos..mailbox_end];

            if mb_pos + 8 < data.len() {
                let status_field =
                    u32::from_le_bytes(data[mb_pos + 4..mb_pos + 8].try_into().unwrap_or([0; 4]));

                if status_field == 0xDEADBEEF || status_field == 0 {
                    findings.push(
                        Finding::new(
                            "pluton",
                            Severity::High,
                            "Microsoft Pluton mailbox with tampered status field",
                            &format!(
                                "Pluton command mailbox at offset 0x{:08X} has status field \
                                 0x{:08X} which indicates either a sentinel value (manipulation) \
                                 or zeroed state (uninitialized/bypassed). A properly functioning \
                                 Pluton should never expose these values.",
                                mb_pos, status_field
                            ),
                        )
                        .with_confidence(0.82)
                        .with_details(serde_json::json!({
                            "offset": format!("0x{:08X}", mb_pos),
                            "status": format!("0x{:08X}", status_field),
                            "technique": "Pluton mailbox manipulation",
                        }))
                        .with_recommendation(
                            "Verify Pluton firmware integrity and check for hardware interposer",
                        ),
                    );
                }

                let response_region = &mailbox_region[8..(64).min(mailbox_region.len())];
                let ff_count = response_region.iter().filter(|&&b| b == 0xFF).count();
                if ff_count > response_region.len() / 2 {
                    findings.push(
                        Finding::new(
                            "pluton",
                            Severity::Medium,
                            "Pluton mailbox response area filled with 0xFF",
                            &format!(
                                "Pluton mailbox response at offset 0x{:08X} is predominantly \
                                 0xFF ({}/{} bytes), suggesting the response was never written \
                                 or has been erased after interception.",
                                mb_pos + 8,
                                ff_count,
                                response_region.len()
                            ),
                        )
                        .with_confidence(0.65)
                        .with_details(serde_json::json!({
                            "offset": format!("0x{:08X}", mb_pos + 8),
                            "ff_ratio": format!("{}/{}", ff_count, response_region.len()),
                        })),
                    );
                }
            }
        }

        findings
    }

    fn check_tpm_redirect(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        let has_pluton_guid = data.windows(PLUTON_GUID.len()).any(|w| w == PLUTON_GUID);
        let has_redirect = data
            .windows(TPM_REDIRECT_MARKER.len())
            .any(|w| w == TPM_REDIRECT_MARKER);

        if has_pluton_guid && has_redirect {
            findings.push(
                Finding::new(
                    "pluton",
                    Severity::High,
                    "Pluton-to-dTPM command redirect detected",
                    "Found Microsoft Pluton GUID alongside PlutonTPM redirect marker. \
                     This indicates TPM commands are being shimmed through Pluton rather \
                     than going directly to the discrete TPM, allowing command interception.",
                )
                .with_confidence(0.85)
                .with_details(serde_json::json!({
                    "pluton_guid": true,
                    "tpm_redirect": true,
                    "technique": "Pluton TPM command interception/shimming",
                }))
                .with_recommendation(
                    "Verify TPM command routing and check Pluton firmware for unauthorized modifications",
                ),
            );
        }

        findings
    }

    fn check_dice_manipulation(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        if let Some(dice_pos) = data
            .windows(DICE_LAYER_MARKER.len())
            .position(|w| w == DICE_LAYER_MARKER)
        {
            let layer_region_end = (dice_pos + 64).min(data.len());
            let layer_region = &data[dice_pos..layer_region_end];

            let hash_offset = DICE_LAYER_MARKER.len() + 4;
            if hash_offset + 32 <= layer_region.len() {
                let hash_region = &layer_region[hash_offset..hash_offset + 32];
                if hash_region.iter().all(|&b| b == 0) || hash_region.iter().all(|&b| b == 0xFF) {
                    findings.push(
                        Finding::new(
                            "pluton",
                            Severity::Critical,
                            "Pluton DICE attestation layer with invalid hash",
                            &format!(
                                "DICE layer at offset 0x{:08X} contains an all-zero or all-FF \
                                 hash where a valid measurement should be. This indicates the \
                                 DICE attestation chain has been broken or manipulated, allowing \
                                 unauthorized firmware to pass attestation.",
                                dice_pos
                            ),
                        )
                        .with_confidence(0.90)
                        .with_details(serde_json::json!({
                            "offset": format!("0x{:08X}", dice_pos),
                            "hash_zeroed": hash_region.iter().all(|&b| b == 0),
                            "hash_ff": hash_region.iter().all(|&b| b == 0xFF),
                            "technique": "DICE attestation layer manipulation",
                        }))
                        .with_recommendation(
                            "Re-provision Pluton DICE chain and verify hardware root of trust integrity",
                        ),
                    );
                }
            }
        }

        findings
    }
}

impl Detector for PlutonDetector {
    fn name(&self) -> &str {
        "pluton"
    }

    fn detect(&self, target_path: &Path) -> Result<Vec<Finding>, DetectorError> {
        self.detect_context(&crate::ScanContext::load(target_path)?)
    }
    fn detect_context(&self, context: &crate::ScanContext) -> Result<Vec<Finding>, DetectorError> {
        let data = context.shared_bytes();
        let mut findings = Vec::new();

        findings.extend(self.check_mailbox_tampering(&data));
        findings.extend(self.check_tpm_redirect(&data));
        findings.extend(self.check_dice_manipulation(&data));

        Ok(findings)
    }
}
