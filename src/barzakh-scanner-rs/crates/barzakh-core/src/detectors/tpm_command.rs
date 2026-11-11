use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};

const TPM2_ST_SESSIONS: u16 = 0x8002;
const TPM2_ST_NO_SESSIONS: u16 = 0x8001;
const TPM2_CC_CERTIFY_CREATION: u32 = 0x0000014A;
const TPM2_CC_NV_WRITE: u32 = 0x00000137;

pub struct TpmCommandDetector;

impl Default for TpmCommandDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl TpmCommandDetector {
    pub fn new() -> Self {
        Self
    }

    fn check_command_size_overflow(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        for i in 0..data.len().saturating_sub(10) {
            let tag = u16::from_be_bytes(data[i..i + 2].try_into().unwrap_or([0; 2]));

            if tag == TPM2_ST_SESSIONS || tag == TPM2_ST_NO_SESSIONS {
                let command_size =
                    u32::from_be_bytes(data[i + 2..i + 6].try_into().unwrap_or([0; 4])) as usize;

                let command_code =
                    u32::from_be_bytes(data[i + 6..i + 10].try_into().unwrap_or([0; 4]));

                if command_code == 0 || command_code > 0x200 {
                    continue;
                }

                let remaining_data = data.len() - i;
                if command_size > remaining_data + 64 && command_size < 0x100000 {
                    findings.push(
                        Finding::new(
                            "tpm_command",
                            Severity::Critical,
                            "CVE-2023-1017/1018: TPM 2.0 command buffer size overflow",
                            &format!(
                                "TPM2 command at offset 0x{:08X} (tag=0x{:04X}, CC=0x{:08X}) \
                                 declares commandSize={} but only {} bytes remain in buffer. \
                                 This triggers an out-of-bounds write in the TPM reference \
                                 implementation's CryptParameterDecrypt routine.",
                                i, tag, command_code, command_size, remaining_data
                            ),
                        )
                        .with_confidence(0.92)
                        .with_details(serde_json::json!({
                            "offset": format!("0x{:08X}", i),
                            "tag": format!("0x{:04X}", tag),
                            "command_code": format!("0x{:08X}", command_code),
                            "declared_size": command_size,
                            "available_bytes": remaining_data,
                            "cve": "CVE-2023-1017/CVE-2023-1018",
                            "technique": "TPM 2.0 reference implementation buffer overflow",
                        }))
                        .with_recommendation(
                            "Update TPM firmware to patched version and validate command buffer bounds",
                        ),
                    );
                }
            }
        }

        findings
    }

    fn check_auth_area_overflow(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        for i in 0..data.len().saturating_sub(14) {
            let tag = u16::from_be_bytes(data[i..i + 2].try_into().unwrap_or([0; 2]));

            if tag == TPM2_ST_SESSIONS {
                let command_size =
                    u32::from_be_bytes(data[i + 2..i + 6].try_into().unwrap_or([0; 4])) as usize;
                let command_code =
                    u32::from_be_bytes(data[i + 6..i + 10].try_into().unwrap_or([0; 4]));

                if (command_code == TPM2_CC_CERTIFY_CREATION || command_code == TPM2_CC_NV_WRITE)
                    && i + 14 < data.len()
                {
                    let auth_size =
                        u32::from_be_bytes(data[i + 10..i + 14].try_into().unwrap_or([0; 4]))
                            as usize;

                    if command_size > 10 && auth_size > command_size - 10 {
                        findings.push(
                            Finding::new(
                                "tpm_command",
                                Severity::Critical,
                                "TPM2 command with oversized authorization area",
                                &format!(
                                    "TPM2 command 0x{:08X} at offset 0x{:08X} has authSize={} \
                                     exceeding commandSize-header ({}). This causes the TPM \
                                     to read/write beyond the command buffer boundary.",
                                    command_code, i, auth_size, command_size - 10
                                ),
                            )
                            .with_confidence(0.90)
                            .with_details(serde_json::json!({
                                "offset": format!("0x{:08X}", i),
                                "command_code": format!("0x{:08X}", command_code),
                                "command_size": command_size,
                                "auth_size": auth_size,
                                "overflow_bytes": auth_size as isize - (command_size as isize - 10),
                                "cve": "CVE-2023-1017/CVE-2023-1018",
                            }))
                            .with_recommendation(
                                "Patch TPM firmware to validate auth area size against command buffer",
                            ),
                        );
                    }
                }
            }
        }

        findings
    }
}

impl Detector for TpmCommandDetector {
    fn name(&self) -> &str {
        "tpm_command"
    }

    fn detect(&self, target_path: &Path) -> Result<Vec<Finding>, DetectorError> {
        self.detect_context(&crate::ScanContext::load(target_path)?)
    }
    fn detect_context(&self, context: &crate::ScanContext) -> Result<Vec<Finding>, DetectorError> {
        let data = context.shared_bytes();
        let mut findings = Vec::new();

        findings.extend(self.check_command_size_overflow(&data));
        findings.extend(self.check_auth_area_overflow(&data));

        Ok(findings)
    }
}
