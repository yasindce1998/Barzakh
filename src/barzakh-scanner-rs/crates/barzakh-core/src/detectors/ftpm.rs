use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};

pub struct FtpmDetector;

impl Default for FtpmDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl FtpmDetector {
    pub fn new() -> Self {
        Self
    }

    fn check_tpm_command_structure(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Scan for TPM2 command headers
        // Tag: 0x8001 (TPM_ST_NO_SESSIONS) or 0x8002 (TPM_ST_SESSIONS) in big-endian
        let tags: &[[u8; 2]] = &[
            [0x80, 0x01], // TPM_ST_NO_SESSIONS
            [0x80, 0x02], // TPM_ST_SESSIONS
        ];

        for (i, window) in data.windows(10).enumerate() {
            let tag_match = tags.iter().any(|tag| window[..2] == *tag);
            if !tag_match {
                continue;
            }

            // Parse commandSize (big-endian u32 at offset 2)
            let command_size =
                u32::from_be_bytes(window[2..6].try_into().unwrap_or([0; 4])) as usize;

            // Validate commandSize
            let remaining = data.len() - i;

            if command_size < 10 {
                findings.push(
                    Finding::new(
                        "ftpm",
                        Severity::High,
                        "Malformed TPM2 command structure",
                        &format!(
                            "TPM2 command header at offset 0x{:08X} with tag 0x{:02X}{:02X} \
                             has commandSize={} which is below minimum (10 bytes). \
                             This indicates a corrupted or crafted TPM command.",
                            i, window[0], window[1], command_size
                        ),
                    )
                    .with_confidence(0.70)
                    .with_details(serde_json::json!({
                        "offset": format!("0x{:08X}", i),
                        "tag": format!("0x{:02X}{:02X}", window[0], window[1]),
                        "command_size": command_size,
                        "issue": "commandSize below minimum",
                    })),
                );
            } else if command_size > remaining {
                findings.push(
                    Finding::new(
                        "ftpm",
                        Severity::High,
                        "Malformed TPM2 command structure",
                        &format!(
                            "TPM2 command header at offset 0x{:08X} with tag 0x{:02X}{:02X} \
                             has commandSize={} which exceeds remaining buffer ({}). \
                             This indicates a buffer overflow attempt or corruption.",
                            i, window[0], window[1], command_size, remaining
                        ),
                    )
                    .with_confidence(0.65)
                    .with_details(serde_json::json!({
                        "offset": format!("0x{:08X}", i),
                        "tag": format!("0x{:02X}{:02X}", window[0], window[1]),
                        "command_size": command_size,
                        "remaining_buffer": remaining,
                        "issue": "commandSize exceeds buffer",
                    })),
                );
            }
        }

        // Deduplicate: only report first few findings
        findings.truncate(5);
        findings
    }

    fn check_tpm_response_forgery(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Look for TPM2 response headers with suspicious characteristics
        // Response tags are same as command tags: 0x8001 or 0x8002
        let tags: &[[u8; 2]] = &[[0x80, 0x01], [0x80, 0x02]];

        for (i, window) in data.windows(10).enumerate() {
            let tag_match = tags.iter().any(|tag| window[..2] == *tag);
            if !tag_match {
                continue;
            }

            // Parse responseSize (big-endian u32 at offset 2)
            let response_size = u32::from_be_bytes(window[2..6].try_into().unwrap_or([0; 4]));

            // Parse responseCode (big-endian u32 at offset 6)
            let response_code = u32::from_be_bytes(window[6..10].try_into().unwrap_or([0; 4]));

            // Check for TPM2_RC_SUCCESS (0x000) with suspiciously small responseSize
            if response_code == 0x000 && response_size < 10 && response_size > 0 {
                findings.push(
                    Finding::new(
                        "ftpm",
                        Severity::Critical,
                        "Forged TPM2 response detected",
                        &format!(
                            "TPM2 response at offset 0x{:08X} reports SUCCESS (RC=0x000) \
                             but responseSize={} is below the minimum valid size. \
                             This strongly indicates a forged TPM response from a \
                             compromised PSP/fTPM implementation.",
                            i, response_size
                        ),
                    )
                    .with_confidence(0.75)
                    .with_details(serde_json::json!({
                        "offset": format!("0x{:08X}", i),
                        "response_size": response_size,
                        "response_code": "TPM2_RC_SUCCESS (0x000)",
                        "issue": "SUCCESS with undersized response",
                    }))
                    .with_recommendation(
                        "fTPM responses may be forged at PSP level. Verify TPM PCR \
                         values against known-good measurements.",
                    ),
                );
                return findings;
            }

            // Also flag SUCCESS responses with responseSize exactly 10 (header only, no payload)
            // for commands that should have payload (heuristic)
            if response_code == 0x000 && response_size == 10 {
                // This is suspicious for read-type commands
                // Check if nearby bytes suggest this should have had a payload
                if i + 10 < data.len() {
                    let after_response = &data[i + 10..(i + 14).min(data.len())];
                    let all_zeros = after_response.iter().all(|&b| b == 0x00);
                    let all_ff = after_response.iter().all(|&b| b == 0xFF);

                    if all_zeros || all_ff {
                        findings.push(
                            Finding::new(
                                "ftpm",
                                Severity::Critical,
                                "Forged TPM2 response detected",
                                &format!(
                                    "TPM2 response at offset 0x{:08X} reports SUCCESS with \
                                     header-only size (10 bytes) followed by null/FF padding. \
                                     Expected response payload is missing, indicating forgery.",
                                    i
                                ),
                            )
                            .with_confidence(0.65)
                            .with_details(serde_json::json!({
                                "offset": format!("0x{:08X}", i),
                                "response_size": response_size,
                                "response_code": "TPM2_RC_SUCCESS (0x000)",
                                "trailing_bytes": format!("{:02X?}", after_response),
                            })),
                        );
                        return findings;
                    }
                }
            }
        }

        findings
    }

    fn check_psp_mailbox_patterns(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Scan for PSP C2P/P2C mailbox patterns
        // PSP MMIO base: 0xFED80000
        // C2P mailbox offset: 0x10570
        // P2C mailbox offset: 0x10670
        let psp_base: &[u8] = &[0x00, 0x00, 0xD8, 0xFE]; // 0xFED80000 little-endian
        let c2p_offset: &[u8] = &[0x70, 0x05, 0x01, 0x00]; // 0x10570 little-endian
        let p2c_offset: &[u8] = &[0x70, 0x06, 0x01, 0x00]; // 0x10670 little-endian

        for (i, window) in data.windows(psp_base.len()).enumerate() {
            if window == psp_base {
                // Look for C2P or P2C offset references within 64 bytes
                let search_end = (i + 64).min(data.len());
                let search_region = &data[i..search_end];

                let has_c2p = search_region
                    .windows(c2p_offset.len())
                    .any(|w| w == c2p_offset);
                let has_p2c = search_region
                    .windows(p2c_offset.len())
                    .any(|w| w == p2c_offset);

                if has_c2p || has_p2c {
                    findings.push(
                        Finding::new(
                            "ftpm",
                            Severity::High,
                            "PSP mailbox manipulation artifacts",
                            &format!(
                                "PSP MMIO base (0xFED80000) at offset 0x{:08X} with \
                                 references to {} mailbox offset. This indicates direct \
                                 PSP mailbox manipulation outside normal firmware flow.",
                                i,
                                if has_c2p && has_p2c {
                                    "C2P and P2C"
                                } else if has_c2p {
                                    "C2P (0x10570)"
                                } else {
                                    "P2C (0x10670)"
                                }
                            ),
                        )
                        .with_confidence(0.70)
                        .with_details(serde_json::json!({
                            "offset": format!("0x{:08X}", i),
                            "psp_base": "0xFED80000",
                            "c2p_reference": has_c2p,
                            "p2c_reference": has_p2c,
                        }))
                        .with_recommendation(
                            "PSP mailbox access from unexpected code may indicate \
                             fTPM command interception or PSP compromise.",
                        ),
                    );
                    return findings;
                }
            }
        }

        findings
    }
}

impl Detector for FtpmDetector {
    fn name(&self) -> &str {
        "ftpm"
    }

    fn detect(&self, target_path: &Path) -> Result<Vec<Finding>, DetectorError> {
        let data = std::fs::read(target_path).map_err(DetectorError::Io)?;
        let mut findings = Vec::new();

        findings.extend(self.check_tpm_command_structure(&data));
        findings.extend(self.check_tpm_response_forgery(&data));
        findings.extend(self.check_psp_mailbox_patterns(&data));

        Ok(findings)
    }
}
