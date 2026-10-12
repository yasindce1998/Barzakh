use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};

const OPTEE_TA_MAGIC: [u8; 4] = [0x4F, 0x50, 0x54, 0x45]; // "OPTE"
const SMC_IMMEDIATE_0: [u8; 4] = [0x03, 0x00, 0x00, 0xD4]; // SMC #0 (little-endian AArch64)
const IMG4_MAGIC: [u8; 4] = *b"IMG4";
const IM4P_MAGIC: [u8; 4] = *b"IM4P";
const KBAG_MAGIC: [u8; 4] = *b"KBAG";
const SHSH_MAGIC: [u8; 4] = *b"SHSH";

pub struct ArmTrustzoneDetector;

impl Default for ArmTrustzoneDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl ArmTrustzoneDetector {
    pub fn new() -> Self {
        Self
    }

    fn check_optee_ta(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        for i in 0..data.len().saturating_sub(16) {
            if data[i..i + 4] == OPTEE_TA_MAGIC {
                if i + 12 > data.len() {
                    break;
                }
                let load_addr =
                    u64::from_le_bytes(data[i + 4..i + 12].try_into().unwrap_or([0; 8]));

                if load_addr > 0x1_0000_0000 {
                    findings.push(
                        Finding::new(
                            "arm_trustzone",
                            Severity::High,
                            "OP-TEE TA header with suspicious load address",
                            &format!(
                                "OP-TEE Trusted Application header at offset 0x{:08X} with \
                                 load address 0x{:016X} outside secure world range. \
                                 Indicates potential TA header tampering for persistence.",
                                i, load_addr
                            ),
                        )
                        .with_confidence(0.85)
                        .with_details(serde_json::json!({
                            "offset": format!("0x{:08X}", i),
                            "load_address": format!("0x{:016X}", load_addr),
                            "magic": "OPTE",
                        }))
                        .with_recommendation(
                            "Verify TA binary signature and compare load address against \
                             expected secure world memory map",
                        ),
                    );
                }
            }
        }

        findings
    }

    fn check_smc_calls(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut smc_count = 0;
        let mut suspicious_smc = Vec::new();

        // Qualcomm SCM commands known to be dangerous when called outside the
        // legitimate bootloader (see qseecom / scm.c command tables).
        const DANGEROUS_SCM_SERVICES: [u32; 3] = [
            0x04, // PIL (peripheral image loading) — SCM_SVC_PIL
            0x01, // fuse read/write — SCM_SVC_FUSE
            0x05, // security service calls
        ];

        for i in 0..data.len().saturating_sub(16) {
            if data[i..i + 4] == SMC_IMMEDIATE_0 {
                smc_count += 1;

                // Look back up to 4 instructions for the MOVZ that loads the
                // service ID into x0 — real SCM call sites interleave argument
                // setup (MOV x1, LDR x2, ...) between the service-ID load
                // and the SMC itself.
                if i >= 16 {
                    for back in 1..=4usize {
                        let instr_start = i - back * 4;
                        let prev_instr = u32::from_le_bytes(
                            data[instr_start..instr_start + 4]
                                .try_into()
                                .unwrap_or([0; 4]),
                        );
                        if (prev_instr & 0xFF80_0000) == 0xD280_0000 {
                            let imm16 = (prev_instr >> 5) & 0xFFFF;
                            let service_id = imm16 >> 8;
                            let dangerous =
                                DANGEROUS_SCM_SERVICES.contains(&service_id) || service_id > 0x10;
                            if dangerous {
                                suspicious_smc.push((i, service_id));
                            }
                            break;
                        }
                    }
                }
            }
        }

        if suspicious_smc.len() >= 2 {
            findings.push(
                Finding::new(
                    "arm_trustzone",
                    Severity::High,
                    "Multiple SMC calls with suspicious service IDs detected",
                    &format!(
                        "Found {} SMC #0 instructions with {} using service IDs that are \
                         known-dangerous (PIL/fuse/security services) or non-standard \
                         (> 0x10). Pattern consistent with Qualcomm SCM call injection or \
                         TrustZone exploit payload.",
                        smc_count,
                        suspicious_smc.len()
                    ),
                )
                .with_confidence(0.80)
                .with_details(serde_json::json!({
                    "total_smc_calls": smc_count,
                    "suspicious_calls": suspicious_smc.iter().map(|(off, svc)| {
                        serde_json::json!({
                            "offset": format!("0x{:08X}", off),
                            "service_id": format!("0x{:02X}", svc),
                        })
                    }).collect::<Vec<_>>(),
                }))
                .with_recommendation(
                    "Audit SMC call sites against known secure monitor service table",
                ),
            );
        }

        findings
    }

    fn check_apple_img4(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        for i in 0..data.len().saturating_sub(8) {
            if data[i..i + 4] == IMG4_MAGIC || data[i..i + 4] == IM4P_MAGIC {
                // Look for KBAG with null IV (encryption bypass)
                for j in i..data.len().saturating_sub(60) {
                    if data[j..j + 4] == KBAG_MAGIC {
                        let iv_start = j + 8;
                        if iv_start + 16 > data.len() {
                            break;
                        }
                        let iv_all_zero = data[iv_start..iv_start + 16].iter().all(|&b| b == 0);
                        if iv_all_zero {
                            findings.push(
                                Finding::new(
                                    "arm_trustzone",
                                    Severity::High,
                                    "Apple IMG4 KBAG with null IV — encryption bypass",
                                    &format!(
                                        "IMG4 container at offset 0x{:08X} has KBAG with \
                                         zeroed IV at 0x{:08X}. Indicates iBoot encryption \
                                         envelope was bypassed (jailbreak/exploit indicator).",
                                        i, j
                                    ),
                                )
                                .with_confidence(0.90)
                                .with_details(serde_json::json!({
                                    "img4_offset": format!("0x{:08X}", i),
                                    "kbag_offset": format!("0x{:08X}", j),
                                    "iv_zeroed": true,
                                }))
                                .with_recommendation(
                                    "Image has had its encryption bypassed — \
                                     verify boot chain integrity with Apple's APTicket",
                                ),
                            );
                        }
                        break;
                    }
                }

                // Look for SHSH with zero-length certificate
                for j in i..data.len().saturating_sub(8) {
                    if data[j..j + 4] == SHSH_MAGIC {
                        if j + 8 > data.len() {
                            break;
                        }
                        let cert_len =
                            u32::from_le_bytes(data[j + 4..j + 8].try_into().unwrap_or([0; 4]));
                        if cert_len == 0 {
                            findings.push(
                                Finding::new(
                                    "arm_trustzone",
                                    Severity::High,
                                    "Apple IMG4 SHSH blob with empty certificate",
                                    &format!(
                                        "SHSH signature blob at offset 0x{:08X} has zero-length \
                                         certificate. Indicates signature verification bypass.",
                                        j
                                    ),
                                )
                                .with_confidence(0.90)
                                .with_details(serde_json::json!({
                                    "shsh_offset": format!("0x{:08X}", j),
                                    "cert_length": 0,
                                }))
                                .with_recommendation(
                                    "Boot chain signature validation has been bypassed — \
                                     device may be running unsigned firmware",
                                ),
                            );
                        }
                        break;
                    }
                }

                break;
            }
        }

        findings
    }
}

impl Detector for ArmTrustzoneDetector {
    fn name(&self) -> &str {
        "arm_trustzone"
    }

    fn detect(&self, target_path: &Path) -> Result<Vec<Finding>, DetectorError> {
        let data = std::fs::read(target_path).map_err(DetectorError::Io)?;

        let mut findings = Vec::new();
        findings.extend(self.check_optee_ta(&data));
        findings.extend(self.check_smc_calls(&data));
        findings.extend(self.check_apple_img4(&data));

        Ok(findings)
    }
}
