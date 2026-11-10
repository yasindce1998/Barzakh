use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};

const OPENSBI_MAGIC: &[u8] = b"OPENSBI\0";

pub struct OpensbiDetector;

impl Default for OpensbiDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl OpensbiDetector {
    pub fn new() -> Self {
        Self
    }

    fn check_sbi_extension_table(&self, data: &[u8], header_offset: usize) -> Vec<Finding> {
        let mut findings = Vec::new();

        // SBI extension table starts at header_offset + 0x100 (after version info)
        let ext_table_offset = header_offset + 0x100;
        if ext_table_offset + 36 > data.len() {
            return findings;
        }

        // Each extension entry: extension_id (u32) + handler_addr (u64) = 12 bytes
        let mut redirected_handlers = Vec::new();

        for entry_idx in 0..8 {
            let entry_offset = ext_table_offset + entry_idx * 12;
            if entry_offset + 12 > data.len() {
                break;
            }

            let ext_id = u32::from_le_bytes(
                data[entry_offset..entry_offset + 4]
                    .try_into()
                    .unwrap_or([0; 4]),
            );
            let handler_addr = u64::from_le_bytes(
                data[entry_offset + 4..entry_offset + 12]
                    .try_into()
                    .unwrap_or([0; 8]),
            );

            if ext_id == 0 && handler_addr == 0 {
                break;
            }

            // Handler addresses should be in the firmware .text range
            // Typical OpenSBI .text: 0x80000000..0x80200000
            // Anything outside that is suspicious
            let in_text_range = (0x8000_0000_0000_0000..=0x8000_0000_00FF_FFFF)
                .contains(&handler_addr)
                || (0x8000_0000..=0x80FF_FFFF).contains(&(handler_addr as u32));

            if handler_addr != 0 && !in_text_range {
                redirected_handlers.push((ext_id, handler_addr, entry_offset));
            }
        }

        if !redirected_handlers.is_empty() {
            findings.push(
                Finding::new(
                    "opensbi",
                    Severity::High,
                    "OpenSBI extension table with redirected handlers",
                    &format!(
                        "OpenSBI firmware at offset 0x{:08X} has {} SBI extension handler(s) \
                         pointing outside expected .text range. Indicates ecall table hooking \
                         for M-mode persistence.",
                        header_offset,
                        redirected_handlers.len()
                    ),
                )
                .with_confidence(0.85)
                .with_details(serde_json::json!({
                    "header_offset": format!("0x{:08X}", header_offset),
                    "redirected_handlers": redirected_handlers.iter().map(|(ext, addr, off)| {
                        serde_json::json!({
                            "extension_id": format!("0x{:08X}", ext),
                            "handler_address": format!("0x{:016X}", addr),
                            "entry_offset": format!("0x{:08X}", off),
                        })
                    }).collect::<Vec<_>>(),
                }))
                .with_recommendation(
                    "Compare SBI extension table against clean OpenSBI build. \
                     Redirected ecall handlers indicate firmware-level rootkit.",
                ),
            );
        }

        findings
    }

    fn check_mtvec_redirect(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Look for csrrw/csrw mtvec patterns pointing to suspicious addresses
        // csrrw zero, mtvec, rs = 0x305_X1073 where X encodes rs
        // csrw mtvec, rs = csrrw x0, mtvec, rs
        for i in 0..data.len().saturating_sub(8) {
            let instr = u32::from_le_bytes(data[i..i + 4].try_into().unwrap_or([0; 4]));

            // Check for csrw mtvec pattern: opcode[6:0]=1110011, funct3=001, csr=0x305
            let is_csrw_mtvec = (instr & 0xFFF0_707F) == 0x3050_1073;

            if is_csrw_mtvec {
                // Check if preceded by LUI loading a suspicious address
                if i >= 4 {
                    let prev = u32::from_le_bytes(data[i - 4..i].try_into().unwrap_or([0; 4]));
                    // LUI: imm[31:12] | rd | 0110111
                    if (prev & 0x7F) == 0x37 {
                        let imm_upper = prev >> 12;
                        // Suspicious: address outside normal firmware range
                        if imm_upper > 0x80200 || (imm_upper & 0xDEAD0) == 0xDEAD0 {
                            findings.push(
                                Finding::new(
                                    "opensbi",
                                    Severity::High,
                                    "RISC-V mtvec CSR redirected to suspicious address",
                                    &format!(
                                        "Machine trap vector (mtvec) write at offset 0x{:08X} \
                                         loads address with upper bits 0x{:05X}000. \
                                         Trap vector redirection to attacker-controlled memory.",
                                        i, imm_upper
                                    ),
                                )
                                .with_confidence(0.80)
                                .with_details(serde_json::json!({
                                    "offset": format!("0x{:08X}", i),
                                    "lui_immediate": format!("0x{:05X}", imm_upper),
                                    "pattern": "csrw_mtvec_with_suspicious_lui",
                                }))
                                .with_recommendation(
                                    "mtvec should point within OpenSBI .text section. \
                                     Redirection indicates M-mode trap handler hijack.",
                                ),
                            );
                        }
                    }
                }
            }
        }

        findings
    }

    fn check_privilege_escalation(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Look for S-mode code attempting to write M-mode CSRs
        // csrw mstatus (0x300), medeleg (0x302), mideleg (0x303) from non-M-mode context
        let mmode_csrs: &[(u32, &str)] =
            &[(0x300, "mstatus"), (0x302, "medeleg"), (0x303, "mideleg")];

        let mut escalation_sites = Vec::new();

        // RISC-V instructions are naturally 4-byte aligned; scanning only
        // aligned positions removes most random byte-sequence matches.
        for i in (0..data.len().saturating_sub(4)).step_by(4) {
            let instr = u32::from_le_bytes(data[i..i + 4].try_into().unwrap_or([0; 4]));

            for &(csr_addr, csr_name) in mmode_csrs {
                // csrw csr, rs: instr[31:20]=csr, instr[14:12]=001, instr[6:0]=1110011
                let expected = (csr_addr << 20) | 0x0005_1073;
                let mask = 0xFFF0_707F;
                if (instr & mask) == (expected & mask) {
                    escalation_sites.push((i, csr_name));
                }
            }
        }

        // The sites must form a tight code sequence (an exploit stub
        // programming several M-mode CSRs back to back), not scattered
        // matches across the image.
        let has_tight_sequence = escalation_sites.windows(2).any(|w| w[1].0 - w[0].0 <= 64);

        if escalation_sites.len() >= 2 && has_tight_sequence {
            findings.push(
                Finding::new(
                    "opensbi",
                    Severity::High,
                    "RISC-V M-mode CSR writes indicate privilege escalation attempt",
                    &format!(
                        "Found {} instructions writing to M-mode CSRs (mstatus/medeleg/mideleg). \
                         Pattern indicates S-to-M privilege escalation exploit via SBI.",
                        escalation_sites.len()
                    ),
                )
                .with_confidence(0.75)
                .with_details(serde_json::json!({
                    "escalation_sites": escalation_sites.iter().take(5).map(|(off, csr)| {
                        serde_json::json!({
                            "offset": format!("0x{:08X}", off),
                            "csr": csr,
                        })
                    }).collect::<Vec<_>>(),
                }))
                .with_recommendation(
                    "M-mode CSR writes from application code indicate exploitation. \
                     Verify OpenSBI ecall handler integrity.",
                ),
            );
        }

        findings
    }
}

impl Detector for OpensbiDetector {
    fn name(&self) -> &str {
        "opensbi"
    }

    fn detect(&self, target_path: &Path) -> Result<Vec<Finding>, DetectorError> {
        let data = std::fs::read(target_path).map_err(DetectorError::Io)?;

        let mut findings = Vec::new();

        // Look for OpenSBI magic
        for i in 0..data.len().saturating_sub(8) {
            if data[i..i + 8] == *OPENSBI_MAGIC {
                findings.extend(self.check_sbi_extension_table(&data, i));
                break;
            }
        }

        findings.extend(self.check_mtvec_redirect(&data));
        findings.extend(self.check_privilege_escalation(&data));

        Ok(findings)
    }
}
