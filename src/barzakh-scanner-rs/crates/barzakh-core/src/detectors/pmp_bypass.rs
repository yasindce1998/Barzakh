use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};

pub struct PmpBypassDetector;

impl Default for PmpBypassDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl PmpBypassDetector {
    pub fn new() -> Self {
        Self
    }

    fn check_pmp_config(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Scan for PMP configuration patterns
        // A suspicious pattern is 8+ consecutive bytes of 0x1F (NAPOT, RWX, unlocked)
        // or 8+ consecutive bytes of 0x00 (PMP completely disabled)
        for i in 0..data.len().saturating_sub(16) {
            let window = &data[i..i + 16];

            // Check for all-disabled PMP (all zeros in pmpcfg block)
            let all_zero = window.iter().all(|&b| b == 0x00);
            // Skip if we're in a large zero region (likely uninitialized)
            if all_zero && i > 0 && data[i - 1] == 0x00 {
                continue;
            }

            // Check for all-permissive PMP: A=NAPOT(0b11), RWX=0b111, L=0
            // pmpcfg byte = 0b000_11_111 = 0x1F
            let all_permissive = window.iter().all(|&b| b == 0x1F);

            if all_permissive {
                // Verify this isn't a false positive by checking surrounding context
                // Look for pmpaddr values nearby (within 64 bytes)
                let has_pmpaddr_pattern = self.has_fullrange_pmpaddr(data, i);

                if has_pmpaddr_pattern {
                    findings.push(
                        Finding::new(
                            "pmp_bypass",
                            Severity::High,
                            "RISC-V PMP configured with full-range RWX (effectively disabled)",
                            &format!(
                                "PMP configuration at offset 0x{:08X} has all entries set to \
                                 NAPOT/RWX/Unlocked (0x1F) with full-range address matching. \
                                 Physical Memory Protection is effectively bypassed.",
                                i
                            ),
                        )
                        .with_confidence(0.85)
                        .with_details(serde_json::json!({
                            "offset": format!("0x{:08X}", i),
                            "pmpcfg_value": "0x1F (A=NAPOT, R=1, W=1, X=1, L=0)",
                            "entries_affected": 16,
                            "full_range_addr": true,
                        }))
                        .with_recommendation(
                            "PMP entries should restrict M-mode memory access. All-permissive \
                             configuration allows arbitrary code execution in machine mode.",
                        ),
                    );
                }
            }
        }

        findings
    }

    fn has_fullrange_pmpaddr(&self, data: &[u8], pmpcfg_offset: usize) -> bool {
        // Look for pmpaddr values within 64 bytes after pmpcfg
        // Full-range NAPOT: pmpaddr = 0x1FFFFFFFFFFFFFFF
        let search_start = pmpcfg_offset + 16;
        let search_end = (pmpcfg_offset + 192).min(data.len().saturating_sub(8));

        for i in (search_start..search_end).step_by(8) {
            if i + 8 > data.len() {
                break;
            }
            let addr = u64::from_le_bytes(data[i..i + 8].try_into().unwrap_or([0; 8]));
            if addr == 0x1FFF_FFFF_FFFF_FFFF {
                return true;
            }
        }
        false
    }

    fn check_pmp_csr_writes(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Look for CSR write instructions targeting PMP registers
        // pmpcfg0=0x3A0, pmpcfg2=0x3A2, pmpaddr0=0x3B0..0x3BF
        let mut pmp_write_sites = Vec::new();

        // RISC-V instructions are naturally 4-byte aligned; scanning only
        // aligned positions removes most random byte-sequence matches.
        for i in (0..data.len().saturating_sub(4)).step_by(4) {
            let instr = u32::from_le_bytes(data[i..i + 4].try_into().unwrap_or([0; 4]));

            // csrw pattern: funct3=001, opcode=1110011, rd=x0
            if (instr & 0x0000_707F) != 0x0000_1073 {
                continue;
            }

            let csr = (instr >> 20) & 0xFFF;
            // PMP CSR range: 0x3A0-0x3A3 (pmpcfg) or 0x3B0-0x3BF (pmpaddr)
            if (0x3A0..=0x3A3).contains(&csr) || (0x3B0..=0x3BF).contains(&csr) {
                pmp_write_sites.push((i, csr));
            }
        }

        // The sites must form a tight code sequence (a PMP programming
        // routine), not scattered matches across the image.
        let has_tight_sequence = pmp_write_sites
            .windows(3)
            .any(|w| w[2].0.saturating_sub(w[0].0) <= 32);

        if pmp_write_sites.len() >= 3 && has_tight_sequence {
            findings.push(
                Finding::new(
                    "pmp_bypass",
                    Severity::High,
                    "RISC-V PMP CSR write sequence detected",
                    &format!(
                        "Found {} CSR write instructions targeting PMP configuration registers. \
                         Code is programmatically reconfiguring Physical Memory Protection.",
                        pmp_write_sites.len()
                    ),
                )
                .with_confidence(0.75)
                .with_details(serde_json::json!({
                    "pmp_writes": pmp_write_sites.iter().take(8).map(|(off, csr)| {
                        serde_json::json!({
                            "offset": format!("0x{:08X}", off),
                            "csr": format!("0x{:03X}", csr),
                            "csr_name": match *csr {
                                0x3A0 => "pmpcfg0",
                                0x3A1 => "pmpcfg1",
                                0x3A2 => "pmpcfg2",
                                0x3A3 => "pmpcfg3",
                                c if (0x3B0..=0x3BF).contains(&c) => "pmpaddr",
                                _ => "unknown",
                            },
                        })
                    }).collect::<Vec<_>>(),
                }))
                .with_recommendation(
                    "PMP reconfiguration at runtime may indicate an exploit weakening \
                     memory protection. Verify this is part of legitimate firmware init.",
                ),
            );
        }

        findings
    }

    fn check_mmode_rwx_region(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Look for NOP sleds followed by MRET (M-mode return)
        // This pattern indicates an exploitable M-mode code region
        let riscv_nop: [u8; 4] = [0x13, 0x00, 0x00, 0x00]; // ADDI x0, x0, 0
        let mret: [u8; 4] = [0x73, 0x00, 0x20, 0x30]; // MRET

        for i in 0..data.len().saturating_sub(64) {
            // Check for NOP sled (8+ consecutive NOPs)
            let mut nop_count = 0;
            let mut j = i;
            while j + 4 <= data.len() && data[j..j + 4] == riscv_nop {
                nop_count += 1;
                j += 4;
                if nop_count >= 32 {
                    break;
                }
            }

            if nop_count >= 8 {
                // Look for MRET after the NOP sled (within 256 bytes)
                let search_end = (j + 256).min(data.len().saturating_sub(4));
                for k in (j..search_end).step_by(4) {
                    if data[k..k + 4] == mret {
                        findings.push(
                            Finding::new(
                                "pmp_bypass",
                                Severity::Medium,
                                "RISC-V NOP sled with MRET indicates writable M-mode region",
                                &format!(
                                    "NOP sled ({} instructions) at offset 0x{:08X} followed by \
                                     MRET at 0x{:08X}. Pattern indicates M-mode memory region \
                                     that can be written to (RWX) — a PMP misconfiguration.",
                                    nop_count, i, k
                                ),
                            )
                            .with_confidence(0.70)
                            .with_details(serde_json::json!({
                                "nop_sled_offset": format!("0x{:08X}", i),
                                "nop_count": nop_count,
                                "mret_offset": format!("0x{:08X}", k),
                            }))
                            .with_recommendation(
                                "M-mode code regions should be Read-Execute only. \
                                 Writable M-mode memory allows privilege escalation.",
                            ),
                        );
                        break;
                    }
                }
            }
        }

        findings
    }
}

impl Detector for PmpBypassDetector {
    fn name(&self) -> &str {
        "pmp_bypass"
    }

    fn detect(&self, target_path: &Path) -> Result<Vec<Finding>, DetectorError> {
        let data = std::fs::read(target_path).map_err(DetectorError::Io)?;

        let mut findings = Vec::new();
        findings.extend(self.check_pmp_config(&data));
        findings.extend(self.check_pmp_csr_writes(&data));
        findings.extend(self.check_mmode_rwx_region(&data));

        Ok(findings)
    }
}
