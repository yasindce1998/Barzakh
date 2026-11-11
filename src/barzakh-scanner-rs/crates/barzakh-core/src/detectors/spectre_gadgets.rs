use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};

// Indirect CALL [mem] and JMP [mem] encodings
const CALL_INDIRECT: [u8; 2] = [0xFF, 0x15];
const JMP_INDIRECT: [u8; 2] = [0xFF, 0x25];
// LFENCE encoding
const LFENCE: [u8; 3] = [0x0F, 0xAE, 0xE8];
// CLFLUSH prefix
const CLFLUSH_PREFIX: [u8; 1] = [0x0F];
const CLFLUSH_OPCODE: u8 = 0xAE;
// RDTSC encoding
const RDTSC: [u8; 2] = [0x0F, 0x31];
// NOP sled byte
const NOP: u8 = 0x90;
// Conditional branch opcodes after which LFENCE should appear
const JA: u8 = 0x77;
const JB: u8 = 0x72;
const JNE: u8 = 0x75;

/// Number of unprotected indirect branches in a 4KB window before flagging
const UNPROTECTED_BRANCH_THRESHOLD: usize = 5;
/// Bytes to look back for LFENCE before an indirect branch
const LFENCE_LOOKBACK: usize = 8;
/// Bytes to search forward from CLFLUSH for RDTSC
const CLFLUSH_RDTSC_WINDOW: usize = 64;
/// Minimum NOP sled length to consider suspicious
const MIN_NOP_SLED: usize = 3;
/// Size of the sliding window for counting unprotected branches
const WINDOW_4KB: usize = 4096;

pub struct SpectreGadgetsDetector;

impl Default for SpectreGadgetsDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl SpectreGadgetsDetector {
    pub fn new() -> Self {
        Self
    }

    /// Returns true if LFENCE appears in data[start..end].
    fn has_lfence_in_range(data: &[u8], start: usize, end: usize) -> bool {
        let end = end.min(data.len());
        if start >= end || end < LFENCE.len() {
            return false;
        }
        data[start..end].windows(LFENCE.len()).any(|w| w == LFENCE)
    }

    /// Check for indirect CALL/JMP without a preceding LFENCE in a 4KB window.
    fn check_indirect_branch_gadgets(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Collect all unprotected indirect branch offsets
        let mut unprotected: Vec<usize> = Vec::new();

        for i in 0..data.len().saturating_sub(2) {
            let is_call_indirect = data[i..i + 2] == CALL_INDIRECT;
            let is_jmp_indirect = data[i..i + 2] == JMP_INDIRECT;

            if !is_call_indirect && !is_jmp_indirect {
                continue;
            }

            let lookback_start = i.saturating_sub(LFENCE_LOOKBACK);
            if !Self::has_lfence_in_range(data, lookback_start, i) {
                unprotected.push(i);
            }
        }

        // Slide a 4KB window and flag when density exceeds threshold
        let mut reported_windows: Vec<usize> = Vec::new();
        for &branch_offset in &unprotected {
            let window_start = branch_offset.saturating_sub(WINDOW_4KB);
            let count_in_window = unprotected
                .iter()
                .filter(|&&o| o >= window_start && o <= branch_offset)
                .count();

            if count_in_window > UNPROTECTED_BRANCH_THRESHOLD {
                // Avoid duplicate reports for the same window
                if reported_windows
                    .iter()
                    .any(|&prev| branch_offset.saturating_sub(prev) < WINDOW_4KB)
                {
                    continue;
                }
                reported_windows.push(branch_offset);

                findings.push(
                    Finding::new(
                        "spectre_gadgets",
                        Severity::Medium,
                        "Dense unprotected indirect branches (Spectre v2 gadget cluster)",
                        &format!(
                            "Found {} unprotected indirect branch instructions (CALL/JMP \
                             [mem] without preceding LFENCE) within a 4 KB window ending at \
                             offset 0x{:08X}. Dense gadget clusters are exploitable for \
                             Spectre variant 2 (branch target injection) attacks.",
                            count_in_window, branch_offset
                        ),
                    )
                    .with_confidence(0.72)
                    .with_details(serde_json::json!({
                        "window_end_offset": format!("0x{:08X}", branch_offset),
                        "unprotected_branch_count": count_in_window,
                        "threshold": UNPROTECTED_BRANCH_THRESHOLD,
                    }))
                    .with_recommendation(
                        "Insert LFENCE instructions before all indirect CALL/JMP in \
                         security-critical firmware paths. Retpoline mitigations should \
                         be enabled at compile time for firmware toolchains.",
                    ),
                );
            }
        }

        findings
    }

    /// Detect CLFLUSH + RDTSC patterns indicative of cache flush-reload side channels.
    fn check_cache_flush_reload(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        for i in 0..data.len().saturating_sub(2) {
            // Detect CLFLUSH: 0F AE /7 — modrm byte has bits 5:3 = 111
            if data[i] != CLFLUSH_PREFIX[0] || data[i + 1] != CLFLUSH_OPCODE {
                continue;
            }
            if i + 2 >= data.len() {
                continue;
            }
            let modrm = data[i + 2];
            // bits 5:3 of modrm = (modrm >> 3) & 0x7 == 7
            if (modrm >> 3) & 0x7 != 7 {
                continue;
            }

            // Search for RDTSC within CLFLUSH_RDTSC_WINDOW bytes forward
            let search_end = (i + 3 + CLFLUSH_RDTSC_WINDOW).min(data.len());
            let region = &data[i + 3..search_end];
            if let Some(rdtsc_rel) = region.windows(2).position(|w| w == RDTSC) {
                let rdtsc_offset = i + 3 + rdtsc_rel;
                findings.push(
                    Finding::new(
                        "spectre_gadgets",
                        Severity::High,
                        "CLFLUSH + RDTSC cache flush-reload side-channel pattern",
                        &format!(
                            "CLFLUSH instruction at offset 0x{:08X} is followed by RDTSC \
                             at 0x{:08X} (within {} bytes). This is the classic cache \
                             flush+reload timing probe sequence used in Spectre and Meltdown \
                             side-channel exploits.",
                            i, rdtsc_offset, CLFLUSH_RDTSC_WINDOW
                        ),
                    )
                    .with_confidence(0.88)
                    .with_details(serde_json::json!({
                        "clflush_offset": format!("0x{:08X}", i),
                        "rdtsc_offset": format!("0x{:08X}", rdtsc_offset),
                        "distance_bytes": rdtsc_offset - (i + 3),
                        "modrm": format!("0x{:02X}", modrm),
                    }))
                    .with_recommendation(
                        "Audit firmware for cache timing measurement sequences. \
                         Firmware executing in SMM or other privileged contexts must \
                         not contain attacker-reachable flush+reload gadgets.",
                    ),
                );
            }
        }

        findings
    }

    /// Detect NOP sleds replacing LFENCE after conditional branches.
    fn check_speculation_barrier_removal(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        let branch_opcodes = [JA, JB, JNE];

        for i in 0..data.len().saturating_sub(2) {
            if !branch_opcodes.contains(&data[i]) {
                continue;
            }
            // Conditional branch: opcode + 1-byte rel offset
            let after_branch = i + 2;
            if after_branch + MIN_NOP_SLED > data.len() {
                continue;
            }

            // Count NOP sled length
            let mut nop_len = 0usize;
            while after_branch + nop_len < data.len() && data[after_branch + nop_len] == NOP {
                nop_len += 1;
            }

            if nop_len < MIN_NOP_SLED {
                continue;
            }

            // A NOP sled that is exactly 3 bytes (matching LFENCE byte length) is
            // the strongest indicator of deliberate LFENCE removal.
            let matches_lfence_len = nop_len == LFENCE.len();

            findings.push(
                Finding::new(
                    "spectre_gadgets",
                    Severity::Medium,
                    "NOP sled replacing speculation barrier after conditional branch",
                    &format!(
                        "Conditional branch (opcode 0x{:02X}) at offset 0x{:08X} is \
                         followed by a NOP sled of {} byte(s) at 0x{:08X}. {}A NOP sled \
                         at this position replaces a required LFENCE speculation barrier, \
                         leaving the code path vulnerable to Spectre variant 1 \
                         (bounds-check bypass).",
                        data[i],
                        i,
                        nop_len,
                        after_branch,
                        if matches_lfence_len {
                            "Sled length exactly matches 3-byte LFENCE encoding. "
                        } else {
                            ""
                        }
                    ),
                )
                .with_confidence(if matches_lfence_len { 0.82 } else { 0.65 })
                .with_details(serde_json::json!({
                    "branch_offset": format!("0x{:08X}", i),
                    "branch_opcode": format!("0x{:02X}", data[i]),
                    "nop_sled_offset": format!("0x{:08X}", after_branch),
                    "nop_sled_length": nop_len,
                    "matches_lfence_length": matches_lfence_len,
                }))
                .with_recommendation(
                    "Replace NOP sleds after conditional branches with LFENCE (0F AE E8) \
                     to prevent speculative execution past bounds checks in SMM/DXE code.",
                ),
            );
        }

        findings
    }
}

impl Detector for SpectreGadgetsDetector {
    fn name(&self) -> &str {
        "spectre_gadgets"
    }

    fn detect(&self, target_path: &Path) -> Result<Vec<Finding>, DetectorError> {
        self.detect_context(&crate::ScanContext::load(target_path)?)
    }
    fn detect_context(&self, context: &crate::ScanContext) -> Result<Vec<Finding>, DetectorError> {
        let data = context.shared_bytes();
        let mut findings = Vec::new();

        findings.extend(self.check_indirect_branch_gadgets(&data));
        findings.extend(self.check_cache_flush_reload(&data));
        findings.extend(self.check_speculation_barrier_removal(&data));

        Ok(findings)
    }
}
