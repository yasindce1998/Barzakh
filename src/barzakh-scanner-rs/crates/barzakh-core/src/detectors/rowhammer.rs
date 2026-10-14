use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};

// CLFLUSH opcode prefix: 0F AE /7  (ModRM byte has reg field = 7, i.e., bits 5:3 = 111 = 0x38)
const CLFLUSH_PREFIX_0: u8 = 0x0F;
const CLFLUSH_PREFIX_1: u8 = 0xAE;
// ModRM bits 5:3 must equal 111 (0x38 mask)
const CLFLUSH_MODRM_MASK: u8 = 0x38;
const CLFLUSH_MODRM_BITS: u8 = 0x38;

// Backward short jump opcode (EB xx, xx has high bit set = negative offset)
const JMP_SHORT: u8 = 0xEB;

// Backward conditional jump prefix (0F 8x)
const JCC_PREFIX: u8 = 0x0F;
const JCC_LO_MIN: u8 = 0x80;
const JCC_LO_MAX: u8 = 0x8F;

// tREFI / REFRESH ASCII markers
const TREFI_MARKER: &[u8] = b"tREFI";
const REFRESH_MARKER: &[u8] = b"REFRESH";

// DDR timing register PCI config space offset for tREFI (typical: 0x3E)
const DDR_TREFI_CONFIG_OFFSET: u8 = 0x3E;

// Row-hammer row size multiples used in many-sided rowhammer (0x2000 = 8192 bytes)
// We look for MOV instructions (various forms) with displacements spaced by this delta.
const ROW_SIZE_STEP: u32 = 0x2000;

// MOV opcodes that carry a 32-bit displacement (common forms in rowhammer PoCs):
// MOV r32, [r+disp32]:  0x8B /r  (ModRM with mod=10)
// MOV [r+disp32], r32:  0x89 /r
const MOV_LOAD: u8 = 0x8B;
const MOV_STORE: u8 = 0x89;

// SHR / SHL opcodes used in DRAM geometry bit-field extraction
// SHR r/m32, imm8: C1 E8 imm
// SHL r/m32, imm8: C1 E0 imm
const SHIFT_PREFIX: u8 = 0xC1;
const SHR_MODRM: u8 = 0xE8;
const SHL_MODRM: u8 = 0xE0;
// AND r/m32, r32: 21 /r  or  AND r32, r/m32: 23 /r
const AND_OP_0: u8 = 0x21;
const AND_OP_1: u8 = 0x23;

pub struct RowhammerDetector;

impl Default for RowhammerDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl RowhammerDetector {
    pub fn new() -> Self {
        Self
    }

    /// Detect tight CLFLUSH loops: CLFLUSH followed within 16 bytes by another CLFLUSH
    /// or a backward jump. More than 2 CLFLUSH instructions with backward jumps strongly
    /// suggests a rowhammer hammering loop.
    fn check_cache_flush_hammer(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Collect all CLFLUSH instruction offsets
        let clflush_offsets: Vec<usize> = (0..data.len().saturating_sub(2))
            .filter(|&i| {
                data[i] == CLFLUSH_PREFIX_0
                    && data[i + 1] == CLFLUSH_PREFIX_1
                    && (data[i + 2] & CLFLUSH_MODRM_MASK) == CLFLUSH_MODRM_BITS
            })
            .collect();

        if clflush_offsets.len() < 2 {
            return findings;
        }

        for &flush_off in &clflush_offsets {
            let window_end = (flush_off + 16).min(data.len());
            let window = &data[flush_off + 3..window_end];

            // Check for another CLFLUSH within 16 bytes
            let has_second_clflush = window.windows(3).any(|w| {
                w[0] == CLFLUSH_PREFIX_0
                    && w[1] == CLFLUSH_PREFIX_1
                    && (w[2] & CLFLUSH_MODRM_MASK) == CLFLUSH_MODRM_BITS
            });

            // Check for backward short jump (EB xx, xx >= 0x80)
            let has_backward_jmp = window
                .windows(2)
                .any(|w| w[0] == JMP_SHORT && (w[1] & 0x80) != 0);

            // Check for backward 2-byte conditional jump (0F 8x xx xx xx xx, where offset < 0)
            // For simplicity check sign of the 4-byte displacement's high byte.
            let has_backward_jcc = window.windows(6).any(|w| {
                w[0] == JCC_PREFIX && w[1] >= JCC_LO_MIN && w[1] <= JCC_LO_MAX && (w[5] & 0x80) != 0
                // high byte of i32 displacement indicates negative
            });

            if has_second_clflush && (has_backward_jmp || has_backward_jcc) {
                // Count total CLFLUSH within 128-byte window around this offset
                let search_start = flush_off.saturating_sub(64);
                let search_end = (flush_off + 64).min(data.len().saturating_sub(2));
                let clflush_count = (search_start..search_end)
                    .filter(|&j| {
                        data[j] == CLFLUSH_PREFIX_0
                            && data[j + 1] == CLFLUSH_PREFIX_1
                            && (data[j + 2] & CLFLUSH_MODRM_MASK) == CLFLUSH_MODRM_BITS
                    })
                    .count();

                let severity = if clflush_count > 4 {
                    Severity::Critical
                } else {
                    Severity::Medium
                };

                findings.push(
                    Finding::new(
                        "rowhammer",
                        severity,
                        "Cache flush hammering loop detected (rowhammer pattern)",
                        &format!(
                            "CLFLUSH instruction at offset 0x{:08X} followed by a second \
                             CLFLUSH and a backward jump within 16 bytes. Found {} CLFLUSH \
                             instructions in the surrounding 128-byte window. This is the \
                             characteristic cache-flush based rowhammer loop pattern.",
                            flush_off, clflush_count
                        ),
                    )
                    .with_confidence(if clflush_count > 4 { 0.89 } else { 0.72 })
                    .with_details(serde_json::json!({
                        "offset": format!("0x{:08X}", flush_off),
                        "clflush_count_in_window": clflush_count,
                        "has_second_clflush": has_second_clflush,
                        "has_backward_jmp": has_backward_jmp,
                        "has_backward_jcc": has_backward_jcc,
                        "technique": "Cache-flush based DRAM rowhammer",
                    }))
                    .with_recommendation(
                        "Verify this code is not reachable from unprivileged contexts. \
                         Enable DRAM Target Row Refresh (TRR) and ECC. Consider \
                         BIOS/UEFI mitigations that increase DRAM refresh rates.",
                    ),
                );
            }
        }

        findings
    }

    /// Detect memory controller tREFI register manipulation or embedded tREFI/REFRESH strings
    /// that suggest refresh rate suppression — a prerequisite for rowhammer.
    fn check_refresh_suppression(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        // ASCII marker scan
        let markers: &[(&[u8], &str)] = &[(TREFI_MARKER, "tREFI"), (REFRESH_MARKER, "REFRESH")];
        for &(marker, label) in markers {
            for pos in (0..data.len().saturating_sub(marker.len()))
                .filter(|&p| data[p..].starts_with(marker))
            {
                findings.push(
                    Finding::new(
                        "rowhammer",
                        Severity::High,
                        "DRAM refresh timing string found",
                        &format!(
                            "'{}' string at offset 0x{:08X}. Presence of refresh timing \
                             symbols in firmware suggests code that manipulates DRAM refresh \
                             intervals, potentially to suppress refresh and enable rowhammer.",
                            label, pos
                        ),
                    )
                    .with_confidence(0.62)
                    .with_details(serde_json::json!({
                        "offset": format!("0x{:08X}", pos),
                        "marker": label,
                        "technique": "DRAM refresh rate manipulation",
                    }))
                    .with_recommendation(
                        "Investigate firmware code at this offset for memory controller \
                         register writes that reduce tREFI below the JEDEC minimum. \
                         Lock memory controller timing registers before OS handoff.",
                    ),
                );
            }
        }

        // PCI config space tREFI register pattern: DDR_TREFI_CONFIG_OFFSET (0x3E) followed
        // by bytes that represent an extended refresh interval (high byte >= 0x10, i.e.,
        // > 4096 clocks above the default ~7.8 µs JEDEC interval).
        //
        // Structural anchor: a bare 0x3E byte followed by a large value is
        // ubiquitous in firmware volumes. A genuine memory-controller
        // register write programs the PCI config ports (0xCF8 address /
        // 0xCFC data) and issues an OUT — require that context.
        for i in 0..data.len().saturating_sub(3) {
            if data[i] != DDR_TREFI_CONFIG_OFFSET {
                continue;
            }
            // The subsequent two bytes form a 16-bit register value.
            // Default tREFI in DDR4 is ~0x1170 clocks; values above 0x3000 are extended.
            let val = u16::from_le_bytes([data[i + 1], data[i + 2]]);
            if val < 0x3000 {
                continue;
            }

            // Look for a PCI config port immediate (MOV DX, 0xCF8 / 0xCFC,
            // or MOV EDX, imm32) and an OUT DX instruction in the
            // surrounding window.
            let ctx_start = i.saturating_sub(24);
            let ctx_end = (i + 24).min(data.len());
            let ctx = &data[ctx_start..ctx_end];
            let has_pci_port = ctx.windows(4).any(|w| {
                (w[0] == 0x66
                    && w[1] == 0xBA
                    && (w[2..4] == [0xF8, 0xC7] || w[2..4] == [0xFC, 0xC7]))
                    || (w[0] == 0xBA
                        && (w[1..4] == [0xF8, 0xC7, 0x00] || w[1..4] == [0xFC, 0xC7, 0x00]))
            });
            let has_out_dx = ctx.contains(&0xEF); // OUT DX, EAX
            if !has_pci_port || !has_out_dx {
                continue;
            }

            findings.push(
                Finding::new(
                    "rowhammer",
                    Severity::High,
                    "Extended tREFI value in memory controller register write",
                    &format!(
                        "PCI config offset 0x3E (DDR timing) at firmware offset \
                         0x{:08X} contains value 0x{:04X}, which significantly exceeds \
                         the JEDEC default tREFI (~0x1170). Extending the refresh \
                         interval increases rowhammer susceptibility.",
                        i, val
                    ),
                )
                .with_confidence(0.75)
                .with_details(serde_json::json!({
                    "offset": format!("0x{:08X}", i),
                    "config_offset": "0x3E",
                    "trefi_value": format!("0x{:04X}", val),
                    "technique": "DRAM tREFI suppression for rowhammer",
                }))
                .with_recommendation(
                    "Prevent firmware from extending DRAM refresh intervals beyond \
                     JEDEC minimums. Lock tREFI configuration registers in memory \
                     controller initialization code.",
                ),
            );
        }

        findings
    }

    /// Detect many-sided row activation patterns: 4+ MOV instructions with memory addresses
    /// spaced by multiples of ROW_SIZE_STEP (0x2000) within a 128-byte code region.
    fn check_trr_bypass_pattern(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Scan 128-byte windows for MOV instructions that carry 32-bit displacements
        // and collect those displacements. If 4+ displacements form an arithmetic
        // sequence with common difference ROW_SIZE_STEP, flag as TRR bypass.
        let window_size = 128usize;

        let mut i = 0usize;
        while i + window_size <= data.len() {
            let window = &data[i..i + window_size];
            let mut displacements: Vec<u32> = Vec::new();

            let mut j = 0usize;
            while j + 5 < window.len() {
                if window[j] == MOV_LOAD || window[j] == MOV_STORE {
                    // Crude heuristic: ModRM byte with mod=10 (bits 7:6 = 10 = 0x80)
                    let modrm = window[j + 1];
                    if (modrm & 0xC0) == 0x80 && j + 6 <= window.len() {
                        let disp = u32::from_le_bytes([
                            window[j + 2],
                            window[j + 3],
                            window[j + 4],
                            window[j + 5],
                        ]);
                        displacements.push(disp);
                        j += 6;
                        continue;
                    }
                }
                j += 1;
            }

            if displacements.len() >= 4 {
                // Sort and check for arithmetic progression with step ROW_SIZE_STEP
                displacements.sort_unstable();
                let mut step_count = 1usize;
                for k in 1..displacements.len() {
                    let diff = displacements[k].wrapping_sub(displacements[k - 1]);
                    if diff == ROW_SIZE_STEP || diff == ROW_SIZE_STEP * 2 {
                        step_count += 1;
                    }
                }

                if step_count >= 4 {
                    findings.push(
                        Finding::new(
                            "rowhammer",
                            Severity::Critical,
                            "Many-sided TRR bypass rowhammer pattern",
                            &format!(
                                "Found {} MOV instructions with memory displacements forming a \
                                 0x{:04X}-byte arithmetic progression within a 128-byte code \
                                 region at firmware offset 0x{:08X}. This is the characteristic \
                                 many-sided rowhammer access pattern used to bypass Target Row \
                                 Refresh (TRR) mitigations (e.g., TRRespass).",
                                step_count, ROW_SIZE_STEP, i
                            ),
                        )
                        .with_confidence(0.85)
                        .with_details(serde_json::json!({
                            "region_offset": format!("0x{:08X}", i),
                            "row_step_bytes": format!("0x{:04X}", ROW_SIZE_STEP),
                            "arithmetic_mov_count": step_count,
                            "displacements": displacements.iter().map(|d| format!("0x{:08X}", d)).collect::<Vec<_>>(),
                            "technique": "Many-sided TRR bypass (TRRespass / Half-Double)",
                        }))
                        .with_recommendation(
                            "Ensure DRAM modules with effective TRR are used. Apply BIOS \
                             mitigations (PARA, increased refresh, pTRR). Evaluate DDR5 \
                             on-die ECC as an additional mitigation layer.",
                        ),
                    );
                    // Advance past this window to avoid overlapping findings
                    i += window_size;
                    continue;
                }
            }

            i += 1;
        }

        findings
    }

    /// Detect DRAM geometry bit-field extraction sequences: SHR + AND + SHR patterns
    /// used to extract bank/row/column bits from physical addresses.
    /// More than 3 such sequences within a 64-byte window indicate rowhammer tooling.
    fn check_physical_address_calc(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        let window_size = 64usize;
        let mut i = 0usize;

        while i + window_size <= data.len() {
            let window = &data[i..i + window_size];

            // Count shift-mask triplets (SHR/SHL followed by AND) in the window
            let mut triplet_count = 0usize;
            let mut j = 0usize;

            while j + 3 < window.len() {
                // Match: C1 E8/E0 imm8  (SHR or SHL r/m32, imm8)
                let is_shift = window[j] == SHIFT_PREFIX
                    && (window[j + 1] == SHR_MODRM || window[j + 1] == SHL_MODRM);

                if is_shift {
                    // Look for AND within the next 8 bytes
                    let lookahead_end = (j + 12).min(window.len());
                    let lookahead = &window[j + 3..lookahead_end];
                    let has_and = lookahead.iter().any(|&b| b == AND_OP_0 || b == AND_OP_1);

                    // Look for a second SHR within the next 8 bytes after AND
                    let has_second_shift = lookahead
                        .windows(2)
                        .any(|w| w[0] == SHIFT_PREFIX && (w[1] == SHR_MODRM || w[1] == SHL_MODRM));

                    if has_and && has_second_shift {
                        triplet_count += 1;
                    }
                    j += 3; // skip past this shift instruction
                } else {
                    j += 1;
                }
            }

            if triplet_count > 3 {
                findings.push(
                    Finding::new(
                        "rowhammer",
                        Severity::High,
                        "DRAM physical address geometry extraction pattern",
                        &format!(
                            "Found {} SHR/SHL + AND + SHR/SHL triplets within a 64-byte \
                             window at firmware offset 0x{:08X}. Sequences of shift-mask \
                             operations are characteristic of DRAM address interleaving \
                             geometry calculations used to construct rowhammer access patterns \
                             that target specific DRAM rows.",
                            triplet_count, i
                        ),
                    )
                    .with_confidence(0.78)
                    .with_details(serde_json::json!({
                        "region_offset": format!("0x{:08X}", i),
                        "shift_mask_triplets": triplet_count,
                        "technique": "DRAM physical address / geometry bit extraction for rowhammer",
                    }))
                    .with_recommendation(
                        "Investigate whether this code performs DRAM address reverse \
                         engineering. Restrict access to physical memory mapping interfaces \
                         (e.g., /dev/mem, pagemap) that enable rowhammer tooling.",
                    ),
                );
                i += window_size;
                continue;
            }

            i += 1;
        }

        findings
    }
}

impl Detector for RowhammerDetector {
    fn name(&self) -> &str {
        "rowhammer"
    }

    fn detect(&self, target_path: &Path) -> Result<Vec<Finding>, DetectorError> {
        let data = std::fs::read(target_path).map_err(DetectorError::Io)?;
        let mut findings = Vec::new();

        findings.extend(self.check_cache_flush_hammer(&data));
        findings.extend(self.check_refresh_suppression(&data));
        findings.extend(self.check_trr_bypass_pattern(&data));
        findings.extend(self.check_physical_address_calc(&data));

        Ok(findings)
    }
}
