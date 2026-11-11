use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};

const S3_DISPATCH_OPCODE: u8 = 0x03;
const S3_MEM_WRITE_OPCODE: u8 = 0x00;
const S3_IO_WRITE_OPCODE: u8 = 0x01;
const S3_PCI_WRITE_OPCODE: u8 = 0x02;
const FIRMWARE_RANGE_LOW: u64 = 0x7E000000;
const FIRMWARE_RANGE_HIGH: u64 = 0x80000000;

pub struct S3BootscriptDetector;

impl Default for S3BootscriptDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl S3BootscriptDetector {
    pub fn new() -> Self {
        Self
    }

    /// True when at least two well-formed script entries chain exactly
    /// into the entry at `dispatch_off` (each predecessor's length field
    /// advances the parse onto the next opcode).
    fn has_chained_predecessors(&self, data: &[u8], dispatch_off: usize) -> bool {
        const VALID_OPCODES: [u8; 3] =
            [S3_MEM_WRITE_OPCODE, S3_IO_WRITE_OPCODE, S3_PCI_WRITE_OPCODE];
        const MAX_LOOKBACK: usize = 128;
        const MIN_ENTRY_LEN: usize = 2;
        const MAX_ENTRY_LEN: usize = 64;
        const MIN_PREDECESSORS: usize = 2;

        let start_min = dispatch_off.saturating_sub(MAX_LOOKBACK);
        for start in start_min..dispatch_off {
            let mut pos = start;
            let mut chain = 0usize;
            while pos < dispatch_off {
                if pos + 2 > data.len() {
                    break;
                }
                if !VALID_OPCODES.contains(&data[pos]) {
                    break;
                }
                let entry_len = data[pos + 1] as usize;
                if !(MIN_ENTRY_LEN..=MAX_ENTRY_LEN).contains(&entry_len) {
                    break;
                }
                pos += entry_len;
                chain += 1;
            }
            if pos == dispatch_off && chain >= MIN_PREDECESSORS {
                return true;
            }
        }
        false
    }

    fn check_bootscript_opcodes(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        // S3 boot script entries start with an opcode byte followed by length
        // Look for DISPATCH opcode (0x03) which executes arbitrary code
        // The DISPATCH entry format: opcode(1) + length(1) + entry_point(8)
        for (i, window) in data.windows(10).enumerate() {
            if window[0] == S3_DISPATCH_OPCODE {
                let length = window[1] as usize;
                // Valid DISPATCH entries have a specific length (typically 10 bytes)
                if length == 10 {
                    let entry_point =
                        u64::from_le_bytes(window[2..10].try_into().unwrap_or([0; 8]));

                    // Entry point should be a valid address
                    if entry_point > 0x1000 && entry_point < 0xFFFFFFFF_FFFFFFFF {
                        // Structural gate: an S3 boot script is a chain of
                        // entries where each entry's length advances the
                        // parse to the next opcode. A lone `03 0A` byte pair
                        // is coincidence; require at least two well-formed
                        // predecessor entries that chain exactly into this
                        // DISPATCH.
                        if !self.has_chained_predecessors(data, i) {
                            continue;
                        }

                        findings.push(
                            Finding::new(
                                "s3_bootscript",
                                Severity::High,
                                "S3 boot script DISPATCH opcode detected",
                                &format!(
                                    "S3 boot script DISPATCH entry at offset 0x{:08X} with \
                                     entry point 0x{:016X}. DISPATCH opcodes execute arbitrary \
                                     code during S3 resume and can be abused for persistence.",
                                    i, entry_point
                                ),
                            )
                            .with_confidence(0.60)
                            .with_details(serde_json::json!({
                                "offset": format!("0x{:08X}", i),
                                "entry_point": format!("0x{:016X}", entry_point),
                                "opcode_length": length,
                            }))
                            .with_recommendation(
                                "Verify S3 boot script DISPATCH entries point to legitimate \
                                 firmware code. Remove any unauthorized DISPATCH opcodes.",
                            ),
                        );
                    }
                }
            }
        }

        findings
    }

    fn check_va_map_hook(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        // EFI Runtime Services Table signature: look for the table header
        // The table has a known header signature "RUNT" (0x544E5552)
        let runt_sig: &[u8] = &[0x52, 0x55, 0x4E, 0x54]; // "RUNT" in LE

        for (i, window) in data.windows(4).enumerate() {
            if window == runt_sig {
                // Runtime services table has function pointers at known offsets
                // SetVirtualAddressMap is at offset 0x68 from table start (after header)
                let va_map_offset = i + 0x68;
                if va_map_offset + 8 > data.len() {
                    continue;
                }

                let func_ptr = u64::from_le_bytes(
                    data[va_map_offset..va_map_offset + 8]
                        .try_into()
                        .unwrap_or([0; 8]),
                );

                // Check if function pointer is outside expected firmware range
                if func_ptr != 0
                    && !(FIRMWARE_RANGE_LOW..=FIRMWARE_RANGE_HIGH).contains(&func_ptr)
                    && func_ptr < 0xFFFF800000000000
                {
                    findings.push(
                        Finding::new(
                            "s3_bootscript",
                            Severity::Critical,
                            "Virtual address map hook artifacts detected",
                            &format!(
                                "EFI Runtime Services table at offset 0x{:08X} has \
                                 SetVirtualAddressMap pointer 0x{:016X} which is outside \
                                 the expected firmware address range (0x{:08X}-0x{:08X}). \
                                 This indicates potential runtime services hooking.",
                                i, func_ptr, FIRMWARE_RANGE_LOW, FIRMWARE_RANGE_HIGH
                            ),
                        )
                        .with_confidence(0.65)
                        .with_details(serde_json::json!({
                            "table_offset": format!("0x{:08X}", i),
                            "function_pointer": format!("0x{:016X}", func_ptr),
                            "expected_range_low": format!("0x{:08X}", FIRMWARE_RANGE_LOW),
                            "expected_range_high": format!("0x{:08X}", FIRMWARE_RANGE_HIGH),
                        }))
                        .with_recommendation(
                            "Validate all EFI Runtime Services function pointers against \
                             known firmware memory ranges.",
                        ),
                    );
                }
            }
        }

        findings
    }

    /// Heuristic gate: does this data contain a plausible boot script table?
    /// A real S3 boot script is a sequence of entries with valid opcodes and
    /// sane lengths (each entry advances the parse). Require a run of at
    /// least 3 such entries somewhere in the data before the integrity
    /// walk runs, so zero-filled or random data is not misread as a
    /// corrupted table.
    fn looks_like_bootscript(data: &[u8]) -> bool {
        let valid_opcodes = [
            S3_MEM_WRITE_OPCODE,
            S3_IO_WRITE_OPCODE,
            S3_PCI_WRITE_OPCODE,
            S3_DISPATCH_OPCODE,
        ];

        for start in 0..data.len().saturating_sub(6) {
            if !valid_opcodes.contains(&data[start]) {
                continue;
            }

            // Walk up to 3 consecutive entries from this candidate start.
            let mut i = start;
            let mut run = 0;
            while i + 2 < data.len() && run < 3 {
                let opcode = data[i];
                if !valid_opcodes.contains(&opcode) {
                    break;
                }
                let length = data[i + 1] as usize;
                // A real entry has a non-zero, sane length and fits in data.
                if length == 0 || length > 4096 || i + length > data.len() {
                    break;
                }
                run += 1;
                i += length;
            }

            if run >= 3 {
                return true;
            }
        }

        false
    }

    fn check_bootscript_integrity(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Look for sequences of boot script opcodes that form a table
        // Valid opcodes: MEM_WRITE(0x00), IO_WRITE(0x01), PCI_WRITE(0x02), DISPATCH(0x03)
        let valid_opcodes = [
            S3_MEM_WRITE_OPCODE,
            S3_IO_WRITE_OPCODE,
            S3_PCI_WRITE_OPCODE,
            S3_DISPATCH_OPCODE,
        ];

        // Require evidence of an actual boot script table before trusting
        // the integrity walk: opcode 0x00 is MEM_WRITE and opcode 0x00 with
        // length 0x00 occurs in any zero-filled region (e.g. erased flash),
        // which produced false Medium findings on clean baselines. A real
        // script contains multiple consecutive parseable entries.
        if !Self::looks_like_bootscript(data) {
            return findings;
        }

        // A corrupted table does not need per-offset enumeration: beyond a
        // handful of entries the report is noise, and unbounded emission
        // turned multi-MB memory dumps (megabytes of zero-filled RAM) into
        // millions of Findings and an OOM.
        const MAX_INTEGRITY_FINDINGS: usize = 64;

        let mut i = 0;
        while i + 2 < data.len() {
            if findings.len() >= MAX_INTEGRITY_FINDINGS {
                break;
            }
            let opcode = data[i];
            if valid_opcodes.contains(&opcode) {
                // Check if this is part of a boot script table by verifying
                // consecutive valid entries
                let length = data[i + 1] as usize;

                // Validate entry length
                if length == 0 {
                    // Opcode 0x00 with length 0x00 is also the signature of
                    // erased or uninitialized memory. A genuine corrupted
                    // entry sits among non-zero bytes; a `00 00` pair inside
                    // a longer zero run is not one. Skip zero runs wholesale
                    // instead of reporting every two bytes.
                    let run_end = data.len().min(i + 16);
                    if data[i..run_end].iter().all(|&b| b == 0) {
                        let skip = data[i..]
                            .iter()
                            .position(|&b| b != 0)
                            .unwrap_or(data.len() - i);
                        i += skip.max(1);
                        continue;
                    }
                    findings.push(
                        Finding::new(
                            "s3_bootscript",
                            Severity::Medium,
                            "Corrupted S3 boot script entry",
                            &format!(
                                "S3 boot script entry at offset 0x{:08X} has length=0, \
                                 indicating table corruption or manipulation.",
                                i
                            ),
                        )
                        .with_confidence(0.50)
                        .with_details(serde_json::json!({
                            "offset": format!("0x{:08X}", i),
                            "opcode": format!("0x{:02X}", opcode),
                            "length": 0,
                        })),
                    );
                    i += 2;
                    continue;
                }

                if length > 4096 {
                    findings.push(
                        Finding::new(
                            "s3_bootscript",
                            Severity::Medium,
                            "Corrupted S3 boot script entry",
                            &format!(
                                "S3 boot script entry at offset 0x{:08X} has length={}, \
                                 which exceeds maximum expected size. This indicates \
                                 table corruption or injection.",
                                i, length
                            ),
                        )
                        .with_confidence(0.50)
                        .with_details(serde_json::json!({
                            "offset": format!("0x{:08X}", i),
                            "opcode": format!("0x{:02X}", opcode),
                            "length": length,
                        })),
                    );
                    i += 2;
                    continue;
                }

                i += length;
            } else {
                i += 1;
            }
        }

        findings
    }
}

impl Detector for S3BootscriptDetector {
    fn name(&self) -> &str {
        "s3_bootscript"
    }

    fn detect(&self, target_path: &Path) -> Result<Vec<Finding>, DetectorError> {
        self.detect_context(&crate::ScanContext::load(target_path)?)
    }
    fn detect_context(&self, context: &crate::ScanContext) -> Result<Vec<Finding>, DetectorError> {
        let data = context.shared_bytes();
        let mut findings = Vec::new();

        findings.extend(self.check_bootscript_opcodes(&data));
        findings.extend(self.check_va_map_hook(&data));
        findings.extend(self.check_bootscript_integrity(&data));

        Ok(findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Seeds a minimal parseable 3-entry chain so the
    /// `looks_like_bootscript` gate opens.
    fn seed_chain(data: &mut [u8]) {
        data[0] = S3_MEM_WRITE_OPCODE;
        data[1] = 0x02;
        data[2] = S3_IO_WRITE_OPCODE;
        data[3] = 0x02;
        data[4] = S3_PCI_WRITE_OPCODE;
        data[5] = 0x02;
    }

    #[test]
    fn zero_filled_memory_does_not_explode() {
        // Regression: a parseable chain opens the integrity walk, which
        // then crosses megabytes of zero-filled RAM. Every two zero bytes
        // used to emit a Finding — a 256 MB memory dump OOM'd the scanner
        // past 13 GB of RSS. Zero runs must be skipped and findings stay
        // bounded.
        let mut data = vec![0u8; 4 * 1024 * 1024];
        seed_chain(&mut data);
        let detector = S3BootscriptDetector::new();
        let findings = detector.check_bootscript_integrity(&data);
        assert!(findings.len() <= 64, "findings must stay bounded");
    }

    #[test]
    fn isolated_zero_length_entry_is_reported() {
        // A length-0 entry surrounded by non-zero data is genuine
        // corruption and must still be reported.
        let mut data = vec![0xAAu8; 0x1000];
        seed_chain(&mut data);
        data[6] = S3_MEM_WRITE_OPCODE; // opcode with length 0 …
        data[7] = 0x00; // … embedded in non-zero context
        let detector = S3BootscriptDetector::new();
        let findings = detector.check_bootscript_integrity(&data);
        assert!(findings
            .iter()
            .any(|f| f.title.contains("Corrupted S3 boot script entry")));
    }

    #[test]
    fn dispatch_chain_still_detected() {
        // The s3_bootscript_inject layout: chained entries ending in a
        // DISPATCH with a suspicious entry point must yield the High
        // finding the corpus gate relies on.
        let mut data = vec![0u8; 0x2000];
        let offset = 0x100;
        data[offset] = S3_MEM_WRITE_OPCODE;
        data[offset + 1] = 0x10;
        data[offset + 0x10] = S3_IO_WRITE_OPCODE;
        data[offset + 0x11] = 0x08;
        let dispatch = offset + 0x18;
        data[dispatch] = S3_DISPATCH_OPCODE;
        data[dispatch + 1] = 0x0A;
        data[dispatch + 2..dispatch + 10].copy_from_slice(&0x41414141_DEADBEEFu64.to_le_bytes());

        let detector = S3BootscriptDetector::new();
        let findings = detector.check_bootscript_opcodes(&data);
        assert!(findings
            .iter()
            .any(|f| f.severity == Severity::High && f.title.contains("DISPATCH")));
    }
}
