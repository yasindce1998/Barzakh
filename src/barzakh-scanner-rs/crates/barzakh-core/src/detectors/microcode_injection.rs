use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};

// Intel MCU header magic: header_version field = 1 (u32 LE)
const INTEL_MCU_MAGIC: [u8; 4] = [0x01, 0x00, 0x00, 0x00];
// Intel MCU header is 48 bytes; data_size threshold for "abnormally large"
const INTEL_MCU_HEADER_SIZE: usize = 48;
const INTEL_MCU_MAX_DATA_SIZE: u32 = 0x4000; // 16 KB
                                             // AMD microcode container starts with 4 zero bytes
const AMD_MCU_MAGIC: [u8; 4] = [0x00, 0x00, 0x00, 0x00];
const AMD_MCU_MAX_TABLE_SIZE: u32 = 0x2000;
// Intel FIT table signature bytes (precede legitimate MCU references)
const FIT_MAGIC: [u8; 4] = [0x5F, 0x46, 0x49, 0x54]; // "_FIT"
const FIT_SEARCH_WINDOW: usize = 4096;

pub struct MicrocodeInjectionDetector;

impl Default for MicrocodeInjectionDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl MicrocodeInjectionDetector {
    pub fn new() -> Self {
        Self
    }

    /// Check whether a 3-byte BCD date field (stored as a u32, lower 3 bytes) is valid.
    /// Intel date format is 0xMMDDYYYY in BCD.
    fn is_valid_bcd_date(date: u32) -> bool {
        // Extract BCD nibbles
        let month_hi = (date >> 28) & 0xF;
        let month_lo = (date >> 24) & 0xF;
        let day_hi = (date >> 20) & 0xF;
        let day_lo = (date >> 16) & 0xF;
        let year_hi = (date >> 12) & 0xF;
        let year_lo = (date >> 8) & 0xF;
        let year_lo2 = (date >> 4) & 0xF;
        let year_lo3 = date & 0xF;

        // All nibbles must be 0–9 (valid BCD)
        let nibbles = [
            month_hi, month_lo, day_hi, day_lo, year_hi, year_lo, year_lo2, year_lo3,
        ];
        if nibbles.iter().any(|&n| n > 9) {
            return false;
        }

        let month = month_hi * 10 + month_lo;
        let day = day_hi * 10 + day_lo;

        (1..=12).contains(&month) && (1..=31).contains(&day)
    }

    /// Scan for Intel MCU headers at 48-byte-aligned offsets.
    fn check_intel_mcu_headers(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        let mut offset = 0usize;
        while offset + INTEL_MCU_HEADER_SIZE <= data.len() {
            // Intel MCU header_version == 1 at aligned offsets
            if data[offset..offset + 4] == INTEL_MCU_MAGIC {
                // Parse header fields (all u32 LE)
                let read_u32 = |o: usize| -> u32 {
                    u32::from_le_bytes([data[o], data[o + 1], data[o + 2], data[o + 3]])
                };

                let _update_revision = read_u32(offset + 4);
                let date = read_u32(offset + 8);
                let processor_signature = read_u32(offset + 12);
                let _checksum = read_u32(offset + 16);
                let loader_revision = read_u32(offset + 20);
                let _processor_flags = read_u32(offset + 24);
                let data_size = read_u32(offset + 28);
                let total_size = read_u32(offset + 32);

                // Structural gate: every real Intel MCU header carries
                // loader_revision == 1. `01 00 00 00` alone is the most
                // common u32 in binary data, so requiring the loader
                // revision keeps ordinary firmware bytes from masquerading
                // as microcode headers.
                if loader_revision != 1 {
                    offset += INTEL_MCU_HEADER_SIZE;
                    continue;
                }

                // Validate: total_size should equal data_size + 48
                let expected_total = data_size.saturating_add(INTEL_MCU_HEADER_SIZE as u32);
                let oversized = data_size > INTEL_MCU_MAX_DATA_SIZE;
                let size_mismatch = total_size != expected_total && total_size != 0;
                let bad_date = !Self::is_valid_bcd_date(date);

                if oversized || size_mismatch || bad_date {
                    let severity = if oversized {
                        Severity::Critical
                    } else {
                        Severity::High
                    };

                    let reason = match (oversized, size_mismatch, bad_date) {
                        (true, _, _) => {
                            format!("data_size 0x{:X} exceeds 16 KB threshold", data_size)
                        }
                        (_, true, _) => format!(
                            "total_size 0x{:X} != data_size 0x{:X} + 48",
                            total_size, data_size
                        ),
                        _ => format!("invalid BCD date field 0x{:08X}", date),
                    };

                    findings.push(
                        Finding::new(
                            "microcode_injection",
                            severity,
                            "Suspicious Intel MCU header detected",
                            &format!(
                                "Intel MCU header at offset 0x{:08X} has anomalous fields: {}. \
                                 Processor signature: 0x{:08X}. Tampered or injected microcode \
                                 updates can subvert CPU security guarantees.",
                                offset, reason, processor_signature
                            ),
                        )
                        .with_confidence(0.85)
                        .with_details(serde_json::json!({
                            "offset": format!("0x{:08X}", offset),
                            "data_size": format!("0x{:X}", data_size),
                            "total_size": format!("0x{:X}", total_size),
                            "date": format!("0x{:08X}", date),
                            "processor_signature": format!("0x{:08X}", processor_signature),
                            "oversized": oversized,
                            "size_mismatch": size_mismatch,
                            "bad_date": bad_date,
                        }))
                        .with_recommendation(
                            "Verify all CPU microcode updates against vendor-signed capsules. \
                             Reject firmware images containing unsigned or malformed MCU headers.",
                        ),
                    );
                }
            }

            offset += INTEL_MCU_HEADER_SIZE;
        }

        findings
    }

    /// Look for AMD microcode container: 4 zero bytes then table_size.
    fn check_amd_equiv_table(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        for i in 0..data.len().saturating_sub(12) {
            if data[i..i + 4] == AMD_MCU_MAGIC {
                // Next u32 LE = table_size
                let table_size =
                    u32::from_le_bytes([data[i + 4], data[i + 5], data[i + 6], data[i + 7]]);

                if table_size == 0 {
                    continue;
                }

                // Structural gate: a real AMD equivalence table has 16-byte
                // entries, a sane size, at least two entries with real
                // (non-zero) processor IDs, and a null terminator entry.
                // Four zero bytes followed by a large u32 occur constantly
                // in firmware padding; only table-shaped candidates are
                // worth analyzing.
                let entry_size = 16usize;
                if !(table_size as usize).is_multiple_of(entry_size)
                    || table_size as usize > AMD_MCU_MAX_TABLE_SIZE as usize + entry_size
                {
                    continue;
                }
                let table_len = table_size as usize;
                if i + 8 + table_len > data.len() {
                    continue;
                }
                let table_data = &data[i + 8..i + 8 + table_len];

                let mut nonzero_entries = 0usize;
                let mut total_entries = 0usize;
                let mut null_proc_nonzero_equiv = false;
                let mut entry_off = 0usize;
                while entry_off + entry_size <= table_data.len() {
                    let proc_id = u32::from_le_bytes([
                        table_data[entry_off],
                        table_data[entry_off + 1],
                        table_data[entry_off + 2],
                        table_data[entry_off + 3],
                    ]);
                    let equiv_id =
                        u16::from_le_bytes([table_data[entry_off + 8], table_data[entry_off + 9]]);
                    total_entries += 1;
                    if proc_id == 0 && equiv_id != 0 {
                        null_proc_nonzero_equiv = true;
                    }
                    // Real AMD processor signatures have a zero top byte
                    // and populated family/model bits (e.g. 0x00800F12);
                    // equivalence IDs are small. Noise tables carry tiny
                    // or scattered values.
                    if proc_id != 0
                        && (proc_id >> 24) == 0
                        && (proc_id & 0x00F0_0000) != 0
                        && (equiv_id >> 8) == 0
                    {
                        nonzero_entries += 1;
                    }
                    entry_off += entry_size;
                }

                // Terminator: the final entry must be null.
                let terminator_ok = table_data[table_len - entry_size..].iter().all(|&b| b == 0);

                // Every entry of a real equivalence table is a real
                // processor signature: the plausible entries must form the
                // majority. Random byte runs that survive the structural
                // gates have a plausible-entry rate near zero.
                if nonzero_entries < 2 || !terminator_ok || nonzero_entries * 2 < total_entries {
                    continue;
                }

                if null_proc_nonzero_equiv {
                    findings.push(
                        Finding::new(
                            "microcode_injection",
                            Severity::High,
                            "Suspicious AMD microcode equivalence table",
                            &format!(
                                "AMD microcode container at offset 0x{:08X} has an anomalous \
                                 equivalence table: entry has processor_id=0 with non-zero \
                                 equiv_id. This may indicate a tampered or injected AMD CPU \
                                 microcode update.",
                                i
                            ),
                        )
                        .with_confidence(0.80)
                        .with_details(serde_json::json!({
                            "offset": format!("0x{:08X}", i),
                            "table_size": format!("0x{:X}", table_size),
                            "suspicious_size": false,
                            "null_proc_nonzero_equiv": true,
                        }))
                        .with_recommendation(
                            "Validate AMD microcode containers against AMD vendor signatures. \
                             Check PSP-signed update capsule integrity.",
                        ),
                    );
                }
            }
        }

        findings
    }

    /// Detect MCU magic or "microcode" string outside of standard FIT-table regions.
    /// Look for structurally valid Intel MCU blobs that are not referenced
    /// by a Firmware Interface Table — microcode living outside the FIT
    /// capsule. The blob must checksum correctly (sum of dwords over
    /// total_size == 0): only a genuinely well-formed microcode image is
    /// worth reporting as an out-of-capsule implant, and noise byte
    /// sequences never satisfy the checksum. (Debug strings containing
    /// "microcode" are not references and are ignored.)
    fn check_unexpected_microcode_location(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        let mut offset = 0usize;
        while offset + INTEL_MCU_HEADER_SIZE <= data.len() {
            if data[offset..offset + 4] == INTEL_MCU_MAGIC {
                let read_u32 = |o: usize| -> u32 {
                    u32::from_le_bytes([data[o], data[o + 1], data[o + 2], data[o + 3]])
                };

                let date = read_u32(offset + 8);
                let loader_revision = read_u32(offset + 20);
                let data_size = read_u32(offset + 28);
                let total_size = read_u32(offset + 32);

                let expected_total = data_size.saturating_add(INTEL_MCU_HEADER_SIZE as u32);
                let structurally_valid = loader_revision == 1
                    && Self::is_valid_bcd_date(date)
                    && data_size <= INTEL_MCU_MAX_DATA_SIZE
                    && total_size == expected_total
                    && total_size > 0
                    && offset + total_size as usize <= data.len();

                // Checksum: sum of all dwords over the image must be zero.
                let checksum_ok = structurally_valid && {
                    let mut sum: u32 = 0;
                    let end = offset + total_size as usize;
                    let mut p = offset;
                    while p + 4 <= end {
                        sum = sum.wrapping_add(read_u32(p));
                        p += 4;
                    }
                    sum == 0
                };

                if checksum_ok {
                    // Check whether a FIT table signature exists within 4KB before this offset
                    let search_start = offset.saturating_sub(FIT_SEARCH_WINDOW);
                    let preceding = &data[search_start..offset];
                    let fit_present = preceding.windows(FIT_MAGIC.len()).any(|w| w == FIT_MAGIC);

                    if !fit_present {
                        findings.push(
                            Finding::new(
                                "microcode_injection",
                                Severity::High,
                                "Microcode blob outside expected firmware region",
                                &format!(
                                    "Found a checksum-valid Intel MCU image at offset \
                                     0x{:08X} without a preceding FIT table signature within \
                                     4 KB. Legitimate microcode updates are referenced via \
                                     the Firmware Interface Table; orphaned blobs suggest \
                                     injection outside the update capsule.",
                                    offset
                                ),
                            )
                            .with_confidence(0.75)
                            .with_details(serde_json::json!({
                                "offset": format!("0x{:08X}", offset),
                                "match_type": "mcu_blob",
                                "total_size": format!("0x{:X}", total_size),
                                "fit_signature_found_nearby": false,
                            }))
                            .with_recommendation(
                                "Inspect the firmware image for MCU blobs outside the standard \
                                 FIT-referenced update capsule and compare against a known-good baseline.",
                            ),
                        );
                    }
                }
            }

            offset += INTEL_MCU_HEADER_SIZE;
        }

        findings
    }
}

impl Detector for MicrocodeInjectionDetector {
    fn name(&self) -> &str {
        "microcode_injection"
    }

    fn detect(&self, target_path: &Path) -> Result<Vec<Finding>, DetectorError> {
        self.detect_context(&crate::ScanContext::load(target_path)?)
    }
    fn detect_context(&self, context: &crate::ScanContext) -> Result<Vec<Finding>, DetectorError> {
        let data = context.shared_bytes();
        let mut findings = Vec::new();

        findings.extend(self.check_intel_mcu_headers(&data));
        findings.extend(self.check_amd_equiv_table(&data));
        findings.extend(self.check_unexpected_microcode_location(&data));

        Ok(findings)
    }
}
