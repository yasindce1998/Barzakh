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

        let mut i = 0;
        while i + 2 < data.len() {
            let opcode = data[i];
            if valid_opcodes.contains(&opcode) {
                // Check if this is part of a boot script table by verifying
                // consecutive valid entries
                let length = data[i + 1] as usize;

                // Validate entry length
                if length == 0 {
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
        let data = std::fs::read(target_path).map_err(DetectorError::Io)?;
        let mut findings = Vec::new();

        findings.extend(self.check_bootscript_opcodes(&data));
        findings.extend(self.check_va_map_hook(&data));
        findings.extend(self.check_bootscript_integrity(&data));

        Ok(findings)
    }
}
