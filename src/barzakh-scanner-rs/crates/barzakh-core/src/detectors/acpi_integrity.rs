use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};

const ACPI_SIGNATURES: &[&[u8; 4]] = &[b"DSDT", b"SSDT", b"XSDT", b"RSDT"];
const AML_OP_REGION: [u8; 2] = [0x5B, 0x80];
const AML_SYSTEM_MEMORY: u8 = 0x00;
const KERNEL_SPACE_THRESHOLD: u64 = 0xFFFF800000000000;
const MAX_NORMAL_SSDT_COUNT: usize = 15;

pub struct AcpiIntegrityDetector;

impl Default for AcpiIntegrityDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl AcpiIntegrityDetector {
    pub fn new() -> Self {
        Self
    }

    fn check_acpi_checksum(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Look for ACPI table headers and validate checksums
        for sig in ACPI_SIGNATURES {
            let sig_slice: &[u8] = sig.as_slice();

            for (i, window) in data.windows(4).enumerate() {
                if window == sig_slice {
                    // ACPI table header:
                    // Signature (4) + Length (4) + Revision (1) + Checksum (1) + ...
                    if i + 8 > data.len() {
                        continue;
                    }

                    let table_length =
                        u32::from_le_bytes(data[i + 4..i + 8].try_into().unwrap_or([0; 4]))
                            as usize;

                    // Sanity check on table length
                    if !(36..=0x1000000).contains(&table_length)
                        || i + table_length > data.len()
                    {
                        continue;
                    }

                    // Sum all bytes in the table - should be 0 mod 256
                    let checksum: u8 = data[i..i + table_length]
                        .iter()
                        .fold(0u8, |acc, &b| acc.wrapping_add(b));

                    if checksum != 0 {
                        let sig_str = std::str::from_utf8(sig_slice).unwrap_or("????");
                        findings.push(
                            Finding::new(
                                "acpi_integrity",
                                Severity::High,
                                "ACPI table checksum failure",
                                &format!(
                                    "ACPI {} table at offset 0x{:08X} (length={} bytes) \
                                     has invalid checksum (sum=0x{:02X}, expected 0x00). \
                                     This indicates the table has been modified without \
                                     updating the checksum.",
                                    sig_str, i, table_length, checksum
                                ),
                            )
                            .with_confidence(0.80)
                            .with_details(serde_json::json!({
                                "offset": format!("0x{:08X}", i),
                                "signature": sig_str,
                                "table_length": table_length,
                                "checksum": format!("0x{:02X}", checksum),
                            }))
                            .with_recommendation(
                                "Investigate the ACPI table for unauthorized modifications. \
                                 Compare against original firmware tables.",
                            ),
                        );
                    }
                }
            }
        }

        findings
    }

    fn check_aml_injection(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        // First, find DSDT/SSDT tables to scope the AML scan
        let dsdt_ssdt_sigs: &[&[u8; 4]] = &[b"DSDT", b"SSDT"];

        for sig in dsdt_ssdt_sigs {
            let sig_slice: &[u8] = sig.as_slice();

            for (table_start, window) in data.windows(4).enumerate() {
                if window != sig_slice {
                    continue;
                }

                if table_start + 8 > data.len() {
                    continue;
                }

                let table_length = u32::from_le_bytes(
                    data[table_start + 4..table_start + 8]
                        .try_into()
                        .unwrap_or([0; 4]),
                ) as usize;

                if !(36..=0x1000000).contains(&table_length)
                    || table_start + table_length > data.len()
                {
                    continue;
                }

                // Scan within the table for OperationRegion opcodes
                let table_data = &data[table_start..table_start + table_length];

                for (j, op_window) in table_data.windows(12).enumerate() {
                    if op_window[0..2] != AML_OP_REGION {
                        continue;
                    }

                    // OperationRegion format: OpRegion(2) + NameSeg(4) + RegionSpace(1) + Offset + Length
                    // RegionSpace at offset +6 (after 2-byte opcode + 4-byte name)
                    let region_space = op_window[6];

                    if region_space != AML_SYSTEM_MEMORY {
                        continue;
                    }

                    // Try to parse the address (may be encoded as various AML integer types)
                    // QWordConst prefix = 0x0E, DWordConst prefix = 0x0C
                    let addr_offset = 7;
                    let address = if addr_offset + 8 < op_window.len()
                        && op_window[addr_offset] == 0x0E
                    {
                        // QWord constant
                        u64::from_le_bytes(
                            op_window[addr_offset + 1..addr_offset + 9]
                                .try_into()
                                .unwrap_or([0; 8]),
                        )
                    } else if addr_offset + 4 < op_window.len() && op_window[addr_offset] == 0x0C {
                        // DWord constant
                        u32::from_le_bytes(
                            op_window[addr_offset + 1..addr_offset + 5]
                                .try_into()
                                .unwrap_or([0; 4]),
                        ) as u64
                    } else {
                        continue;
                    };

                    // Check if address targets kernel space
                    if address > KERNEL_SPACE_THRESHOLD {
                        let sig_str = std::str::from_utf8(sig_slice).unwrap_or("????");
                        findings.push(
                            Finding::new(
                                "acpi_integrity",
                                Severity::Critical,
                                "Suspicious AML OperationRegion targeting kernel memory",
                                &format!(
                                    "AML OperationRegion in {} table (offset 0x{:08X}) \
                                     targets SystemMemory at address 0x{:016X} which is \
                                     in kernel space. This may be used for kernel memory \
                                     access from ACPI context.",
                                    sig_str,
                                    table_start + j,
                                    address
                                ),
                            )
                            .with_confidence(0.75)
                            .with_details(serde_json::json!({
                                "table_offset": format!("0x{:08X}", table_start),
                                "table_signature": sig_str,
                                "opregion_offset": format!("0x{:08X}", table_start + j),
                                "target_address": format!("0x{:016X}", address),
                                "region_space": "SystemMemory",
                            }))
                            .with_recommendation(
                                "Investigate the AML OperationRegion. Legitimate firmware \
                                 should not access kernel address space through ACPI.",
                            ),
                        );
                    }
                }
            }
        }

        findings
    }

    fn check_acpi_table_count(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Count SSDT table signatures in the image
        let ssdt_sig: &[u8] = b"SSDT";
        let mut ssdt_count = 0;

        for window in data.windows(4) {
            if window == ssdt_sig {
                ssdt_count += 1;
            }
        }

        if ssdt_count > MAX_NORMAL_SSDT_COUNT {
            findings.push(
                Finding::new(
                    "acpi_integrity",
                    Severity::Medium,
                    "Abnormal SSDT table count - possible injection",
                    &format!(
                        "Found {} SSDT table signatures in the firmware image. \
                         Typical systems have 1-10 SSDTs. An abnormally high count \
                         may indicate injected ACPI tables for persistence or \
                         privilege escalation.",
                        ssdt_count
                    ),
                )
                .with_confidence(0.50)
                .with_details(serde_json::json!({
                    "ssdt_count": ssdt_count,
                    "threshold": MAX_NORMAL_SSDT_COUNT,
                }))
                .with_recommendation(
                    "Review all SSDT tables in the firmware image. Identify and \
                     remove any that are not part of the original firmware.",
                ),
            );
        }

        findings
    }
}

impl Detector for AcpiIntegrityDetector {
    fn name(&self) -> &str {
        "acpi_integrity"
    }

    fn detect(&self, target_path: &Path) -> Result<Vec<Finding>, DetectorError> {
        let data = std::fs::read(target_path).map_err(DetectorError::Io)?;
        let mut findings = Vec::new();

        findings.extend(self.check_acpi_checksum(&data));
        findings.extend(self.check_aml_injection(&data));
        findings.extend(self.check_acpi_table_count(&data));

        Ok(findings)
    }
}
