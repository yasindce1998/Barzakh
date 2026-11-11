use std::path::Path;

use crate::baseline::Baseline;
use crate::detector::{Detector, DetectorError, Finding, Severity};

const EFI_RUNTIME_SERVICES_SIGNATURE: u64 = 0x56524553_544E5552; // "RUNTSERV"

const RUNTIME_SERVICE_NAMES: &[&str] = &[
    "GetTime",
    "SetTime",
    "GetWakeupTime",
    "SetWakeupTime",
    "SetVirtualAddressMap",
    "ConvertPointer",
    "GetVariable",
    "GetNextVariableName",
    "SetVariable",
    "GetNextHighMonotonicCount",
    "ResetSystem",
    "UpdateCapsule",
    "QueryCapsuleCapabilities",
    "QueryVariableInfo",
];

pub struct RuntimeHookDetector {
    #[allow(dead_code)]
    baseline: Option<Baseline>,
}

impl RuntimeHookDetector {
    pub fn new(baseline: Option<Baseline>) -> Self {
        Self { baseline }
    }

    fn find_runtime_services_table(&self, data: &[u8]) -> Option<usize> {
        let sig_bytes = EFI_RUNTIME_SERVICES_SIGNATURE.to_le_bytes();
        data.windows(8).position(|w| w == sig_bytes)
    }
}

impl Detector for RuntimeHookDetector {
    fn name(&self) -> &str {
        "runtime"
    }

    fn detect(&self, target_path: &Path) -> Result<Vec<Finding>, DetectorError> {
        self.detect_context(&crate::ScanContext::load(target_path)?)
    }
    fn detect_context(&self, context: &crate::ScanContext) -> Result<Vec<Finding>, DetectorError> {
        let data = context.shared_bytes();
        let mut findings = Vec::new();

        if let Some(table_offset) = self.find_runtime_services_table(&data) {
            let ptrs_offset = table_offset + 24; // after header
            let ptr_size = 8;

            for (i, name) in RUNTIME_SERVICE_NAMES.iter().enumerate() {
                let offset = ptrs_offset + i * ptr_size;
                if offset + ptr_size > data.len() {
                    break;
                }

                let ptr = u64::from_le_bytes(
                    data[offset..offset + ptr_size].try_into().unwrap_or([0; 8]),
                );

                if ptr == 0 || ptr == u64::MAX {
                    continue;
                }

                // GetVariable and SetVariable are high-value targets
                let is_critical = matches!(*name, "GetVariable" | "SetVariable" | "ResetSystem");

                // Validate pointer range
                let in_expected_range = !(0x1_0000_0000..0x7F00_0000_0000_0000).contains(&ptr);

                if !in_expected_range {
                    let severity = if is_critical {
                        Severity::Critical
                    } else {
                        Severity::High
                    };

                    findings.push(
                        Finding::new(
                            "runtime",
                            severity,
                            &format!("Runtime Services hook: {}", name),
                            &format!(
                                "Runtime service {} pointer 0x{:016X} is outside expected range.",
                                name, ptr
                            ),
                        )
                        .with_confidence(0.85)
                        .with_details(serde_json::json!({
                            "service": name,
                            "pointer": format!("0x{:016X}", ptr),
                            "table_offset": format!("0x{:08X}", table_offset),
                            "critical_service": is_critical,
                        }))
                        .with_recommendation(
                            "Runtime Services Table modified. Possible persistent rootkit.",
                        ),
                    );
                }
            }

            // CRC32 check
            if table_offset + 20 <= data.len() {
                let header_size = u32::from_le_bytes(
                    data[table_offset + 12..table_offset + 16]
                        .try_into()
                        .unwrap_or([0; 4]),
                ) as usize;
                let stored_crc = u32::from_le_bytes(
                    data[table_offset + 16..table_offset + 20]
                        .try_into()
                        .unwrap_or([0; 4]),
                );

                if table_offset + header_size <= data.len() && header_size > 0 {
                    let mut header_copy = data[table_offset..table_offset + header_size].to_vec();
                    if header_copy.len() >= 20 {
                        header_copy[16..20].fill(0);
                    }
                    let computed_crc = crc32fast::hash(&header_copy);

                    if stored_crc != computed_crc {
                        findings.push(
                            Finding::new(
                                "runtime",
                                Severity::Critical,
                                "Runtime Services Table CRC32 mismatch",
                                &format!(
                                    "Stored CRC: 0x{:08X}, Computed: 0x{:08X}. Table modified.",
                                    stored_crc, computed_crc
                                ),
                            )
                            .with_confidence(0.95),
                        );
                    }
                }
            }
        }

        Ok(findings)
    }
}
