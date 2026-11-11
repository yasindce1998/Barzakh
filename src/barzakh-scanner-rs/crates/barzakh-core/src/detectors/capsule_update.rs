use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};

const EFI_CAPSULE_GUID: [u8; 16] = [
    0xBD, 0x86, 0x66, 0x3B, 0x76, 0x0D, 0x30, 0x40, 0xB7, 0x0E, 0xB5, 0x51, 0x9E, 0x2F, 0xC5, 0xA0,
];

const EFI_FMP_CAPSULE_GUID: [u8; 16] = [
    0x78, 0xED, 0xE4, 0x6B, 0x26, 0x1F, 0x45, 0x14, 0xBC, 0xB7, 0x6B, 0x20, 0x47, 0x00, 0x3F, 0xF7,
];

const CAPSULE_HEADER_SIZE: usize = 28;

pub struct CapsuleUpdateDetector;

impl Default for CapsuleUpdateDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl CapsuleUpdateDetector {
    pub fn new() -> Self {
        Self
    }

    fn check_capsule_header(&self, data: &[u8], offset: usize) -> Vec<Finding> {
        let mut findings = Vec::new();

        if offset + CAPSULE_HEADER_SIZE > data.len() {
            return findings;
        }

        // EFI_CAPSULE_HEADER:
        // [0:16]  CapsuleGuid
        // [16:20] HeaderSize
        // [20:24] Flags
        // [24:28] CapsuleImageSize

        let header_size =
            u32::from_le_bytes(data[offset + 16..offset + 20].try_into().unwrap_or([0; 4]))
                as usize;
        let flags = u32::from_le_bytes(data[offset + 20..offset + 24].try_into().unwrap_or([0; 4]));
        let capsule_image_size =
            u32::from_le_bytes(data[offset + 24..offset + 28].try_into().unwrap_or([0; 4]))
                as usize;

        let remaining = data.len() - offset;

        // HeaderSize must be >= 28 and <= CapsuleImageSize
        if header_size < CAPSULE_HEADER_SIZE {
            findings.push(
                Finding::new(
                    "capsule_update",
                    Severity::High,
                    "Firmware Capsule: Header size too small",
                    &format!(
                        "Capsule at offset 0x{:08X} has HeaderSize={} (minimum is {}). \
                         Malformed capsule may exploit parser vulnerabilities in UpdateCapsule().",
                        offset, header_size, CAPSULE_HEADER_SIZE
                    ),
                )
                .with_confidence(0.85)
                .with_details(serde_json::json!({
                    "offset": format!("0x{:08X}", offset),
                    "header_size": header_size,
                    "flags": format!("0x{:08X}", flags),
                }))
                .with_recommendation("Reject malformed capsule and verify update source"),
            );
        }

        // CapsuleImageSize exceeds available data
        if capsule_image_size > remaining {
            findings.push(
                Finding::new(
                    "capsule_update",
                    Severity::Critical,
                    "Firmware Capsule: Image size exceeds available data (buffer overflow)",
                    &format!(
                        "Capsule at offset 0x{:08X} declares CapsuleImageSize=0x{:X} but only \
                         0x{:X} bytes available. Processing this capsule will read out of bounds.",
                        offset, capsule_image_size, remaining
                    ),
                )
                .with_confidence(0.90)
                .with_details(serde_json::json!({
                    "offset": format!("0x{:08X}", offset),
                    "capsule_image_size": capsule_image_size,
                    "available_bytes": remaining,
                }))
                .with_recommendation("Do not process this capsule — likely crafted exploit"),
            );
        }

        // HeaderSize > CapsuleImageSize (inconsistency)
        if header_size > capsule_image_size && capsule_image_size > 0 {
            findings.push(
                Finding::new(
                    "capsule_update",
                    Severity::High,
                    "Firmware Capsule: HeaderSize exceeds CapsuleImageSize",
                    &format!(
                        "Capsule at offset 0x{:08X} has HeaderSize=0x{:X} > CapsuleImageSize=0x{:X}. \
                         This inconsistency indicates a tampered or corrupted capsule.",
                        offset, header_size, capsule_image_size
                    ),
                )
                .with_confidence(0.88)
                .with_details(serde_json::json!({
                    "offset": format!("0x{:08X}", offset),
                    "header_size": header_size,
                    "capsule_image_size": capsule_image_size,
                })),
            );
        }

        // Check flags for CAPSULE_FLAGS_PERSIST_ACROSS_RESET without INITIATE_RESET
        let persist_flag = flags & 0x00010000 != 0;
        let initiate_flag = flags & 0x00040000 != 0;
        let populate_flag = flags & 0x00020000 != 0;

        if persist_flag && !populate_flag {
            findings.push(
                Finding::new(
                    "capsule_update",
                    Severity::Medium,
                    "Firmware Capsule: PERSIST_ACROSS_RESET without POPULATE_SYSTEM_TABLE",
                    &format!(
                        "Capsule at offset 0x{:08X} sets PERSIST but not POPULATE. This unusual \
                         flag combination may bypass capsule validation on next boot.",
                        offset
                    ),
                )
                .with_confidence(0.60)
                .with_details(serde_json::json!({
                    "offset": format!("0x{:08X}", offset),
                    "flags": format!("0x{:08X}", flags),
                    "persist": persist_flag,
                    "populate": populate_flag,
                    "initiate_reset": initiate_flag,
                })),
            );
        }

        // Check FMP payload if present
        if header_size <= capsule_image_size && offset + header_size + 20 < data.len() {
            let payload_offset = offset + header_size;
            // FMP capsule has its own header with item count
            if data.len() > payload_offset + 8 {
                let fmp_version = u32::from_le_bytes(
                    data[payload_offset..payload_offset + 4]
                        .try_into()
                        .unwrap_or([0; 4]),
                );
                let item_count = u16::from_le_bytes(
                    data[payload_offset + 4..payload_offset + 6]
                        .try_into()
                        .unwrap_or([0; 2]),
                );

                if item_count > 64 {
                    findings.push(
                        Finding::new(
                            "capsule_update",
                            Severity::High,
                            "Firmware Capsule: FMP payload with excessive item count",
                            &format!(
                                "FMP capsule payload at offset 0x{:08X} declares {} update items \
                                 (expected <10). May overflow internal tracking structures.",
                                payload_offset, item_count
                            ),
                        )
                        .with_confidence(0.75)
                        .with_details(serde_json::json!({
                            "payload_offset": format!("0x{:08X}", payload_offset),
                            "fmp_version": fmp_version,
                            "item_count": item_count,
                        })),
                    );
                }
            }
        }

        findings
    }
}

impl Detector for CapsuleUpdateDetector {
    fn name(&self) -> &str {
        "capsule_update"
    }

    fn detect(&self, target_path: &Path) -> Result<Vec<Finding>, DetectorError> {
        self.detect_context(&crate::ScanContext::load(target_path)?)
    }

    fn detect_context(&self, context: &crate::ScanContext) -> Result<Vec<Finding>, DetectorError> {
        let data = context.shared_bytes();
        let mut findings = Vec::new();

        // Scan for EFI Capsule headers
        for i in 0..data.len().saturating_sub(CAPSULE_HEADER_SIZE) {
            if data[i..i + 16] == EFI_CAPSULE_GUID || data[i..i + 16] == EFI_FMP_CAPSULE_GUID {
                findings.extend(self.check_capsule_header(&data, i));
            }
        }

        Ok(findings)
    }
}
