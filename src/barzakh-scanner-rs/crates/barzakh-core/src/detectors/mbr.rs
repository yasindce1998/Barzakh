use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};

const MBR_SIZE: usize = 512;
const MBR_SIGNATURE: [u8; 2] = [0x55, 0xAA];

const IVT_INT13H_OFFSET: usize = 0x13 * 4; // INT 13h vector in real-mode IVT
const IVT_INT15H_OFFSET: usize = 0x15 * 4; // INT 15h vector

const KNOWN_BOOTKITS: &[(&str, &[u8])] = &[
    ("TDL4/TDSS", b"\x58\xC3\xB8\x01\x02\xBB\x00\x7C"),
    ("Rovnix", b"\xFA\x33\xC0\x8E\xD0\xBC\x00\x7C\x8B\xF4"),
    ("Olmasco", b"\xE8\x00\x00\x5D\x83\xED\x06"),
    ("Gapz", b"\xEB\x5E\x00\x00\x00\x00\x00\x00"),
];

pub struct MbrDetector;

impl Default for MbrDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl MbrDetector {
    pub fn new() -> Self {
        Self
    }

    fn check_ivt_hooks(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        if data.len() < 0x200 {
            return findings;
        }

        // The IVT is only meaningful inside an actual boot sector: require
        // the 0x55AA boot signature before interpreting bytes at 0x4C/0x54
        // as interrupt vectors. Firmware volumes and embedded strings (FV
        // headers, GUIDs, iPXE scripts) merely resemble hooked vectors.
        if !(data[510] == 0x55 && data[511] == 0xAA) {
            return findings;
        }

        // Check INT 13h (disk services) - commonly hooked by bootkits
        if IVT_INT13H_OFFSET + 4 <= data.len() {
            let segment = u16::from_le_bytes(
                data[IVT_INT13H_OFFSET + 2..IVT_INT13H_OFFSET + 4]
                    .try_into()
                    .unwrap_or([0; 2]),
            );
            let offset = u16::from_le_bytes(
                data[IVT_INT13H_OFFSET..IVT_INT13H_OFFSET + 2]
                    .try_into()
                    .unwrap_or([0; 2]),
            );

            // INT 13h normally points to BIOS ROM (segment >= 0xC000)
            if segment != 0 && segment < 0xC000 {
                findings.push(
                    Finding::new(
                        "mbr",
                        Severity::Critical,
                        "INT 13h IVT hook detected",
                        &format!(
                            "INT 13h vector points to {:04X}:{:04X} which is outside \
                             BIOS ROM range. This is a strong indicator of a bootkit.",
                            segment, offset
                        ),
                    )
                    .with_confidence(0.90)
                    .with_details(serde_json::json!({
                        "interrupt": "13h",
                        "segment": format!("0x{:04X}", segment),
                        "offset": format!("0x{:04X}", offset),
                        "linear_address": format!("0x{:08X}", (segment as u32) * 16 + offset as u32),
                    }))
                    .with_recommendation("MBR bootkit detected. Restore MBR from clean backup."),
                );
            }
        }

        // Check INT 15h (memory map) - hooked to hide memory
        if IVT_INT15H_OFFSET + 4 <= data.len() {
            let segment = u16::from_le_bytes(
                data[IVT_INT15H_OFFSET + 2..IVT_INT15H_OFFSET + 4]
                    .try_into()
                    .unwrap_or([0; 2]),
            );
            let offset = u16::from_le_bytes(
                data[IVT_INT15H_OFFSET..IVT_INT15H_OFFSET + 2]
                    .try_into()
                    .unwrap_or([0; 2]),
            );

            if segment != 0 && segment < 0xC000 {
                findings.push(
                    Finding::new(
                        "mbr",
                        Severity::High,
                        "INT 15h IVT hook detected",
                        &format!(
                            "INT 15h vector points to {:04X}:{:04X} outside BIOS ROM. \
                             Used by bootkits to hide stolen memory.",
                            segment, offset
                        ),
                    )
                    .with_confidence(0.85)
                    .with_details(serde_json::json!({
                        "interrupt": "15h",
                        "segment": format!("0x{:04X}", segment),
                        "offset": format!("0x{:04X}", offset),
                    })),
                );
            }
        }

        findings
    }

    fn check_known_signatures(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        for (name, signature) in KNOWN_BOOTKITS {
            if let Some(pos) = data.windows(signature.len()).position(|w| w == *signature) {
                findings.push(
                    Finding::new(
                        "mbr",
                        Severity::Critical,
                        &format!("Known bootkit signature: {}", name),
                        &format!(
                            "Matched {} bootkit signature at MBR offset 0x{:04X}.",
                            name, pos
                        ),
                    )
                    .with_confidence(0.95)
                    .with_details(serde_json::json!({
                        "bootkit": name,
                        "offset": format!("0x{:04X}", pos),
                        "signature_length": signature.len(),
                    }))
                    .with_recommendation(
                        "Confirmed bootkit infection. Rebuild MBR and scan full disk.",
                    ),
                );
            }
        }

        findings
    }
}

impl Detector for MbrDetector {
    fn name(&self) -> &str {
        "mbr"
    }

    fn detect(&self, target_path: &Path) -> Result<Vec<Finding>, DetectorError> {
        self.detect_context(&crate::ScanContext::load(target_path)?)
    }
    fn detect_context(&self, context: &crate::ScanContext) -> Result<Vec<Finding>, DetectorError> {
        let data = context.shared_bytes();
        let mut findings = Vec::new();

        if data.len() < MBR_SIZE {
            return Ok(findings);
        }

        let mbr = &data[..MBR_SIZE];

        // Validate MBR signature
        if mbr[510..512] != MBR_SIGNATURE {
            findings.push(Finding::new(
                "mbr",
                Severity::Medium,
                "Invalid MBR signature",
                "MBR does not end with 0x55AA boot signature. May be corrupted or tampered.",
            ));
        }

        // Check for IVT hooks
        findings.extend(self.check_ivt_hooks(&data));

        // Scan for known bootkit signatures
        findings.extend(self.check_known_signatures(mbr));

        Ok(findings)
    }
}
