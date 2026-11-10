use std::path::Path;

use aho_corasick::AhoCorasick;

use crate::detector::{Detector, DetectorError, Finding, Severity};

#[allow(dead_code)]
const ERASURE_PATTERNS: &[&[u8]] = &[
    // SetVariable with empty data (delete variable)
    b"\x48\x8D\x0D", // LEA RCX pattern before SetVariable call
    // Firmware write patterns
    b"\xB8\x00\x00\x00\x00\x48\x89", // MOV EAX, 0; MOV [reg]
    // SPI erase command sequences
    &[0x20], // SPI Sector Erase command
    &[0xD8], // SPI Block Erase command
    &[0xC7], // SPI Chip Erase command
    &[0x60], // SPI Chip Erase (alternate)
];

const ANTI_FORENSIC_STRINGS: &[&[u8]] = &[
    // Unambiguous capability markers only. Generic API and utility names
    // ("DeleteVariable", "CleanUp", "SpiErase", "EraseFlash") appear in
    // perfectly legitimate UEFI binaries and flash tooling.
    b"WipeTrace",
    b"SelfDestruct",
    b"RemoveEvidence",
];

pub struct SelfErasureDetector {
    string_matcher: AhoCorasick,
}

impl Default for SelfErasureDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl SelfErasureDetector {
    pub fn new() -> Self {
        let string_matcher = AhoCorasick::new(ANTI_FORENSIC_STRINGS).expect("valid patterns");
        Self { string_matcher }
    }
}

impl Detector for SelfErasureDetector {
    fn name(&self) -> &str {
        "self_erasure"
    }

    fn detect(&self, target_path: &Path) -> Result<Vec<Finding>, DetectorError> {
        let data = std::fs::read(target_path).map_err(DetectorError::Io)?;
        let mut findings = Vec::new();

        // Check for anti-forensic strings
        for mat in self.string_matcher.find_iter(&data) {
            let pattern_idx = mat.pattern().as_usize();
            let name = std::str::from_utf8(ANTI_FORENSIC_STRINGS[pattern_idx]).unwrap_or("unknown");

            findings.push(
                Finding::new(
                    "self_erasure",
                    Severity::High,
                    &format!("Anti-forensic capability: {}", name),
                    &format!(
                        "Found string '{}' at offset 0x{:08X} indicating \
                         self-erasure or anti-forensic capability.",
                        name,
                        mat.start()
                    ),
                )
                .with_confidence(0.70)
                .with_details(serde_json::json!({
                    "string": name,
                    "offset": format!("0x{:08X}", mat.start()),
                }))
                .with_recommendation(
                    "Firmware contains anti-forensic code. Preserve evidence before remediation.",
                ),
            );
        }

        // Check for SPI erase command byte sequences in executable context
        // Only flag if near executable code patterns
        let spi_erase_commands: &[u8] = &[0x20, 0xD8, 0xC7, 0x60];
        let out_byte: u8 = 0xE6; // x86 OUT instruction

        for (i, window) in data.windows(3).enumerate() {
            if window[0] == out_byte && spi_erase_commands.contains(&window[1]) {
                findings.push(
                    Finding::new(
                        "self_erasure",
                        Severity::Medium,
                        "SPI erase command in executable code",
                        &format!(
                            "OUT instruction at 0x{:08X} writes SPI erase command 0x{:02X}. \
                             May be used to erase flash regions.",
                            i, window[1]
                        ),
                    )
                    .with_confidence(0.50)
                    .with_details(serde_json::json!({
                        "offset": format!("0x{:08X}", i),
                        "command": format!("0x{:02X}", window[1]),
                    })),
                );
            }
        }

        Ok(findings)
    }
}
