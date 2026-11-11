use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};

const IBOOT_MAGIC: &[u8] = b"iBoot";
const IMG4_MAGIC: [u8; 4] = [0x49, 0x4D, 0x34, 0x50]; // "IM4P"

pub struct IosIbootDetector;

impl Default for IosIbootDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl IosIbootDetector {
    pub fn new() -> Self {
        Self
    }

    fn check_iboot(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        for offset in 0..data.len().saturating_sub(64) {
            if data[offset..].starts_with(IBOOT_MAGIC) {
                self.validate_iboot_image(data, offset, &mut findings);
            }
            if offset + 4 <= data.len() && data[offset..offset + 4] == IMG4_MAGIC {
                self.validate_img4_wrapper(data, offset, &mut findings);
            }
        }

        findings
    }

    fn validate_iboot_image(&self, data: &[u8], offset: usize, findings: &mut Vec<Finding>) {
        if offset + 0x80 > data.len() {
            return;
        }

        // Check for version string following magic (e.g. "iBoot-10000.0.0.0.4")
        let version_region = &data[offset..offset.saturating_add(48).min(data.len())];
        let has_version = version_region.windows(6).any(|w| w.starts_with(b"iBoot-"));

        // Check signature region: iBoot images have RSA signature at end of header
        // Typical iBoot header is 0x40 bytes, followed by code, signature at end
        let sig_offset = offset + 0x40;
        if sig_offset + 0x100 <= data.len() {
            let sig_region = &data[sig_offset..sig_offset + 0x100];
            let sig_zeroed = sig_region.iter().all(|&b| b == 0x00);

            if sig_zeroed {
                findings.push(
                    Finding::new(
                        "ios_iboot",
                        Severity::Critical,
                        "iBoot image has zeroed signature region",
                        &format!(
                            "iBoot at 0x{:08X} has a zeroed signature region. \
                             This indicates a patched or unsigned iBoot — \
                             the Secure Boot chain is broken at the bootloader stage.",
                            offset
                        ),
                    )
                    .with_confidence(0.93)
                    .with_recommendation("Restore genuine iBoot image signed by Apple."),
                );
            }
        }

        // Check entrypoint integrity: first instruction bytes after header shouldn't be NOP sleds
        let code_start = offset + 0x40;
        if code_start + 16 <= data.len() {
            let code_region = &data[code_start..code_start + 16];
            // ARM64 NOP = 0xD503201F
            let nop_pattern: [u8; 4] = [0x1F, 0x20, 0x03, 0xD5];
            let nop_count = code_region
                .chunks(4)
                .filter(|chunk| chunk == &nop_pattern)
                .count();
            if nop_count >= 3 {
                findings.push(
                    Finding::new(
                        "ios_iboot",
                        Severity::High,
                        "iBoot entrypoint contains NOP sled",
                        &format!(
                            "iBoot at 0x{:08X} has {} consecutive NOPs at code entrypoint. \
                             This pattern indicates code patching or exploitation setup.",
                            offset, nop_count
                        ),
                    )
                    .with_confidence(0.80),
                );
            }
        }

        if !has_version {
            findings.push(
                Finding::new(
                    "ios_iboot",
                    Severity::Medium,
                    "iBoot image missing version string",
                    &format!(
                        "iBoot magic found at 0x{:08X} but no 'iBoot-' version string detected. \
                         May indicate stripped or custom iBoot build.",
                        offset
                    ),
                )
                .with_confidence(0.65),
            );
        }
    }

    fn validate_img4_wrapper(&self, data: &[u8], offset: usize, findings: &mut Vec<Finding>) {
        if offset + 0x20 > data.len() {
            return;
        }

        // IMG4 payload should have a component tag after the magic
        // Check if the IMG4 wraps an ibot (iBoot) payload
        let tag_region = &data[offset + 4..offset + 0x20];
        let is_iboot_img4 = tag_region
            .windows(4)
            .any(|w| w == b"ibot" || w == b"ibss" || w == b"ibec");

        if is_iboot_img4 {
            // Check for missing or zeroed SHSH blob (signature)
            let shsh_offset = offset + 0x100;
            if shsh_offset + 0x40 <= data.len() {
                let shsh = &data[shsh_offset..shsh_offset + 0x40];
                if shsh.iter().all(|&b| b == 0x00) {
                    findings.push(
                        Finding::new(
                            "ios_iboot",
                            Severity::Critical,
                            "IMG4-wrapped iBoot payload has zeroed SHSH signature",
                            &format!(
                                "IM4P container at 0x{:08X} wrapping iBoot has no valid SHSH blob. \
                                 The signature verification will fail or has been bypassed.",
                                offset
                            ),
                        )
                        .with_confidence(0.90),
                    );
                }
            }
        }
    }
}

impl Detector for IosIbootDetector {
    fn name(&self) -> &str {
        "ios_iboot"
    }

    fn detect(&self, target_path: &Path) -> Result<Vec<Finding>, DetectorError> {
        self.detect_context(&crate::ScanContext::load(target_path)?)
    }
    fn detect_context(&self, context: &crate::ScanContext) -> Result<Vec<Finding>, DetectorError> {
        let data = context.shared_bytes();
        Ok(self.check_iboot(&data))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn fires_on_unsigned_iboot() {
        let mut data = vec![0u8; 0x200];
        data[0..5].copy_from_slice(b"iBoot");
        // sig region at +0x40 is all zeros (already)

        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(&data).unwrap();

        let detector = IosIbootDetector::new();
        let findings = detector.detect(tmp.path()).unwrap();
        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.severity == Severity::Critical));
    }

    #[test]
    fn quiet_on_signed_iboot() {
        let mut data = vec![0u8; 0x200];
        data[0..5].copy_from_slice(b"iBoot");
        data[5..20].copy_from_slice(b"-10000.0.0.0.4\x00");
        // Non-zero signature
        data[0x40..0x140].fill(0xAA);

        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(&data).unwrap();

        let detector = IosIbootDetector::new();
        let findings = detector.detect(tmp.path()).unwrap();
        assert!(findings.is_empty());
    }
}
