use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};

// Markers that identify a Windows boot configuration / boot manager image. BCD
// stores and UEFI boot files hold these as UTF-16LE strings.
const BOOT_MARKERS: &[&str] = &["Windows Boot Manager", "bootmgfw.efi", "winload"];

// BCD options that switch off boot-time code-integrity enforcement, allowing
// unsigned (bootkit) drivers to load.
const INTEGRITY_OFF: &[&str] = &["nointegritychecks", "testsigning", "disableintegritychecks"];

// Early Launch Anti-Malware references; absence on a Windows boot image is a
// (weaker) tamper signal.
const ELAM_MARKERS: &[&str] = &["ELAM", "WdBoot"];

pub struct WindowsBootchainDetector;

impl Default for WindowsBootchainDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl WindowsBootchainDetector {
    pub fn new() -> Self {
        Self
    }

    fn utf16le(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }

    fn contains_str(data: &[u8], s: &str) -> bool {
        let needle = Self::utf16le(s);
        data.windows(needle.len()).any(|w| w == needle.as_slice())
    }

    fn scan(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Gate: only analyse buffers that look like a Windows boot configuration.
        if !BOOT_MARKERS.iter().any(|m| Self::contains_str(data, m)) {
            return findings;
        }

        for opt in INTEGRITY_OFF {
            if Self::contains_str(data, opt) {
                findings.push(
                    Finding::new(
                        "windows_bootchain",
                        Severity::High,
                        "Windows boot configuration disables code integrity",
                        &format!(
                            "The Windows boot configuration enables '{opt}'. Disabling boot-time \
                             code-integrity (testsigning / nointegritychecks) lets unsigned or \
                             self-signed drivers load during boot — the persistence path used by \
                             bootkits to install a malicious kernel driver.",
                        ),
                    )
                    .with_confidence(0.85)
                    .with_details(serde_json::json!({ "bcd_option": opt }))
                    .with_recommendation(
                        "Remove the option via `bcdedit` (e.g. `/set nointegritychecks off`, \
                         `/set testsigning off`) and re-enable Secure Boot.",
                    ),
                );
            }
        }

        if !ELAM_MARKERS.iter().any(|m| Self::contains_str(data, m)) {
            findings.push(
                Finding::new(
                    "windows_bootchain",
                    Severity::Medium,
                    "Windows boot image lacks an ELAM reference",
                    "A Windows Boot Manager image was identified but contains no Early Launch \
                     Anti-Malware (ELAM / WdBoot) reference. A boot chain with ELAM stripped \
                     cannot vet boot-start drivers and is a common bootkit tampering artifact.",
                )
                .with_confidence(0.45)
                .with_recommendation(
                    "Verify the boot configuration still registers the ELAM driver and repair the \
                     Windows boot files (e.g. `bcdboot`) if it is missing.",
                ),
            );
        }

        findings
    }
}

impl Detector for WindowsBootchainDetector {
    fn name(&self) -> &str {
        "windows_bootchain"
    }

    fn detect(&self, target_path: &Path) -> Result<Vec<Finding>, DetectorError> {
        self.detect_context(&crate::ScanContext::load(target_path)?)
    }
    fn detect_context(&self, context: &crate::ScanContext) -> Result<Vec<Finding>, DetectorError> {
        let data = context.shared_bytes();
        Ok(self.scan(&data))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tampered_bcd() -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&WindowsBootchainDetector::utf16le("Windows Boot Manager"));
        v.extend_from_slice(&WindowsBootchainDetector::utf16le("nointegritychecks"));
        v.extend_from_slice(&WindowsBootchainDetector::utf16le("testsigning"));
        v
    }

    #[test]
    fn fires_on_integrity_disabled() {
        let findings = WindowsBootchainDetector::new().scan(&tampered_bcd());
        assert!(
            findings.iter().any(|f| f.severity == Severity::High),
            "nointegritychecks should raise a high finding"
        );
    }

    #[test]
    fn quiet_on_clean_buffer() {
        let data = vec![0u8; 0x4000];
        assert!(WindowsBootchainDetector::new().scan(&data).is_empty());
    }

    #[test]
    fn quiet_without_boot_marker() {
        // Integrity option present but no boot-manager marker → not a Windows boot image.
        let v = WindowsBootchainDetector::utf16le("testsigning");
        assert!(WindowsBootchainDetector::new().scan(&v).is_empty());
    }
}
