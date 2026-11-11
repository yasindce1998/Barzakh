use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};

// Tokens that mark a fastboot / bootloader-unlock context.
const GATE_TOKENS: &[&[u8]] = &[b"unlock_critical", b"get_unlock_ability"];

// Tokens indicating the bootloader is unlocked or unlockable.
const STATE_UNLOCKED: &[&[u8]] = &[b"verifiedbootstate=orange", b"DEVICE STATE - unlocked"];
const UNLOCK_ALLOWED: &[u8] = b"get_unlock_ability: 1";

pub struct AndroidFastbootDetector;

impl Default for AndroidFastbootDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl AndroidFastbootDetector {
    pub fn new() -> Self {
        Self
    }

    fn contains(data: &[u8], needle: &[u8]) -> bool {
        data.windows(needle.len()).any(|w| w == needle)
    }

    fn scan(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Gate: only analyse blobs that carry fastboot unlock plumbing.
        if !GATE_TOKENS.iter().any(|t| Self::contains(data, t)) {
            return findings;
        }

        let unlocked = STATE_UNLOCKED.iter().any(|t| Self::contains(data, t));
        let allowed = Self::contains(data, UNLOCK_ALLOWED);

        if unlocked {
            findings.push(
                Finding::new(
                    "android_fastboot",
                    Severity::High,
                    "Android bootloader is unlocked",
                    "The boot state reports an unlocked bootloader (verified boot 'orange' / \
                     DEVICE STATE - unlocked). An unlocked bootloader accepts unsigned boot, \
                     vbmeta and system images via fastboot flash, removing the root of trust.",
                )
                .with_confidence(0.85)
                .with_recommendation(
                    "Re-lock the bootloader (`fastboot flashing lock`) on production devices and \
                     verify the device returns to the green verified-boot state.",
                ),
            );
        }

        if allowed {
            findings.push(
                Finding::new(
                    "android_fastboot",
                    Severity::High,
                    "Android bootloader unlocking is enabled",
                    "`get_unlock_ability` reports 1, so OEM unlocking is permitted. Combined with \
                     physical or ADB access this allows flashing unsigned firmware and disabling \
                     Verified Boot.",
                )
                .with_confidence(0.75)
                .with_recommendation(
                    "Disable 'OEM unlocking' in Developer options / MDM policy for fielded devices.",
                ),
            );
        }

        findings
    }
}

impl Detector for AndroidFastbootDetector {
    fn name(&self) -> &str {
        "android_fastboot"
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

    #[test]
    fn fires_on_unlocked_state() {
        let mut v = Vec::new();
        v.extend_from_slice(b"get_unlock_ability: 1\n");
        v.extend_from_slice(b"androidboot.verifiedbootstate=orange\n");
        let findings = AndroidFastbootDetector::new().scan(&v);
        assert!(findings.iter().any(|f| f.severity == Severity::High));
    }

    #[test]
    fn quiet_without_gate() {
        // State token but no fastboot plumbing → ignored.
        let v = b"verifiedbootstate=orange".to_vec();
        assert!(AndroidFastbootDetector::new().scan(&v).is_empty());
    }

    #[test]
    fn quiet_on_clean_buffer() {
        assert!(AndroidFastbootDetector::new()
            .scan(&vec![0u8; 0x2000])
            .is_empty());
    }
}
