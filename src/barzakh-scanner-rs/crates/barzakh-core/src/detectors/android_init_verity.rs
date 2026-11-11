use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};

const VERITY_MAGIC: [u8; 8] = [0x76, 0x65, 0x72, 0x69, 0x74, 0x79, 0x00, 0x00]; // "verity\0\0"
const DM_VERITY_MAGIC: u32 = 0xB001B001;

pub struct AndroidInitVerityDetector;

impl Default for AndroidInitVerityDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl AndroidInitVerityDetector {
    pub fn new() -> Self {
        Self
    }

    fn check_verity(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut found_verity = false;

        for offset in 0..data.len().saturating_sub(32) {
            // Check for verity superblock
            if data[offset..offset + 8] == VERITY_MAGIC {
                found_verity = true;
                self.validate_verity_superblock(data, offset, &mut findings);
            }

            // Check for dm-verity metadata
            if offset + 4 <= data.len() {
                let magic =
                    u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap_or([0; 4]));
                if magic == DM_VERITY_MAGIC {
                    found_verity = true;
                    self.validate_dm_verity(data, offset, &mut findings);
                }
            }
        }

        // Check for "androidboot.veritymode=disabled" or "androidboot.verifiedbootstate=orange"
        self.check_boot_params(data, &mut findings);

        if !found_verity && data.len() > 0x1000 {
            // Only flag if this looks like an Android image (has ANDROID! magic somewhere)
            if self.has_android_marker(data) {
                findings.push(
                    Finding::new(
                        "android_init_verity",
                        Severity::Medium,
                        "No dm-verity/fs-verity metadata found in Android image",
                        "Android boot image lacks verity metadata. System and vendor \
                         partitions may not have integrity protection.",
                    )
                    .with_confidence(0.60),
                );
            }
        }

        findings
    }

    fn validate_verity_superblock(&self, data: &[u8], offset: usize, findings: &mut Vec<Finding>) {
        if offset + 32 > data.len() {
            return;
        }

        // Check verity version at +8
        let version =
            u32::from_le_bytes(data[offset + 8..offset + 12].try_into().unwrap_or([0; 4]));

        if version == 0 {
            findings.push(
                Finding::new(
                    "android_init_verity",
                    Severity::High,
                    "Verity superblock has version 0 (disabled)",
                    &format!(
                        "Verity superblock at 0x{:08X} has version=0 indicating \
                         dm-verity is disabled for this partition.",
                        offset
                    ),
                )
                .with_confidence(0.85),
            );
        }
    }

    fn validate_dm_verity(&self, data: &[u8], offset: usize, findings: &mut Vec<Finding>) {
        if offset + 16 > data.len() {
            return;
        }

        // Flags at +4: bit 0 = disabled
        let flags = u32::from_le_bytes(data[offset + 4..offset + 8].try_into().unwrap_or([0; 4]));

        if flags & 0x01 != 0 {
            findings.push(
                Finding::new(
                    "android_init_verity",
                    Severity::Critical,
                    "dm-verity explicitly disabled via metadata flag",
                    &format!(
                        "dm-verity metadata at 0x{:08X} has disabled flag set. \
                         System partition integrity is not enforced.",
                        offset
                    ),
                )
                .with_confidence(0.92)
                .with_recommendation("Re-enable dm-verity and re-sign the vbmeta image."),
            );
        }
    }

    fn check_boot_params(&self, data: &[u8], findings: &mut Vec<Finding>) {
        let disabled_marker = b"veritymode=disabled";
        let orange_state = b"verifiedbootstate=orange";

        for offset in 0..data.len().saturating_sub(24) {
            if offset + disabled_marker.len() <= data.len()
                && &data[offset..offset + disabled_marker.len()] == disabled_marker.as_slice()
            {
                findings.push(
                    Finding::new(
                        "android_init_verity",
                        Severity::Critical,
                        "Boot parameter disables verity mode",
                        &format!(
                            "Found 'veritymode=disabled' at offset 0x{:08X}. \
                             dm-verity will be skipped during init.",
                            offset
                        ),
                    )
                    .with_confidence(0.95),
                );
                break;
            }

            if offset + orange_state.len() <= data.len()
                && &data[offset..offset + orange_state.len()] == orange_state.as_slice()
            {
                findings.push(
                    Finding::new(
                        "android_init_verity",
                        Severity::High,
                        "Verified boot state is 'orange' (unlocked bootloader)",
                        &format!(
                            "Found 'verifiedbootstate=orange' at offset 0x{:08X}. \
                             Device has unlocked bootloader — verified boot chain is advisory only.",
                            offset
                        ),
                    )
                    .with_confidence(0.90),
                );
                break;
            }
        }
    }

    fn has_android_marker(&self, data: &[u8]) -> bool {
        let android_magic = b"ANDROID!";
        data.windows(8).any(|w| w == android_magic)
    }
}

impl Detector for AndroidInitVerityDetector {
    fn name(&self) -> &str {
        "android_init_verity"
    }

    fn detect(&self, target_path: &Path) -> Result<Vec<Finding>, DetectorError> {
        self.detect_context(&crate::ScanContext::load(target_path)?)
    }

    fn detect_context(&self, context: &crate::ScanContext) -> Result<Vec<Finding>, DetectorError> {
        let data = context.shared_bytes();
        Ok(self.check_verity(&data))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn fires_on_disabled_verity() {
        let mut data = vec![0u8; 0x200];
        // dm-verity magic with disabled flag
        data[0..4].copy_from_slice(&DM_VERITY_MAGIC.to_le_bytes());
        data[4..8].copy_from_slice(&0x01u32.to_le_bytes()); // disabled flag

        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(&data).unwrap();

        let detector = AndroidInitVerityDetector::new();
        let findings = detector.detect(tmp.path()).unwrap();
        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.severity == Severity::Critical));
    }

    #[test]
    fn quiet_on_clean() {
        let data = vec![0u8; 0x200];
        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(&data).unwrap();

        let detector = AndroidInitVerityDetector::new();
        let findings = detector.detect(tmp.path()).unwrap();
        assert!(findings.is_empty());
    }
}
