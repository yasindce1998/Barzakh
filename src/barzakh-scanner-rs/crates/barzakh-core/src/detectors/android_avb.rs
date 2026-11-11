use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};

// Android Verified Boot (libavb) vbmeta image magic. All multi-byte header
// fields are big-endian.
const AVB_MAGIC: &[u8; 4] = b"AVB0";

// Offsets within AvbVBMetaImageHeader.
const OFF_ROLLBACK_INDEX: usize = 112; // u64
const OFF_FLAGS: usize = 120; // u32
const AVB_HEADER_MIN: usize = 124;

// AvbVBMetaImageFlags.
const FLAG_HASHTREE_DISABLED: u32 = 0x1; // dm-verity off
const FLAG_VERIFICATION_DISABLED: u32 = 0x2; // signature checks off

pub struct AndroidAvbDetector;

impl Default for AndroidAvbDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl AndroidAvbDetector {
    pub fn new() -> Self {
        Self
    }

    fn check_header(&self, data: &[u8], off: usize) -> Vec<Finding> {
        let mut findings = Vec::new();
        if off + AVB_HEADER_MIN > data.len() {
            return findings;
        }

        let flags = u32::from_be_bytes(
            data[off + OFF_FLAGS..off + OFF_FLAGS + 4]
                .try_into()
                .unwrap_or([0; 4]),
        );
        let rollback_index = u64::from_be_bytes(
            data[off + OFF_ROLLBACK_INDEX..off + OFF_ROLLBACK_INDEX + 8]
                .try_into()
                .unwrap_or([0; 8]),
        );

        if flags & (FLAG_HASHTREE_DISABLED | FLAG_VERIFICATION_DISABLED) != 0 {
            let mut which = Vec::new();
            if flags & FLAG_VERIFICATION_DISABLED != 0 {
                which.push("VERIFICATION_DISABLED");
            }
            if flags & FLAG_HASHTREE_DISABLED != 0 {
                which.push("HASHTREE_DISABLED");
            }
            findings.push(
                Finding::new(
                    "android_avb",
                    Severity::Critical,
                    "Android Verified Boot disabled in vbmeta",
                    &format!(
                        "vbmeta image at offset 0x{off:08X} sets flags 0x{flags:08X} ({}). With \
                         verification or the dm-verity hashtree disabled, the device boots \
                         unverified system/vendor partitions — a tampered or downgraded image \
                         will be accepted.",
                        which.join(" | "),
                    ),
                )
                .with_confidence(0.90)
                .with_details(serde_json::json!({
                    "offset": format!("0x{off:08X}"),
                    "flags": format!("0x{flags:08X}"),
                    "rollback_index": rollback_index,
                }))
                .with_recommendation(
                    "Re-flash a vbmeta with flags=0 and a current rollback index; never ship \
                     --disable-verity / --disable-verification outside a debug build.",
                ),
            );

            if rollback_index == 0 {
                findings.push(
                    Finding::new(
                        "android_avb",
                        Severity::Medium,
                        "Android Verified Boot rollback index reset to 0",
                        &format!(
                            "vbmeta at offset 0x{off:08X} declares rollback_index=0 alongside \
                             disabled verification flags, consistent with a downgrade to an older, \
                             vulnerable image whose anti-rollback protection has been stripped.",
                        ),
                    )
                    .with_confidence(0.55)
                    .with_details(serde_json::json!({
                        "offset": format!("0x{off:08X}"),
                        "rollback_index": 0,
                    })),
                );
            }
        }

        findings
    }

    fn scan(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();
        for (i, w) in data.windows(4).enumerate() {
            if w == AVB_MAGIC.as_slice() {
                findings.extend(self.check_header(data, i));
            }
        }
        findings
    }
}

impl Detector for AndroidAvbDetector {
    fn name(&self) -> &str {
        "android_avb"
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

    fn vbmeta(flags: u32, rollback: u64) -> Vec<u8> {
        let mut v = vec![0u8; 256];
        v[0..4].copy_from_slice(AVB_MAGIC);
        v[OFF_ROLLBACK_INDEX..OFF_ROLLBACK_INDEX + 8].copy_from_slice(&rollback.to_be_bytes());
        v[OFF_FLAGS..OFF_FLAGS + 4].copy_from_slice(&flags.to_be_bytes());
        v
    }

    #[test]
    fn fires_on_verification_disabled() {
        let data = vbmeta(FLAG_HASHTREE_DISABLED | FLAG_VERIFICATION_DISABLED, 0);
        let findings = AndroidAvbDetector::new().scan(&data);
        assert!(findings.iter().any(|f| f.severity == Severity::Critical));
    }

    #[test]
    fn quiet_on_valid_vbmeta() {
        let data = vbmeta(0, 5);
        assert!(AndroidAvbDetector::new().scan(&data).is_empty());
    }

    #[test]
    fn quiet_on_clean_buffer() {
        assert!(AndroidAvbDetector::new()
            .scan(&vec![0u8; 0x2000])
            .is_empty());
    }
}
