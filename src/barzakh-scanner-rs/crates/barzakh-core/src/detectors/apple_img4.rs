use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};

// Apple Image4 container / manifest magic tags (IA5String payloads in the DER).
const IMG4_MAGIC: &[u8] = b"IMG4";
const IM4M_MAGIC: &[u8] = b"IM4M"; // signed manifest

// Manifest boolean properties that gate trust on Apple Silicon:
//   CPRO = Certificate Production status, CSEC = Certificate Security mode.
// When both are *false* the image is a development/permissive build — the
// "Permissive Security" downgrade that disables full SEP-backed boot policy.
const PROP_CPRO: &[u8] = b"CPRO";
const PROP_CSEC: &[u8] = b"CSEC";
// snon = boot nonce; an all-zero nonce is the hallmark of a replayed/forged
// manifest used to downgrade the boot chain.
const PROP_SNON: &[u8] = b"snon";

// DER BOOLEAN encoding for `false` (tag 0x01, length 0x01, value 0x00).
const DER_BOOL_FALSE: [u8; 3] = [0x01, 0x01, 0x00];
const PROP_VALUE_WINDOW: usize = 16;
const SNON_NONCE_LEN: usize = 20;

pub struct AppleImg4Detector;

impl Default for AppleImg4Detector {
    fn default() -> Self {
        Self::new()
    }
}

impl AppleImg4Detector {
    pub fn new() -> Self {
        Self
    }

    fn contains(data: &[u8], needle: &[u8]) -> bool {
        data.windows(needle.len()).any(|w| w == needle)
    }

    /// True if a DER boolean-false appears shortly after the given property tag.
    fn prop_is_false(&self, data: &[u8], prop: &[u8]) -> Option<usize> {
        for (i, w) in data.windows(prop.len()).enumerate() {
            if w != prop {
                continue;
            }
            let start = i + prop.len();
            let end = (start + PROP_VALUE_WINDOW).min(data.len());
            if data[start..end]
                .windows(DER_BOOL_FALSE.len())
                .any(|x| x == DER_BOOL_FALSE)
            {
                return Some(i);
            }
        }
        None
    }

    fn snon_zeroed(&self, data: &[u8]) -> Option<usize> {
        for (i, w) in data.windows(PROP_SNON.len()).enumerate() {
            if w != PROP_SNON {
                continue;
            }
            let start = i + PROP_SNON.len();
            let end = (start + SNON_NONCE_LEN).min(data.len());
            if end - start >= 8 && data[start..end].iter().all(|&b| b == 0) {
                return Some(i);
            }
        }
        None
    }

    fn scan(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Gate: only analyse buffers that actually contain an Image4 manifest.
        if !Self::contains(data, IM4M_MAGIC) && !Self::contains(data, IMG4_MAGIC) {
            return findings;
        }

        for (prop, label) in [
            (PROP_CPRO, "production status (CPRO)"),
            (PROP_CSEC, "security mode (CSEC)"),
        ] {
            if let Some(off) = self.prop_is_false(data, prop) {
                let tag = std::str::from_utf8(prop).unwrap_or("????");
                findings.push(
                    Finding::new(
                        "apple_img4",
                        Severity::High,
                        "Apple Image4 manifest disables full boot security",
                        &format!(
                            "Image4 manifest property {tag} ({label}) at offset 0x{off:08X} is set \
                             to false. A manifest with production/security mode cleared corresponds \
                             to a Permissive Security / development boot policy, downgrading the \
                             SEP-enforced secure boot chain on Apple Silicon.",
                        ),
                    )
                    .with_confidence(0.80)
                    .with_details(serde_json::json!({
                        "offset": format!("0x{off:08X}"),
                        "property": tag,
                        "value": false,
                    }))
                    .with_recommendation(
                        "Restore a production-signed Image4 manifest and set the boot policy back \
                         to Full Security via the platform's recovery tooling.",
                    ),
                );
            }
        }

        if let Some(off) = self.snon_zeroed(data) {
            findings.push(
                Finding::new(
                    "apple_img4",
                    Severity::Medium,
                    "Apple Image4 manifest carries a zeroed boot nonce",
                    &format!(
                        "The Image4 boot nonce (snon) at offset 0x{off:08X} is all zeros. A null or \
                         fixed nonce defeats anti-replay protection and is characteristic of a \
                         forged or replayed manifest used to downgrade the boot chain.",
                    ),
                )
                .with_confidence(0.60)
                .with_details(serde_json::json!({
                    "offset": format!("0x{off:08X}"),
                    "nonce": "all-zero",
                })),
            );
        }

        findings
    }
}

impl Detector for AppleImg4Detector {
    fn name(&self) -> &str {
        "apple_img4"
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

    fn permissive_manifest() -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(IMG4_MAGIC);
        v.extend_from_slice(IM4M_MAGIC);
        v.extend_from_slice(PROP_CPRO);
        v.extend_from_slice(&DER_BOOL_FALSE);
        v.extend_from_slice(PROP_CSEC);
        v.extend_from_slice(&DER_BOOL_FALSE);
        v.extend_from_slice(PROP_SNON);
        v.extend_from_slice(&[0u8; SNON_NONCE_LEN]);
        v
    }

    #[test]
    fn fires_on_permissive_manifest() {
        let findings = AppleImg4Detector::new().scan(&permissive_manifest());
        assert!(
            findings.iter().any(|f| f.severity == Severity::High),
            "permissive CPRO/CSEC should raise a high finding"
        );
    }

    #[test]
    fn quiet_on_clean_buffer() {
        let data = vec![0u8; 0x4000];
        assert!(AppleImg4Detector::new().scan(&data).is_empty());
    }

    #[test]
    fn quiet_without_img4_magic() {
        // Property bytes present but no Image4 manifest → ignored.
        let mut v = Vec::new();
        v.extend_from_slice(PROP_CPRO);
        v.extend_from_slice(&DER_BOOL_FALSE);
        assert!(AppleImg4Detector::new().scan(&v).is_empty());
    }
}
