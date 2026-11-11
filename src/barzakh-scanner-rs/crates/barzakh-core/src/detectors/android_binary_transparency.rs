use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};

const SIGNED_TREE_HEAD_MARKER: &[u8] = b"tree_size";
const MERKLE_LEAF_PREFIX: u8 = 0x00;
const MERKLE_NODE_PREFIX: u8 = 0x01;
const INCLUSION_PROOF_MARKER: &[u8] = b"leaf_index";
const CONSISTENCY_PROOF_MARKER: &[u8] = b"consistency";

pub struct AndroidBinaryTransparencyDetector;

impl Default for AndroidBinaryTransparencyDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl AndroidBinaryTransparencyDetector {
    pub fn new() -> Self {
        Self
    }

    fn check_forged_inclusion_proof(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        if let Some(pos) = data
            .windows(INCLUSION_PROOF_MARKER.len())
            .position(|w| w == INCLUSION_PROOF_MARKER)
        {
            let region_end = (pos + 512).min(data.len());
            let region = &data[pos..region_end];

            let hash_count = region
                .windows(33)
                .filter(|w| w[0] == MERKLE_NODE_PREFIX || w[0] == MERKLE_LEAF_PREFIX)
                .count();

            let has_repeated_hashes = region.windows(64).any(|w| w[..32] == w[32..64]);

            if hash_count >= 3 && has_repeated_hashes {
                findings.push(
                    Finding::new(
                        "android_binary_transparency",
                        Severity::Critical,
                        "Binary Transparency inclusion proof with repeated hash nodes",
                        &format!(
                            "Found inclusion proof structure at offset 0x{:08X} containing {} \
                             Merkle path nodes with repeated hash values. Legitimate inclusion \
                             proofs from the Pixel Binary Transparency log should have unique \
                             hashes at each level. Repeated hashes indicate a forged proof.",
                            pos, hash_count
                        ),
                    )
                    .with_confidence(0.90)
                    .with_details(serde_json::json!({
                        "offset": format!("0x{:08X}", pos),
                        "hash_node_count": hash_count,
                        "repeated_hashes_detected": true,
                        "technique": "Merkle inclusion proof forgery for Binary Transparency bypass",
                    }))
                    .with_recommendation(
                        "Verify inclusion proof against the public Binary Transparency log root hash",
                    ),
                );
            }
        }

        findings
    }

    fn check_signed_tree_head_manipulation(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        if let Some(pos) = data
            .windows(SIGNED_TREE_HEAD_MARKER.len())
            .position(|w| w == SIGNED_TREE_HEAD_MARKER)
        {
            let region_end = (pos + 256).min(data.len());
            let region = &data[pos..region_end];

            let has_zero_timestamp = region.windows(8).any(|w| w.iter().all(|&b| b == 0x00));
            let has_zero_root = region.len() >= 128 && region[64..96].iter().all(|&b| b == 0x00);

            if has_zero_timestamp || has_zero_root {
                findings.push(
                    Finding::new(
                        "android_binary_transparency",
                        Severity::High,
                        "SignedTreeHead with zeroed timestamp or root hash",
                        &format!(
                            "Found SignedTreeHead structure at offset 0x{:08X} with {}. \
                             A valid STH from the Pixel Binary Transparency log must have a \
                             non-zero timestamp and root hash. Zeroed values indicate fabrication.",
                            pos,
                            if has_zero_timestamp && has_zero_root {
                                "zeroed timestamp and root hash"
                            } else if has_zero_timestamp {
                                "zeroed timestamp"
                            } else {
                                "zeroed root hash"
                            }
                        ),
                    )
                    .with_confidence(0.88)
                    .with_details(serde_json::json!({
                        "offset": format!("0x{:08X}", pos),
                        "zeroed_timestamp": has_zero_timestamp,
                        "zeroed_root_hash": has_zero_root,
                        "technique": "SignedTreeHead fabrication for transparency log spoofing",
                    }))
                    .with_recommendation(
                        "Fetch current STH from transparency.pixel.google.com and compare",
                    ),
                );
            }
        }

        findings
    }

    fn check_consistency_proof_forgery(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        if let Some(pos) = data
            .windows(CONSISTENCY_PROOF_MARKER.len())
            .position(|w| w == CONSISTENCY_PROOF_MARKER)
        {
            let region_end = (pos + 256).min(data.len());
            let region = &data[pos..region_end];

            let empty_proof =
                region.len() >= 32 && region[16..48.min(region.len())].iter().all(|&b| b == 0x00);

            if empty_proof {
                findings.push(
                    Finding::new(
                        "android_binary_transparency",
                        Severity::High,
                        "Empty consistency proof in Binary Transparency verification data",
                        &format!(
                            "Found consistency proof marker at offset 0x{:08X} with empty/zeroed \
                             proof data. A valid consistency proof must contain hash nodes \
                             demonstrating the log grew append-only. Empty proofs allow an \
                             attacker to present a split view of the transparency log.",
                            pos
                        ),
                    )
                    .with_confidence(0.86)
                    .with_details(serde_json::json!({
                        "offset": format!("0x{:08X}", pos),
                        "empty_proof_data": true,
                        "technique": "Consistency proof omission for transparency log split-view attack",
                    }))
                    .with_recommendation(
                        "Require non-empty consistency proofs; cross-verify with multiple log witnesses",
                    ),
                );
            }
        }

        findings
    }
}

impl Detector for AndroidBinaryTransparencyDetector {
    fn name(&self) -> &str {
        "android_binary_transparency"
    }

    fn detect(&self, target_path: &Path) -> Result<Vec<Finding>, DetectorError> {
        self.detect_context(&crate::ScanContext::load(target_path)?)
    }

    fn detect_context(&self, context: &crate::ScanContext) -> Result<Vec<Finding>, DetectorError> {
        let data = context.shared_bytes();
        let mut findings = Vec::new();

        findings.extend(self.check_forged_inclusion_proof(&data));
        findings.extend(self.check_signed_tree_head_manipulation(&data));
        findings.extend(self.check_consistency_proof_forgery(&data));

        Ok(findings)
    }
}
