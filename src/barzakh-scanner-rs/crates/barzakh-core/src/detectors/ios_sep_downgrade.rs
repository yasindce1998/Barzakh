use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};

// Gate: a Secure Enclave OS (SEPOS) image / personalization context.
const GATE_TOKENS: &[&[u8]] = &[b"AppleSEPOS", b"sepos", b"SEP firmware"];

// The personalization nonce tag; a zeroed nonce is replayable, enabling a SEP
// firmware downgrade to a previously-signed (vulnerable) version.
const SEP_NONCE_TAG: &[u8] = b"SEPNonce";
const SEP_NONCE_LEN: usize = 16;

pub struct IosSepDowngradeDetector;

impl Default for IosSepDowngradeDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl IosSepDowngradeDetector {
    pub fn new() -> Self {
        Self
    }

    fn contains(data: &[u8], needle: &[u8]) -> bool {
        data.windows(needle.len()).any(|w| w == needle)
    }

    fn scan(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        if !GATE_TOKENS.iter().any(|t| Self::contains(data, t)) {
            return findings;
        }

        for (i, w) in data.windows(SEP_NONCE_TAG.len()).enumerate() {
            if w != SEP_NONCE_TAG {
                continue;
            }
            let start = i + SEP_NONCE_TAG.len();
            let end = start + SEP_NONCE_LEN;
            if end <= data.len() && data[start..end].iter().all(|&b| b == 0) {
                findings.push(
                    Finding::new(
                        "ios_sep_downgrade",
                        Severity::High,
                        "Secure Enclave personalization nonce zeroed (SEP downgrade)",
                        &format!(
                            "The SEP personalization nonce (SEPNonce) at offset 0x{start:08X} is \
                             all zeros. A null/fixed SEP nonce makes the APTicket replayable, \
                             allowing a Secure Enclave firmware downgrade to an older signed sepos \
                             with known vulnerabilities (checkm8 / blackbird-class SEP attack).",
                        ),
                    )
                    .with_confidence(0.75)
                    .with_details(serde_json::json!({
                        "offset": format!("0x{start:08X}"),
                        "nonce": "all-zero",
                    }))
                    .with_recommendation(
                        "Require a fresh, server-supplied SEP nonce for every personalization; \
                         reject APTickets whose SEPNonce is zero or reused.",
                    ),
                );
            }
        }

        findings
    }
}

impl Detector for IosSepDowngradeDetector {
    fn name(&self) -> &str {
        "ios_sep_downgrade"
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

    fn sep_blob(zero_nonce: bool) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(b"AppleSEPOS sepos image\n");
        v.extend_from_slice(SEP_NONCE_TAG);
        if zero_nonce {
            v.extend_from_slice(&[0u8; SEP_NONCE_LEN]);
        } else {
            v.extend_from_slice(&[0x5A; SEP_NONCE_LEN]);
        }
        v
    }

    #[test]
    fn fires_on_zero_nonce() {
        let findings = IosSepDowngradeDetector::new().scan(&sep_blob(true));
        assert!(findings.iter().any(|f| f.severity == Severity::High));
    }

    #[test]
    fn quiet_on_fresh_nonce() {
        assert!(IosSepDowngradeDetector::new()
            .scan(&sep_blob(false))
            .is_empty());
    }

    #[test]
    fn quiet_on_clean_buffer() {
        assert!(IosSepDowngradeDetector::new()
            .scan(&vec![0u8; 0x2000])
            .is_empty());
    }
}
