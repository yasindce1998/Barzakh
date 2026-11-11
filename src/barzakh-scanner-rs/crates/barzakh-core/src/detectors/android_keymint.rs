use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};

// Tokens marking an Android key-attestation context (KeyMint / Keymaster).
const GATE_TOKENS: &[&[u8]] = &[b"keymint", b"keymaster", b"attestation"];

// A hardware-backed key should attest TRUSTED_ENVIRONMENT or STRONG_BOX. A
// SOFTWARE security level means the key never touched the TEE/StrongBox.
const SOFTWARE_LEVEL: &[&[u8]] = &[b"securityLevel: Software", b"security_level=software"];

// The attested verified-boot state should be Verified (green). Unverified means
// the boot chain integrity guarantee behind the key is gone.
const UNVERIFIED_STATE: &[&[u8]] = &[
    b"verifiedBootState: Unverified",
    b"verified_boot_state=unverified",
];

pub struct AndroidKeymintDetector;

impl Default for AndroidKeymintDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl AndroidKeymintDetector {
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

        if SOFTWARE_LEVEL.iter().any(|t| Self::contains(data, t)) {
            findings.push(
                Finding::new(
                    "android_keymint",
                    Severity::High,
                    "Key attestation downgraded to SOFTWARE security level",
                    "An Android key-attestation record reports a SOFTWARE security level. A key \
                     that should be hardware-backed (TrustedEnvironment / StrongBox) but attests \
                     SOFTWARE indicates a KeyMint downgrade or emulated TEE — the attested key is \
                     not protected by secure hardware and can be extracted.",
                )
                .with_confidence(0.85)
                .with_recommendation(
                    "Reject attestations whose securityLevel is not TrustedEnvironment/StrongBox; \
                     investigate the device for a tampered/emulated KeyMint TA.",
                ),
            );
        }

        if UNVERIFIED_STATE.iter().any(|t| Self::contains(data, t)) {
            findings.push(
                Finding::new(
                    "android_keymint",
                    Severity::High,
                    "Key attestation reports Unverified boot state",
                    "The attestation extension reports an Unverified verified-boot state. The \
                     hardware key is being issued on a device whose boot chain is no longer \
                     trusted, defeating the purpose of remote attestation / Play Integrity.",
                )
                .with_confidence(0.75),
            );
        }

        findings
    }
}

impl Detector for AndroidKeymintDetector {
    fn name(&self) -> &str {
        "android_keymint"
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
    fn fires_on_software_downgrade() {
        let v = b"keymint attestation\nsecurityLevel: Software\n".to_vec();
        let findings = AndroidKeymintDetector::new().scan(&v);
        assert!(findings.iter().any(|f| f.severity == Severity::High));
    }

    #[test]
    fn quiet_without_gate() {
        let v = b"securityLevel: Software".to_vec();
        assert!(AndroidKeymintDetector::new().scan(&v).is_empty());
    }

    #[test]
    fn quiet_on_clean_buffer() {
        assert!(AndroidKeymintDetector::new()
            .scan(&vec![0u8; 0x2000])
            .is_empty());
    }
}
