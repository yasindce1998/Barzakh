use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};

// Gate: an iOS boot-args / AMFI context.
const GATE_TOKENS: &[&[u8]] = &[b"boot-args", b"amfi", b"AppleMobileFileIntegrity"];

// Boot-args / NVRAM tokens that switch off code-signing enforcement.
const BYPASS_TOKENS: &[&[u8]] = &[
    b"amfi_get_out_of_my_way=1",
    b"cs_enforcement_disable=1",
    b"amfi=0xff",
    b"-amfi_allow_any_signature",
];

pub struct IosAmfiDetector;

impl Default for IosAmfiDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl IosAmfiDetector {
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

        let hits: Vec<&str> = BYPASS_TOKENS
            .iter()
            .filter(|t| Self::contains(data, t))
            .map(|t| std::str::from_utf8(t).unwrap_or("?"))
            .collect();

        if !hits.is_empty() {
            findings.push(
                Finding::new(
                    "ios_amfi",
                    Severity::Critical,
                    "iOS code-signing enforcement disabled via boot-args",
                    &format!(
                        "AMFI / code-signing enforcement is disabled through boot-args ({}). With \
                         Apple Mobile File Integrity neutralized, the kernel will execute unsigned \
                         and ad-hoc-signed binaries — a jailbroken / fully compromised code-signing \
                         posture.",
                        hits.join(", "),
                    ),
                )
                .with_confidence(0.90)
                .with_details(serde_json::json!({ "boot_args": hits }))
                .with_recommendation(
                    "Clear the offending boot-args from NVRAM, restore a production boot policy, \
                     and re-enable Secure Boot / AMFI enforcement.",
                ),
            );
        }

        findings
    }
}

impl Detector for IosAmfiDetector {
    fn name(&self) -> &str {
        "ios_amfi"
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
    fn fires_on_amfi_bypass() {
        let v = b"boot-args=amfi_get_out_of_my_way=1 cs_enforcement_disable=1".to_vec();
        let findings = IosAmfiDetector::new().scan(&v);
        assert!(findings.iter().any(|f| f.severity == Severity::Critical));
    }

    #[test]
    fn quiet_without_gate() {
        let v = b"cs_enforcement_disable=1".to_vec();
        assert!(IosAmfiDetector::new().scan(&v).is_empty());
    }

    #[test]
    fn quiet_on_clean_buffer() {
        assert!(IosAmfiDetector::new().scan(&vec![0u8; 0x2000]).is_empty());
    }
}
