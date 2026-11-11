use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};

// Gate: a context that references the KTRR / AMCC kernel-text lockdown.
const GATE_TOKENS: &[&[u8]] = &[b"KTRR", b"AMCC", b"CTRR", b"RoRgn"];

// Tokens indicating the lockdown register was never engaged.
const UNLOCKED_TOKENS: &[&[u8]] = &[
    b"CTRR_LOCK=0",
    b"KTRR_LOCK=0",
    b"rorgn_lock=0",
    b"ctrr_lock: 0",
];

pub struct IosKtrrDetector;

impl Default for IosKtrrDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl IosKtrrDetector {
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

        if UNLOCKED_TOKENS.iter().any(|t| Self::contains(data, t)) {
            findings.push(
                Finding::new(
                    "ios_ktrr",
                    Severity::Critical,
                    "KTRR/CTRR kernel-text lockdown not engaged",
                    "The KTRR / CTRR (AMCC) lockdown that makes the kernel text read-only is not \
                     locked (lock register = 0). Without KTRR engaged, the Read-only Region is \
                     writable, defeating Kernel Patch Protection and allowing persistent kernel \
                     text patches (the precondition for an Apple-Silicon kernel implant).",
                )
                .with_confidence(0.85)
                .with_recommendation(
                    "Ensure iBoot/the kernel locks CTRR (RoRgnLock) before first kernel exec; a \
                     device that boots with KTRR unlocked is exploited or running a patched iBoot.",
                ),
            );
        }

        findings
    }
}

impl Detector for IosKtrrDetector {
    fn name(&self) -> &str {
        "ios_ktrr"
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
    fn fires_on_unlocked_ktrr() {
        let v = b"AMCC KTRR region\nCTRR_LOCK=0\n".to_vec();
        let findings = IosKtrrDetector::new().scan(&v);
        assert!(findings.iter().any(|f| f.severity == Severity::Critical));
    }

    #[test]
    fn quiet_when_locked() {
        // KTRR context present but the lock is engaged → no finding.
        let v = b"AMCC KTRR region\nCTRR_LOCK=1\n".to_vec();
        assert!(IosKtrrDetector::new().scan(&v).is_empty());
    }

    #[test]
    fn quiet_on_clean_buffer() {
        assert!(IosKtrrDetector::new().scan(&vec![0u8; 0x2000]).is_empty());
    }
}
