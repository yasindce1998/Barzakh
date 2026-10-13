use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};

const PLATFORM_MARKERS: &[&[u8]] = &[b"BootROM", b"RISC-V", b"bootrom"];

const BOOTROM_EXPLOIT_MARKERS: &[&[u8]] = &[
    b"bootrom_pmp_disable",
    b"otp_key_extract",
    b"mrom_stage2_hijack",
];

pub struct RiscVBootRomDetector;

impl Default for RiscVBootRomDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl RiscVBootRomDetector {
    pub fn new() -> Self {
        Self
    }

    fn contains(data: &[u8], needle: &[u8]) -> bool {
        data.windows(needle.len()).any(|w| w == needle)
    }

    fn matched_markers(data: &[u8]) -> Vec<String> {
        BOOTROM_EXPLOIT_MARKERS
            .iter()
            .filter(|m| Self::contains(data, m))
            .map(|m| String::from_utf8_lossy(m).into_owned())
            .collect()
    }

    fn scan(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        if !PLATFORM_MARKERS.iter().any(|m| Self::contains(data, m)) {
            return findings;
        }

        let hits = Self::matched_markers(data);
        if !hits.is_empty() {
            findings.push(
                Finding::new(
                    "riscv_bootrom",
                    Severity::Critical,
                    "RISC-V Boot ROM exploit artifacts",
                    &format!(
                        "RISC-V boot ROM firmware contains {} exploit artifact(s): {}. \
                         These markers indicate disabling PMP protections during boot, \
                         extraction of OTP-fused keys, or hijacking of the mROM stage-2 \
                         loader — compromising the platform root of trust.",
                        hits.len(),
                        hits.join(", "),
                    ),
                )
                .with_confidence(0.88)
                .with_details(serde_json::json!({
                    "indicators": hits,
                }))
                .with_recommendation(
                    "Boot ROM is mask ROM and cannot be reflashed — treat the silicon as \
                     compromised if these artifacts are on production parts; for \
                     field-programmable boot ROMs, restore from the vendor-signed image \
                     and rotate any OTP-derived keys.",
                ),
            );
        }

        findings
    }
}

impl Detector for RiscVBootRomDetector {
    fn name(&self) -> &str {
        "riscv_bootrom"
    }

    fn detect(&self, target_path: &Path) -> Result<Vec<Finding>, DetectorError> {
        let data = std::fs::read(target_path).map_err(DetectorError::Io)?;
        Ok(self.scan(&data))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fires_on_bootrom_exploit() {
        let mut v = b"RISC-V BootROM mrom loader\n".to_vec();
        v.extend_from_slice(b"bootrom_pmp_disable=1\notp_key_extract=efuse\n");
        let findings = RiscVBootRomDetector::new().scan(&v);
        assert!(findings
            .iter()
            .any(|f| f.severity == Severity::Critical
                && f.title == "RISC-V Boot ROM exploit artifacts"));
    }

    #[test]
    fn quiet_on_clean_bootrom() {
        let v = b"RISC-V BootROM production stage-2 loader v1.2".to_vec();
        assert!(RiscVBootRomDetector::new().scan(&v).is_empty());
    }

    #[test]
    fn quiet_without_platform_marker() {
        let v = b"generic firmware with otp_key_extract marker only".to_vec();
        assert!(RiscVBootRomDetector::new().scan(&v).is_empty());
    }
}
