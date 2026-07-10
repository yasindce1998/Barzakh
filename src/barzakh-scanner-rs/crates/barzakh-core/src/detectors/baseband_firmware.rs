use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};

const QUALCOMM_MARKERS: &[&[u8]] = &[b"QCOM_", b"QC_IMAGE_VERSION", b"amss_", b"MBA_"];
const MEDIATEK_MARKERS: &[&[u8]] = &[b"MTK_BROM", b"md1rom", b"MDDB_INFO", b"CCCI_"];
const SHANNON_MARKERS: &[&[u8]] = &[b"SHANNON", b"TOC\x00", b"SEC_BOOT", b"CP_"];
const UNISOC_MARKERS: &[&[u8]] = &[b"UNISOC", b"modem_", b"SPRD_"];

const NOP_ARM: &[u8] = &[0x00, 0xF0, 0x20, 0xE3]; // ARM NOP
const NOP_THUMB: &[u8] = &[0x00, 0xBF]; // Thumb NOP (mov r8, r8)
const MIN_SLED_LEN: usize = 32;

pub struct BasebandFirmwareDetector;

impl Default for BasebandFirmwareDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl BasebandFirmwareDetector {
    pub fn new() -> Self {
        Self
    }

    fn contains(data: &[u8], needle: &[u8]) -> bool {
        data.windows(needle.len()).any(|w| w == needle)
    }

    fn has_baseband_marker(data: &[u8]) -> bool {
        QUALCOMM_MARKERS.iter().any(|m| Self::contains(data, m))
            || MEDIATEK_MARKERS.iter().any(|m| Self::contains(data, m))
            || SHANNON_MARKERS.iter().any(|m| Self::contains(data, m))
            || UNISOC_MARKERS.iter().any(|m| Self::contains(data, m))
    }

    fn count_nop_runs(data: &[u8], pattern: &[u8]) -> Vec<(usize, usize)> {
        let mut runs = Vec::new();
        let mut i = 0;
        while i + pattern.len() <= data.len() {
            if &data[i..i + pattern.len()] == pattern {
                let start = i;
                while i + pattern.len() <= data.len() && &data[i..i + pattern.len()] == pattern {
                    i += pattern.len();
                }
                let count = (i - start) / pattern.len();
                if count >= MIN_SLED_LEN / pattern.len() {
                    runs.push((start, count * pattern.len()));
                }
            } else {
                i += 1;
            }
        }
        runs
    }

    fn check_suspicious_strings(data: &[u8]) -> Option<usize> {
        let suspicious: &[&[u8]] = &[b"implant", b"/dev/kmem", b"rootkit", b"inject_"];
        for s in suspicious {
            if let Some(pos) = data.windows(s.len()).position(|w| w == *s) {
                return Some(pos);
            }
        }
        None
    }

    fn scan(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        if !Self::has_baseband_marker(data) {
            return findings;
        }

        // Check for ARM NOP sleds (code injection indicator)
        let arm_runs = Self::count_nop_runs(data, NOP_ARM);
        let thumb_runs = Self::count_nop_runs(data, NOP_THUMB);

        for (off, len) in arm_runs.iter().chain(thumb_runs.iter()) {
            findings.push(
                Finding::new(
                    "baseband_firmware",
                    Severity::Critical,
                    "Code injection sled in cellular baseband firmware",
                    &format!(
                        "Baseband firmware image contains a {len}-byte NOP sled at offset \
                         0x{off:08X}. Cellular baseband firmware (Qualcomm/MediaTek/Shannon) \
                         does not use NOP padding of this size; indicates an implant injected \
                         into the modem processor firmware for persistent radio-layer access.",
                    ),
                )
                .with_confidence(0.85)
                .with_details(serde_json::json!({
                    "offset": format!("0x{off:08X}"),
                    "sled_length": len,
                    "type": if *off == arm_runs.first().map_or(0, |r| r.0) { "ARM" } else { "Thumb" },
                }))
                .with_recommendation(
                    "Re-flash vendor-signed baseband firmware via OEM tools; verify \
                     modem firmware hash against carrier-approved build; check for \
                     unauthorized AT command interfaces.",
                ),
            );
        }

        if let Some(pos) = Self::check_suspicious_strings(data) {
            findings.push(
                Finding::new(
                    "baseband_firmware",
                    Severity::High,
                    "Suspicious strings in baseband firmware blob",
                    &format!(
                        "Baseband firmware contains implant-associated strings at offset \
                         0x{pos:08X}. Legitimate modem firmware should not reference \
                         kernel memory devices or injection primitives.",
                    ),
                )
                .with_confidence(0.75)
                .with_details(serde_json::json!({
                    "offset": format!("0x{pos:08X}"),
                }))
                .with_recommendation(
                    "Dump full baseband firmware and compare against known-good image \
                     from vendor; investigate any AT command exfiltration channels.",
                ),
            );
        }

        findings
    }
}

impl Detector for BasebandFirmwareDetector {
    fn name(&self) -> &str {
        "baseband_firmware"
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
    fn fires_on_implanted_baseband() {
        let mut v = Vec::new();
        v.extend_from_slice(b"QCOM_AMSS QC_IMAGE_VERSION=1.0\n");
        v.extend_from_slice(&NOP_ARM.repeat(16));
        let findings = BasebandFirmwareDetector::new().scan(&v);
        assert!(findings.iter().any(|f| f.severity == Severity::Critical));
    }

    #[test]
    fn quiet_without_marker() {
        let v = NOP_ARM.repeat(64);
        assert!(BasebandFirmwareDetector::new().scan(&v).is_empty());
    }

    #[test]
    fn quiet_on_clean_baseband() {
        let v = b"QCOM_AMSS clean firmware image v3.1".to_vec();
        assert!(BasebandFirmwareDetector::new().scan(&v).is_empty());
    }
}
