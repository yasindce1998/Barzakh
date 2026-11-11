use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};

// Markers identifying a WLAN controller firmware blob (Broadcom FullMAC and friends).
const WLAN_MARKERS: &[&[u8]] = &[b"brcmfmac", b"FWID:", b"wl0:", b"wlc_init"];

// An injected x86-style NOP sled is not natural in ARM WLAN microcode; a long
// run is a strong sign of a code stub appended past the signed image.
const NOP: u8 = 0x90;
const MIN_SLED_LEN: usize = 48;

pub struct WifiFirmwareDetector;

impl Default for WifiFirmwareDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl WifiFirmwareDetector {
    pub fn new() -> Self {
        Self
    }

    fn contains(data: &[u8], needle: &[u8]) -> bool {
        data.windows(needle.len()).any(|w| w == needle)
    }

    /// Offset and length of the longest run of `byte`, if any.
    fn longest_run(data: &[u8], byte: u8) -> Option<(usize, usize)> {
        let mut best_off = 0usize;
        let mut best_len = 0usize;
        let mut i = 0usize;
        while i < data.len() {
            if data[i] == byte {
                let start = i;
                while i < data.len() && data[i] == byte {
                    i += 1;
                }
                let len = i - start;
                if len > best_len {
                    best_len = len;
                    best_off = start;
                }
            } else {
                i += 1;
            }
        }
        if best_len > 0 {
            Some((best_off, best_len))
        } else {
            None
        }
    }

    fn scan(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        if !WLAN_MARKERS.iter().any(|m| Self::contains(data, m)) {
            return findings;
        }

        if let Some((off, len)) = Self::longest_run(data, NOP) {
            if len >= MIN_SLED_LEN {
                findings.push(
                    Finding::new(
                        "wifi_firmware",
                        Severity::High,
                        "Injected code stub in WLAN firmware",
                        &format!(
                            "WLAN controller firmware contains a {len}-byte NOP sled at offset \
                             0x{off:08X}. ARM WLAN microcode does not use 0x90 padding; a sled of \
                             this size indicates an injected code stub appended past the signed \
                             firmware image (radio-side persistent implant).",
                        ),
                    )
                    .with_confidence(0.80)
                    .with_details(serde_json::json!({
                        "offset": format!("0x{off:08X}"),
                        "sled_length": len,
                    }))
                    .with_recommendation(
                        "Re-flash the vendor-signed WLAN firmware and verify its signature; audit \
                         the driver's firmware-load path for unsigned blobs.",
                    ),
                );
            }
        }

        findings
    }
}

impl Detector for WifiFirmwareDetector {
    fn name(&self) -> &str {
        "wifi_firmware"
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
    fn fires_on_implanted_firmware() {
        let mut v = Vec::new();
        v.extend_from_slice(b"brcmfmac firmware FWID: 01-deadbeef\n");
        v.extend_from_slice(&[NOP; 64]);
        let findings = WifiFirmwareDetector::new().scan(&v);
        assert!(findings.iter().any(|f| f.severity == Severity::High));
    }

    #[test]
    fn quiet_without_marker() {
        // NOP sled but no WLAN firmware marker → ignored.
        let v = vec![NOP; 128];
        assert!(WifiFirmwareDetector::new().scan(&v).is_empty());
    }

    #[test]
    fn quiet_on_clean_firmware() {
        let v = b"brcmfmac firmware FWID: 01-clean".to_vec();
        assert!(WifiFirmwareDetector::new().scan(&v).is_empty());
    }
}
