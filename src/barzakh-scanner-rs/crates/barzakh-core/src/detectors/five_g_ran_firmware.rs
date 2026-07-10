use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};

const GNB_MARKERS: &[&[u8]] = &[b"gNB-DU", b"O-RAN", b"nrCellId", b"F1AP"];
const ENB_MARKERS: &[&[u8]] = &[b"eNB-DU", b"S1AP", b"X2AP", b"LTE_RRC"];
const RAN_VENDOR_MARKERS: &[&[u8]] = &[
    b"NOKIA_AirScale",
    b"ERICSSON_RBS",
    b"SAMSUNG_RAN",
    b"HUAWEI_BBU",
];

const HOOK_PATTERNS: &[&[u8]] = &[
    &[0xE5, 0x9F, 0xF0, 0x00], // LDR PC, [PC, #0] — ARM branch hijack
    &[0x04, 0xF0, 0x1F, 0xE5], // LDR PC, [PC, #-4]
];

pub struct FiveGRanFirmwareDetector;

impl Default for FiveGRanFirmwareDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl FiveGRanFirmwareDetector {
    pub fn new() -> Self {
        Self
    }

    fn contains(data: &[u8], needle: &[u8]) -> bool {
        data.windows(needle.len()).any(|w| w == needle)
    }

    fn has_ran_marker(data: &[u8]) -> bool {
        GNB_MARKERS.iter().any(|m| Self::contains(data, m))
            || ENB_MARKERS.iter().any(|m| Self::contains(data, m))
            || RAN_VENDOR_MARKERS.iter().any(|m| Self::contains(data, m))
    }

    fn find_hook_patterns(data: &[u8]) -> Vec<(usize, &'static str)> {
        let mut hits = Vec::new();
        for pattern in HOOK_PATTERNS {
            let mut i = 0;
            while i + pattern.len() <= data.len() {
                if &data[i..i + pattern.len()] == *pattern {
                    hits.push((i, "ARM_PC_LOAD"));
                }
                i += 4; // ARM instruction alignment
            }
        }
        hits
    }

    fn check_unsigned_section(data: &[u8]) -> Option<(usize, usize)> {
        // Look for large blocks of 0xFF (erased flash) followed by non-0xFF code —
        // indicates code appended after a signed region boundary.
        let min_gap = 4096;
        let mut i = 0;
        while i + min_gap < data.len() {
            if data[i..i + min_gap].iter().all(|&b| b == 0xFF) {
                let gap_start = i;
                while i < data.len() && data[i] == 0xFF {
                    i += 1;
                }
                if i < data.len() && i - gap_start >= min_gap {
                    let code_after = data[i..].iter().take(64).filter(|&&b| b != 0x00).count();
                    if code_after > 16 {
                        return Some((i, data.len() - i));
                    }
                }
            } else {
                i += 1;
            }
        }
        None
    }

    fn scan(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        if !Self::has_ran_marker(data) {
            return findings;
        }

        let hooks = Self::find_hook_patterns(data);
        if hooks.len() > 4 {
            let first = hooks[0].0;
            findings.push(
                Finding::new(
                    "5g_ran_firmware",
                    Severity::Critical,
                    "Function hooking patterns in 5G RAN firmware",
                    &format!(
                        "5G gNB/eNB firmware contains {} ARM PC-load instructions consistent \
                         with function hooking. First occurrence at offset 0x{first:08X}. \
                         This pattern is used by RAN firmware implants to intercept radio \
                         resource control (RRC) and user-plane data.",
                        hooks.len(),
                    ),
                )
                .with_confidence(0.80)
                .with_details(serde_json::json!({
                    "hook_count": hooks.len(),
                    "first_offset": format!("0x{first:08X}"),
                }))
                .with_recommendation(
                    "Verify RAN firmware signature chain against vendor HSM; audit \
                     O-RAN fronthaul interface for unauthorized traffic mirroring; \
                     check gNB software version against operator-approved baseline.",
                ),
            );
        }

        if let Some((off, len)) = Self::check_unsigned_section(data) {
            findings.push(
                Finding::new(
                    "5g_ran_firmware",
                    Severity::High,
                    "Unsigned code section appended to RAN firmware",
                    &format!(
                        "5G RAN firmware image has {len} bytes of executable code at offset \
                         0x{off:08X} following an erased-flash gap. Code after the signed \
                         region boundary indicates a persistent backdoor appended to the \
                         baseband unit firmware.",
                    ),
                )
                .with_confidence(0.78)
                .with_details(serde_json::json!({
                    "offset": format!("0x{off:08X}"),
                    "appended_size": len,
                }))
                .with_recommendation(
                    "Re-image the RAN unit from vendor-signed firmware package; verify \
                     integrity of O-RAN software management interface; audit FCAPS for \
                     unauthorized configuration pushes.",
                ),
            );
        }

        findings
    }
}

impl Detector for FiveGRanFirmwareDetector {
    fn name(&self) -> &str {
        "5g_ran_firmware"
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
    fn fires_on_hooked_gnb_firmware() {
        let mut v = Vec::new();
        v.extend_from_slice(b"gNB-DU firmware O-RAN v2.0\n");
        for _ in 0..8 {
            v.extend_from_slice(&[0xE5, 0x9F, 0xF0, 0x00]);
            v.extend_from_slice(&[0x00; 60]);
        }
        let findings = FiveGRanFirmwareDetector::new().scan(&v);
        assert!(findings.iter().any(|f| f.severity == Severity::Critical));
    }

    #[test]
    fn quiet_without_ran_marker() {
        let mut v = vec![0u8; 256];
        for i in (0..256).step_by(64) {
            v[i..i + 4].copy_from_slice(&[0xE5, 0x9F, 0xF0, 0x00]);
        }
        assert!(FiveGRanFirmwareDetector::new().scan(&v).is_empty());
    }

    #[test]
    fn quiet_on_clean_ran() {
        let v = b"gNB-DU firmware O-RAN v2.0 clean build".to_vec();
        assert!(FiveGRanFirmwareDetector::new().scan(&v).is_empty());
    }
}
