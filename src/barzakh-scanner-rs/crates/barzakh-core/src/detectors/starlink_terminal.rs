use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};

const LEO_TERMINAL_MARKERS: &[&[u8]] = &[
    b"SpaceX",
    b"Starlink",
    b"dishy",
    b"user_terminal",
    b"phased_array",
];

const LEO_CONSTELLATION_MARKERS: &[&[u8]] =
    &[b"OneWeb", b"Kuiper", b"Telesat", b"LEO_constellation"];

pub struct StarlinkTerminalDetector;

impl Default for StarlinkTerminalDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl StarlinkTerminalDetector {
    pub fn new() -> Self {
        Self
    }

    fn contains(data: &[u8], needle: &[u8]) -> bool {
        data.windows(needle.len()).any(|w| w == needle)
    }

    fn has_leo_marker(data: &[u8]) -> bool {
        LEO_TERMINAL_MARKERS.iter().any(|m| Self::contains(data, m))
            || LEO_CONSTELLATION_MARKERS
                .iter()
                .any(|m| Self::contains(data, m))
    }

    fn detect_bootloader_patch(data: &[u8]) -> Option<(usize, &'static str)> {
        let patch_indicators: &[(&[u8], &str)] = &[
            (b"skip_sig_verify", "signature verification bypass"),
            (b"boot_unsigned", "unsigned boot enabled"),
            (b"disable_antirollback", "anti-rollback disabled"),
            (b"uart_root_shell", "UART root shell backdoor"),
            (b"modchip_", "voltage glitch modchip interface"),
        ];
        for (pat, desc) in patch_indicators {
            if let Some(pos) = data.windows(pat.len()).position(|w| w == *pat) {
                return Some((pos, desc));
            }
        }
        None
    }

    fn detect_traffic_intercept(data: &[u8]) -> Vec<usize> {
        let intercept_markers = [
            b"mirror_downlink" as &[u8],
            b"capture_ku_band",
            b"intercept_beam",
            b"sniff_grpc",
        ];
        let mut hits = Vec::new();
        for m in &intercept_markers {
            if let Some(pos) = data.windows(m.len()).position(|w| w == *m) {
                hits.push(pos);
            }
        }
        hits
    }

    fn detect_phased_array_tamper(data: &[u8]) -> Option<usize> {
        let pa_markers = [
            b"beam_redirect" as &[u8],
            b"override_beam_angle",
            b"force_handover",
            b"jam_adjacent",
        ];
        for m in &pa_markers {
            if let Some(pos) = data.windows(m.len()).position(|w| w == *m) {
                return Some(pos);
            }
        }
        None
    }

    fn scan(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        if !Self::has_leo_marker(data) {
            return findings;
        }

        if let Some((off, desc)) = Self::detect_bootloader_patch(data) {
            findings.push(
                Finding::new(
                    "starlink_terminal",
                    Severity::Critical,
                    "Bootloader integrity bypass in LEO terminal firmware",
                    &format!(
                        "LEO satellite terminal firmware contains {desc} at offset \
                         0x{off:08X}. Bootloader patches that disable signature verification \
                         allow persistent code execution on the terminal — enabling traffic \
                         interception, network pivoting, or constellation protocol attacks.",
                    ),
                )
                .with_confidence(0.87)
                .with_details(serde_json::json!({
                    "offset": format!("0x{off:08X}"),
                    "bypass_type": desc,
                }))
                .with_recommendation(
                    "Re-flash terminal from factory firmware via recovery mode; verify \
                     eMMC boot partition integrity; check for physical modchip or \
                     voltage glitch hardware; report to constellation operator.",
                ),
            );
        }

        let intercept_hits = Self::detect_traffic_intercept(data);
        if !intercept_hits.is_empty() {
            let first = intercept_hits[0];
            findings.push(
                Finding::new(
                    "starlink_terminal",
                    Severity::High,
                    "Downlink traffic interception in LEO terminal firmware",
                    &format!(
                        "LEO terminal firmware contains {} traffic interception markers. \
                         First at offset 0x{first:08X}. Modified terminal firmware can \
                         mirror all Ku/Ka-band downlink traffic or intercept gRPC \
                         management protocol communications.",
                        intercept_hits.len(),
                    ),
                )
                .with_confidence(0.81)
                .with_details(serde_json::json!({
                    "indicator_count": intercept_hits.len(),
                    "first_offset": format!("0x{first:08X}"),
                }))
                .with_recommendation(
                    "Audit terminal's network interfaces for traffic mirroring; verify \
                     firmware version matches constellation operator's latest release; \
                     check for unauthorized Ethernet tap or WiFi AP.",
                ),
            );
        }

        if let Some(off) = Self::detect_phased_array_tamper(data) {
            findings.push(
                Finding::new(
                    "starlink_terminal",
                    Severity::High,
                    "Phased array beam manipulation in LEO terminal firmware",
                    &format!(
                        "LEO terminal firmware contains phased-array beam control \
                         manipulation at offset 0x{off:08X}. Unauthorized beam steering \
                         can be used to redirect communications, force satellite handovers, \
                         or jam adjacent terminals.",
                    ),
                )
                .with_confidence(0.75)
                .with_details(serde_json::json!({
                    "offset": format!("0x{off:08X}"),
                }))
                .with_recommendation(
                    "Verify phased-array controller firmware; check beam steering \
                     parameters against expected satellite ephemeris; report anomalous \
                     RF behavior to constellation operator.",
                ),
            );
        }

        findings
    }
}

impl Detector for StarlinkTerminalDetector {
    fn name(&self) -> &str {
        "starlink_terminal"
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
    fn fires_on_boot_bypass() {
        let mut v = b"SpaceX Starlink user_terminal firmware\n".to_vec();
        v.extend_from_slice(b"skip_sig_verify=1\n");
        let findings = StarlinkTerminalDetector::new().scan(&v);
        assert!(findings.iter().any(|f| f.severity == Severity::Critical));
    }

    #[test]
    fn fires_on_intercept() {
        let mut v = b"Starlink dishy phased_array v2\n".to_vec();
        v.extend_from_slice(b"mirror_downlink=all\n");
        let findings = StarlinkTerminalDetector::new().scan(&v);
        assert!(findings.iter().any(|f| f.severity == Severity::High));
    }

    #[test]
    fn quiet_on_clean_terminal() {
        let v = b"SpaceX Starlink user_terminal firmware v2024.1 clean".to_vec();
        assert!(StarlinkTerminalDetector::new().scan(&v).is_empty());
    }
}
