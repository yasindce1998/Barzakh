use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};

const GNSS_MARKERS: &[&[u8]] = &[
    b"u-blox",
    b"$GPGGA",
    b"$GNRMC",
    b"NMEA",
    b"Trimble",
    b"Septentrio",
];

const GNSS_CHIPSET_MARKERS: &[&[u8]] = &[
    b"UBX-CFG",
    b"Qualcomm_GNSS",
    b"Broadcom_BCM47",
    b"MediaTek_MT33",
];

pub struct GnssReceiverDetector;

impl Default for GnssReceiverDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl GnssReceiverDetector {
    pub fn new() -> Self {
        Self
    }

    fn contains(data: &[u8], needle: &[u8]) -> bool {
        data.windows(needle.len()).any(|w| w == needle)
    }

    fn has_gnss_marker(data: &[u8]) -> bool {
        GNSS_MARKERS.iter().any(|m| Self::contains(data, m))
            || GNSS_CHIPSET_MARKERS.iter().any(|m| Self::contains(data, m))
    }

    fn detect_spoofing_config(data: &[u8]) -> Vec<(usize, &'static str)> {
        let spoof_markers: &[(&[u8], &str)] = &[
            (b"spoof_location", "location spoofing configuration"),
            (b"inject_ephemeris", "ephemeris injection for GNSS spoofing"),
            (b"fake_sv", "simulated satellite vehicle generation"),
            (b"override_pnt", "PNT (position/navigation/time) override"),
            (b"replay_rf", "RF replay attack configuration"),
        ];
        let mut hits = Vec::new();
        for (pat, desc) in spoof_markers {
            if let Some(pos) = data.windows(pat.len()).position(|w| w == *pat) {
                hits.push((pos, *desc));
            }
        }
        hits
    }

    fn detect_firmware_patch(data: &[u8]) -> Option<(usize, usize)> {
        // Look for a large block of 0xFF (erased NOR flash) followed by code —
        // indicates firmware patched beyond the signed boundary.
        let min_gap = 2048;
        let mut i = 0;
        while i + min_gap < data.len() {
            if data[i..i + min_gap].iter().all(|&b| b == 0xFF) {
                let gap_end = i + data[i..].iter().take_while(|&&b| b == 0xFF).count();
                if gap_end < data.len() {
                    let remaining = &data[gap_end..];
                    let nonzero = remaining.iter().take(32).filter(|&&b| b != 0x00).count();
                    if nonzero > 8 {
                        return Some((gap_end, data.len() - gap_end));
                    }
                }
                i = gap_end;
            } else {
                i += 1;
            }
        }
        None
    }

    fn scan(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        if !Self::has_gnss_marker(data) {
            return findings;
        }

        let spoof_hits = Self::detect_spoofing_config(data);
        if !spoof_hits.is_empty() {
            let first = spoof_hits[0].0;
            let descs: Vec<&str> = spoof_hits.iter().map(|(_, d)| *d).collect();
            findings.push(
                Finding::new(
                    "gnss_receiver",
                    Severity::Critical,
                    "GNSS spoofing configuration in receiver firmware",
                    &format!(
                        "GNSS receiver firmware contains {} spoofing-related configurations. \
                         First at offset 0x{first:08X}. Modified GNSS firmware with spoofing \
                         capability can feed false position/time to all downstream systems \
                         (navigation, timing infrastructure, cellular synchronization).",
                        spoof_hits.len(),
                    ),
                )
                .with_confidence(0.88)
                .with_details(serde_json::json!({
                    "indicators": descs,
                    "first_offset": format!("0x{first:08X}"),
                }))
                .with_recommendation(
                    "Re-flash GNSS receiver with vendor-signed firmware; enable GNSS \
                     anti-spoofing features (multi-constellation cross-check, RAIM); \
                     verify PNT output against independent timing source.",
                ),
            );
        }

        if let Some((off, len)) = Self::detect_firmware_patch(data) {
            findings.push(
                Finding::new(
                    "gnss_receiver",
                    Severity::High,
                    "Unsigned firmware extension in GNSS receiver",
                    &format!(
                        "GNSS receiver firmware has {len} bytes of code appended after an \
                         erased-flash boundary at offset 0x{off:08X}. This pattern indicates \
                         post-manufacture firmware modification — potentially enabling \
                         location tracking exfiltration or timing manipulation.",
                    ),
                )
                .with_confidence(0.76)
                .with_details(serde_json::json!({
                    "offset": format!("0x{off:08X}"),
                    "appended_size": len,
                }))
                .with_recommendation(
                    "Verify receiver firmware version and hash against vendor manifest; \
                     check for unauthorized UBX configuration messages; audit serial/I2C \
                     interfaces for data exfiltration.",
                ),
            );
        }

        findings
    }
}

impl Detector for GnssReceiverDetector {
    fn name(&self) -> &str {
        "gnss_receiver"
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
    fn fires_on_spoofing_config() {
        let mut v = b"u-blox GNSS receiver UBX-CFG\n".to_vec();
        v.extend_from_slice(b"spoof_location=51.5074,-0.1278\n");
        let findings = GnssReceiverDetector::new().scan(&v);
        assert!(findings.iter().any(|f| f.severity == Severity::Critical));
    }

    #[test]
    fn quiet_without_gnss_marker() {
        let v = b"spoof_location=test override_pnt=1".to_vec();
        assert!(GnssReceiverDetector::new().scan(&v).is_empty());
    }

    #[test]
    fn quiet_on_clean_gnss() {
        let v = b"u-blox GNSS receiver firmware v3.0 production".to_vec();
        assert!(GnssReceiverDetector::new().scan(&v).is_empty());
    }
}
