use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};

const SATCOM_MARKERS: &[&[u8]] = &[
    b"Inmarsat",
    b"BGAN",
    b"FleetBroadband",
    b"IsatPhone",
    b"SwiftBroadband",
];

const MARITIME_MARKERS: &[&[u8]] = &[b"GMDSS", b"Iridium", b"Thuraya", b"VSAT_maritime"];
const AERO_MARKERS: &[&[u8]] = &[b"SwiftBroadband-Safety", b"Cobham", b"Honeywell_satcom"];

const TERMINAL_PLATFORM: &[&[u8]] = &[b"Sailor", b"Intellian", b"KVH", b"Thrane"];

pub struct InmarsatTerminalDetector;

impl Default for InmarsatTerminalDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl InmarsatTerminalDetector {
    pub fn new() -> Self {
        Self
    }

    fn contains(data: &[u8], needle: &[u8]) -> bool {
        data.windows(needle.len()).any(|w| w == needle)
    }

    fn has_satcom_marker(data: &[u8]) -> bool {
        SATCOM_MARKERS.iter().any(|m| Self::contains(data, m))
            || MARITIME_MARKERS.iter().any(|m| Self::contains(data, m))
            || AERO_MARKERS.iter().any(|m| Self::contains(data, m))
            || TERMINAL_PLATFORM.iter().any(|m| Self::contains(data, m))
    }

    fn detect_position_spoof(data: &[u8]) -> Vec<(usize, &'static str)> {
        let spoof_markers: &[(&[u8], &str)] = &[
            (b"override_gps_pos", "GPS position override"),
            (b"fake_mmsi", "MMSI spoofing (maritime identity)"),
            (b"spoof_ais", "AIS transponder spoofing"),
            (b"hide_vessel", "vessel tracking evasion"),
        ];
        let mut hits = Vec::new();
        for (pat, desc) in spoof_markers {
            if let Some(pos) = data.windows(pat.len()).position(|w| w == *pat) {
                hits.push((pos, *desc));
            }
        }
        hits
    }

    fn detect_comms_intercept(data: &[u8]) -> Option<usize> {
        let intercept_markers = [
            b"mirror_voice" as &[u8],
            b"capture_sms",
            b"intercept_data",
            b"clone_session",
            b"eavesdrop_",
        ];
        for m in &intercept_markers {
            if let Some(pos) = data.windows(m.len()).position(|w| w == *m) {
                return Some(pos);
            }
        }
        None
    }

    fn detect_distress_tamper(data: &[u8]) -> Option<usize> {
        let distress_markers = [
            b"suppress_distress" as &[u8],
            b"block_sos",
            b"disable_gmdss",
            b"fake_distress",
        ];
        for m in &distress_markers {
            if let Some(pos) = data.windows(m.len()).position(|w| w == *m) {
                return Some(pos);
            }
        }
        None
    }

    fn scan(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        if !Self::has_satcom_marker(data) {
            return findings;
        }

        let spoof_hits = Self::detect_position_spoof(data);
        if !spoof_hits.is_empty() {
            let first = spoof_hits[0].0;
            let descs: Vec<&str> = spoof_hits.iter().map(|(_, d)| *d).collect();
            findings.push(
                Finding::new(
                    "inmarsat_terminal",
                    Severity::Critical,
                    "Position/identity spoofing in maritime satcom firmware",
                    &format!(
                        "Maritime/aviation satcom terminal firmware contains {} position \
                         or identity spoofing capabilities. First at offset 0x{first:08X}. \
                         Spoofing vessel position or MMSI enables sanctions evasion, \
                         illegal fishing, or piracy concealment.",
                        spoof_hits.len(),
                    ),
                )
                .with_confidence(0.88)
                .with_details(serde_json::json!({
                    "indicators": descs,
                    "first_offset": format!("0x{first:08X}"),
                }))
                .with_recommendation(
                    "Cross-reference vessel position with independent radar/AIS data; \
                     verify terminal firmware against type-approved version; report to \
                     flag state and IMO if maritime vessel; check for GPS spoofing \
                     hardware.",
                ),
            );
        }

        if let Some(pos) = Self::detect_comms_intercept(data) {
            findings.push(
                Finding::new(
                    "inmarsat_terminal",
                    Severity::High,
                    "Communications interception in satcom terminal firmware",
                    &format!(
                        "Satcom terminal firmware contains voice/data interception \
                         capability at offset 0x{pos:08X}. Modified terminal firmware \
                         can silently mirror all satellite communications including \
                         voice calls, SMS, and data sessions.",
                    ),
                )
                .with_confidence(0.81)
                .with_details(serde_json::json!({
                    "offset": format!("0x{pos:08X}"),
                }))
                .with_recommendation(
                    "Re-flash terminal from manufacturer-signed firmware; audit \
                     terminal's local interfaces for unauthorized data exfiltration; \
                     verify SIM/USIM credentials.",
                ),
            );
        }

        if let Some(pos) = Self::detect_distress_tamper(data) {
            findings.push(
                Finding::new(
                    "inmarsat_terminal",
                    Severity::Critical,
                    "Safety/distress signal suppression in satcom firmware",
                    &format!(
                        "Satcom terminal firmware contains distress signal suppression \
                         at offset 0x{pos:08X}. Blocking GMDSS distress signals is \
                         life-threatening — preventing crew from calling for emergency \
                         assistance at sea or in the air.",
                    ),
                )
                .with_confidence(0.92)
                .with_details(serde_json::json!({
                    "offset": format!("0x{pos:08X}"),
                }))
                .with_recommendation(
                    "IMMEDIATE: Verify distress alerting capability via test call; \
                     replace terminal firmware; report to maritime/aviation safety \
                     authority; check for physical tampering.",
                ),
            );
        }

        findings
    }
}

impl Detector for InmarsatTerminalDetector {
    fn name(&self) -> &str {
        "inmarsat_terminal"
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
    fn fires_on_position_spoof() {
        let mut v = b"Inmarsat FleetBroadband Sailor terminal\n".to_vec();
        v.extend_from_slice(b"override_gps_pos=0.0,0.0\nfake_mmsi=123456789\n");
        let findings = InmarsatTerminalDetector::new().scan(&v);
        assert!(findings.iter().any(|f| f.severity == Severity::Critical));
    }

    #[test]
    fn fires_on_distress_suppression() {
        let mut v = b"GMDSS Inmarsat safety terminal\n".to_vec();
        v.extend_from_slice(b"suppress_distress=true\n");
        let findings = InmarsatTerminalDetector::new().scan(&v);
        assert!(findings
            .iter()
            .any(|f| f.severity == Severity::Critical && f.title.contains("distress")));
    }

    #[test]
    fn quiet_on_clean_terminal() {
        let v = b"Inmarsat FleetBroadband terminal v8.0 production".to_vec();
        assert!(InmarsatTerminalDetector::new().scan(&v).is_empty());
    }
}
