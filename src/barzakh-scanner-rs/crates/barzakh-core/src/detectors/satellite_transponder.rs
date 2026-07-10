use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};

const TRANSPONDER_MARKERS: &[&[u8]] = &[
    b"transponder",
    b"TWTA",
    b"SSPA",
    b"bent_pipe",
    b"frequency_plan",
];

const PAYLOAD_CTRL_MARKERS: &[&[u8]] = &[
    b"payload_controller",
    b"beam_switch",
    b"channelizer",
    b"digital_processor",
    b"HPA_",
];

const SPACE_PLATFORM_MARKERS: &[&[u8]] = &[b"Thales", b"Airbus_DS", b"Boeing_BSS", b"Lockheed"];

pub struct SatelliteTransponderDetector;

impl Default for SatelliteTransponderDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl SatelliteTransponderDetector {
    pub fn new() -> Self {
        Self
    }

    fn contains(data: &[u8], needle: &[u8]) -> bool {
        data.windows(needle.len()).any(|w| w == needle)
    }

    fn has_transponder_marker(data: &[u8]) -> bool {
        TRANSPONDER_MARKERS.iter().any(|m| Self::contains(data, m))
            || PAYLOAD_CTRL_MARKERS.iter().any(|m| Self::contains(data, m))
            || SPACE_PLATFORM_MARKERS
                .iter()
                .any(|m| Self::contains(data, m))
    }

    fn detect_unauthorized_reconfig(data: &[u8]) -> Vec<(usize, &'static str)> {
        let reconfig_markers: &[(&[u8], &str)] = &[
            (b"force_beam_repoint", "unauthorized beam repointing"),
            (b"modify_freq_plan", "frequency plan modification"),
            (b"disable_beacon", "beacon signal disable"),
            (b"override_eirp", "EIRP override (power manipulation)"),
        ];
        let mut hits = Vec::new();
        for (pat, desc) in reconfig_markers {
            if let Some(pos) = data.windows(pat.len()).position(|w| w == *pat) {
                hits.push((pos, *desc));
            }
        }
        hits
    }

    fn detect_signal_injection(data: &[u8]) -> Option<usize> {
        let inject_markers = [
            b"inject_carrier" as &[u8],
            b"spoof_beacon",
            b"jam_transponder",
            b"interference_gen",
        ];
        for m in &inject_markers {
            if let Some(pos) = data.windows(m.len()).position(|w| w == *m) {
                return Some(pos);
            }
        }
        None
    }

    fn scan(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        if !Self::has_transponder_marker(data) {
            return findings;
        }

        let reconfig_hits = Self::detect_unauthorized_reconfig(data);
        if !reconfig_hits.is_empty() {
            let first = reconfig_hits[0].0;
            let descs: Vec<&str> = reconfig_hits.iter().map(|(_, d)| *d).collect();
            findings.push(
                Finding::new(
                    "satellite_transponder",
                    Severity::Critical,
                    "Unauthorized reconfiguration commands in transponder firmware",
                    &format!(
                        "Satellite transponder/payload controller firmware contains {} \
                         unauthorized reconfiguration commands. First at offset 0x{first:08X}. \
                         Compromised transponder firmware can repoint beams, modify frequency \
                         plans, or manipulate EIRP levels — disrupting communications for \
                         entire coverage regions.",
                        reconfig_hits.len(),
                    ),
                )
                .with_confidence(0.85)
                .with_details(serde_json::json!({
                    "indicators": descs,
                    "first_offset": format!("0x{first:08X}"),
                }))
                .with_recommendation(
                    "Verify payload controller firmware against manufacturer baseline; \
                     audit telecommand history for unauthorized configuration changes; \
                     validate current frequency plan and beam coverage against nominal; \
                     engage satellite operator NOC.",
                ),
            );
        }

        if let Some(off) = Self::detect_signal_injection(data) {
            findings.push(
                Finding::new(
                    "satellite_transponder",
                    Severity::High,
                    "Signal injection capability in transponder firmware",
                    &format!(
                        "Transponder firmware contains signal injection/jamming markers at \
                         offset 0x{off:08X}. Modified transponder firmware with carrier \
                         injection or interference generation capability can disrupt or \
                         spoof signals for all users of the affected transponder.",
                    ),
                )
                .with_confidence(0.79)
                .with_details(serde_json::json!({
                    "offset": format!("0x{off:08X}"),
                }))
                .with_recommendation(
                    "Monitor transponder spectrum for unauthorized carriers; verify \
                     digital channelizer configuration; audit HPA power levels against \
                     expected values.",
                ),
            );
        }

        findings
    }
}

impl Detector for SatelliteTransponderDetector {
    fn name(&self) -> &str {
        "satellite_transponder"
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
    fn fires_on_unauthorized_reconfig() {
        let mut v = b"payload_controller transponder beam_switch\n".to_vec();
        v.extend_from_slice(b"force_beam_repoint=region_b\n");
        let findings = SatelliteTransponderDetector::new().scan(&v);
        assert!(findings.iter().any(|f| f.severity == Severity::Critical));
    }

    #[test]
    fn fires_on_signal_injection() {
        let mut v = b"Thales transponder TWTA controller\n".to_vec();
        v.extend_from_slice(b"inject_carrier=12.5GHz\n");
        let findings = SatelliteTransponderDetector::new().scan(&v);
        assert!(findings.iter().any(|f| f.severity == Severity::High));
    }

    #[test]
    fn quiet_on_clean_transponder() {
        let v = b"payload_controller transponder nominal config v1.0".to_vec();
        assert!(SatelliteTransponderDetector::new().scan(&v).is_empty());
    }
}
