use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};

const GROUND_STATION_MARKERS: &[&[u8]] = &[
    b"CCSDS",
    b"ground_station",
    b"TT&C",
    b"telecommand",
    b"telemetry_proc",
];

const ANTENNA_CTRL_MARKERS: &[&[u8]] = &[
    b"ACU_",
    b"antenna_control",
    b"az_el_track",
    b"autotrack",
    b"monopulse",
];

const MODEM_CTRL_MARKERS: &[&[u8]] = &[b"Datum", b"Radyne", b"Advantech", b"Terrasat"];

pub struct SatelliteGroundStationDetector;

impl Default for SatelliteGroundStationDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl SatelliteGroundStationDetector {
    pub fn new() -> Self {
        Self
    }

    fn contains(data: &[u8], needle: &[u8]) -> bool {
        data.windows(needle.len()).any(|w| w == needle)
    }

    fn has_gs_marker(data: &[u8]) -> bool {
        GROUND_STATION_MARKERS
            .iter()
            .any(|m| Self::contains(data, m))
            || ANTENNA_CTRL_MARKERS.iter().any(|m| Self::contains(data, m))
            || MODEM_CTRL_MARKERS.iter().any(|m| Self::contains(data, m))
    }

    fn detect_unauthorized_telecommand(data: &[u8]) -> Vec<(usize, &'static str)> {
        let tc_indicators: &[(&[u8], &str)] = &[
            (b"inject_tc", "telecommand injection capability"),
            (b"override_cmd_auth", "command authentication bypass"),
            (b"replay_tc_frame", "telecommand frame replay"),
            (b"disable_crc", "CRC/authentication disable"),
        ];
        let mut hits = Vec::new();
        for (pat, desc) in tc_indicators {
            if let Some(pos) = data.windows(pat.len()).position(|w| w == *pat) {
                hits.push((pos, *desc));
            }
        }
        hits
    }

    fn detect_tracking_override(data: &[u8]) -> Option<usize> {
        let override_markers = [
            b"force_track_offset" as &[u8],
            b"az_override",
            b"el_override",
            b"disable_autotrack",
        ];
        for m in &override_markers {
            if let Some(pos) = data.windows(m.len()).position(|w| w == *m) {
                return Some(pos);
            }
        }
        None
    }

    fn scan(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        if !Self::has_gs_marker(data) {
            return findings;
        }

        let tc_hits = Self::detect_unauthorized_telecommand(data);
        if !tc_hits.is_empty() {
            let first = tc_hits[0].0;
            let descs: Vec<&str> = tc_hits.iter().map(|(_, d)| *d).collect();
            findings.push(
                Finding::new(
                    "satellite_ground_station",
                    Severity::Critical,
                    "Unauthorized telecommand capability in ground station firmware",
                    &format!(
                        "Ground station controller firmware contains {} telecommand \
                         manipulation indicators. First at offset 0x{first:08X}. \
                         Compromised ground station firmware can inject unauthorized \
                         commands to orbiting spacecraft or bypass command authentication.",
                        tc_hits.len(),
                    ),
                )
                .with_confidence(0.86)
                .with_details(serde_json::json!({
                    "indicators": descs,
                    "first_offset": format!("0x{first:08X}"),
                }))
                .with_recommendation(
                    "Isolate ground station from satellite command uplink; verify \
                     firmware against vendor-signed baseline; audit CCSDS telecommand \
                     logs for unauthorized frames; rotate spacecraft command \
                     encryption keys.",
                ),
            );
        }

        if let Some(off) = Self::detect_tracking_override(data) {
            findings.push(
                Finding::new(
                    "satellite_ground_station",
                    Severity::High,
                    "Antenna tracking override in ground station firmware",
                    &format!(
                        "Ground station firmware contains antenna tracking override \
                         commands at offset 0x{off:08X}. Unauthorized azimuth/elevation \
                         overrides can be used to disrupt satellite communications by \
                         deliberately de-pointing the antenna or to track unauthorized \
                         objects.",
                    ),
                )
                .with_confidence(0.77)
                .with_details(serde_json::json!({
                    "offset": format!("0x{off:08X}"),
                }))
                .with_recommendation(
                    "Verify antenna control unit firmware integrity; check for \
                     unauthorized tracking schedules; audit ACU access logs and \
                     network interfaces for remote command injection.",
                ),
            );
        }

        findings
    }
}

impl Detector for SatelliteGroundStationDetector {
    fn name(&self) -> &str {
        "satellite_ground_station"
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
    fn fires_on_tc_injection() {
        let mut v = b"CCSDS ground_station TT&C controller\n".to_vec();
        v.extend_from_slice(b"inject_tc=enabled\noverride_cmd_auth=1\n");
        let findings = SatelliteGroundStationDetector::new().scan(&v);
        assert!(findings.iter().any(|f| f.severity == Severity::Critical));
    }

    #[test]
    fn fires_on_tracking_override() {
        let mut v = b"ACU_ antenna_control firmware\n".to_vec();
        v.extend_from_slice(b"force_track_offset=5.0\n");
        let findings = SatelliteGroundStationDetector::new().scan(&v);
        assert!(findings.iter().any(|f| f.severity == Severity::High));
    }

    #[test]
    fn quiet_on_clean_gs() {
        let v = b"CCSDS ground_station controller v2.1 nominal".to_vec();
        assert!(SatelliteGroundStationDetector::new().scan(&v).is_empty());
    }
}
