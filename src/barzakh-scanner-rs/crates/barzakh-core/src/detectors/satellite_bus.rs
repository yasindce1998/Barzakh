use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};

const BUS_MARKERS: &[&[u8]] = &[
    b"satellite_bus",
    b"AOCS",
    b"ADCS",
    b"OBC_",
    b"flight_computer",
];

const SUBSYSTEM_MARKERS: &[&[u8]] = &[
    b"power_subsystem",
    b"thermal_ctrl",
    b"propulsion_ctrl",
    b"reaction_wheel",
    b"star_tracker",
];

const SPACE_RTOS_MARKERS: &[&[u8]] = &[b"RTEMS", b"VxWorks", b"RTOS_SAT", b"cFS", b"FreeRTOS"];
const RAD_HARD_MARKERS: &[&[u8]] = &[b"RAD750", b"GR740", b"LEON3", b"Vorago"];

pub struct SatelliteBusDetector;

impl Default for SatelliteBusDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl SatelliteBusDetector {
    pub fn new() -> Self {
        Self
    }

    fn contains(data: &[u8], needle: &[u8]) -> bool {
        data.windows(needle.len()).any(|w| w == needle)
    }

    fn has_bus_marker(data: &[u8]) -> bool {
        BUS_MARKERS.iter().any(|m| Self::contains(data, m))
            || SUBSYSTEM_MARKERS.iter().any(|m| Self::contains(data, m))
            || SPACE_RTOS_MARKERS.iter().any(|m| Self::contains(data, m))
            || RAD_HARD_MARKERS.iter().any(|m| Self::contains(data, m))
    }

    fn detect_aocs_manipulation(data: &[u8]) -> Vec<(usize, &'static str)> {
        let aocs_attacks: &[(&[u8], &str)] = &[
            (b"override_attitude", "attitude override command"),
            (b"disable_safemode", "safe mode disable"),
            (b"force_deorbit", "forced deorbit command"),
            (b"spin_up_rw", "reaction wheel spin-up attack"),
            (b"disable_sun_sensor", "sun sensor disable"),
        ];
        let mut hits = Vec::new();
        for (pat, desc) in aocs_attacks {
            if let Some(pos) = data.windows(pat.len()).position(|w| w == *pat) {
                hits.push((pos, *desc));
            }
        }
        hits
    }

    fn detect_power_attack(data: &[u8]) -> Option<(usize, &'static str)> {
        let power_attacks: &[(&[u8], &str)] = &[
            (b"drain_battery", "battery drain attack"),
            (b"disable_solar_array", "solar array disable"),
            (b"overcharge_cell", "battery overcharge"),
            (b"power_bus_short", "power bus short circuit"),
        ];
        for (pat, desc) in power_attacks {
            if let Some(pos) = data.windows(pat.len()).position(|w| w == *pat) {
                return Some((pos, desc));
            }
        }
        None
    }

    fn scan(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        if !Self::has_bus_marker(data) {
            return findings;
        }

        let aocs_hits = Self::detect_aocs_manipulation(data);
        if !aocs_hits.is_empty() {
            let first = aocs_hits[0].0;
            let descs: Vec<&str> = aocs_hits.iter().map(|(_, d)| *d).collect();
            findings.push(
                Finding::new(
                    "satellite_bus",
                    Severity::Critical,
                    "AOCS/attitude manipulation in satellite bus firmware",
                    &format!(
                        "Satellite bus/flight computer firmware contains {} attitude \
                         control manipulation commands. First at offset 0x{first:08X}. \
                         Unauthorized AOCS commands can cause loss of spacecraft \
                         (tumbling, deorbit), disabling an entire orbital asset.",
                        aocs_hits.len(),
                    ),
                )
                .with_confidence(0.89)
                .with_details(serde_json::json!({
                    "indicators": descs,
                    "first_offset": format!("0x{first:08X}"),
                }))
                .with_recommendation(
                    "Verify OBC firmware against manufacturer baseline via secure \
                     telemetry channel; engage spacecraft vendor and mission operations; \
                     check AOCS telemetry for anomalous attitude or momentum values; \
                     enable command authentication if not already active.",
                ),
            );
        }

        if let Some((off, desc)) = Self::detect_power_attack(data) {
            findings.push(
                Finding::new(
                    "satellite_bus",
                    Severity::Critical,
                    "Power subsystem attack in satellite bus firmware",
                    &format!(
                        "Satellite bus firmware contains {desc} at offset 0x{off:08X}. \
                         Power subsystem attacks can permanently damage the spacecraft \
                         by depleting batteries, disabling solar arrays, or causing \
                         thermal runaway.",
                    ),
                )
                .with_confidence(0.86)
                .with_details(serde_json::json!({
                    "offset": format!("0x{off:08X}"),
                    "attack_type": desc,
                }))
                .with_recommendation(
                    "IMMEDIATE: Verify power subsystem telemetry; check battery \
                     state-of-charge and solar array current; switch to backup OBC \
                     if available; audit command uplink logs.",
                ),
            );
        }

        findings
    }
}

impl Detector for SatelliteBusDetector {
    fn name(&self) -> &str {
        "satellite_bus"
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
    fn fires_on_aocs_attack() {
        let mut v = b"AOCS flight_computer RTEMS OBC_main\n".to_vec();
        v.extend_from_slice(b"override_attitude=tumble\ndisable_safemode=1\n");
        let findings = SatelliteBusDetector::new().scan(&v);
        assert!(findings.iter().any(|f| f.severity == Severity::Critical));
    }

    #[test]
    fn fires_on_power_attack() {
        let mut v = b"satellite_bus power_subsystem controller\n".to_vec();
        v.extend_from_slice(b"drain_battery=max_rate\n");
        let findings = SatelliteBusDetector::new().scan(&v);
        assert!(findings.iter().any(|f| f.severity == Severity::Critical));
    }

    #[test]
    fn quiet_on_clean_bus() {
        let v = b"AOCS flight_computer RTEMS nominal operations v3.2".to_vec();
        assert!(SatelliteBusDetector::new().scan(&v).is_empty());
    }
}
