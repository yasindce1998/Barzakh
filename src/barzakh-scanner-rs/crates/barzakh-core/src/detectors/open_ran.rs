use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};

const ORAN_MARKERS: &[&[u8]] = &[
    b"O-RAN.WG",
    b"o-ran-sc",
    b"xApp",
    b"rApp",
    b"near-RT RIC",
    b"E2AP",
    b"A1-Policy",
];

const DU_MARKERS: &[&[u8]] = &[b"O-DU", b"FAPI_", b"nFAPI", b"fronthaul"];
const CU_MARKERS: &[&[u8]] = &[b"O-CU", b"F1AP", b"E1AP", b"NGAP"];

pub struct OpenRanDetector;

impl Default for OpenRanDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl OpenRanDetector {
    pub fn new() -> Self {
        Self
    }

    fn contains(data: &[u8], needle: &[u8]) -> bool {
        data.windows(needle.len()).any(|w| w == needle)
    }

    fn has_oran_marker(data: &[u8]) -> bool {
        ORAN_MARKERS.iter().any(|m| Self::contains(data, m))
            || DU_MARKERS.iter().any(|m| Self::contains(data, m))
            || CU_MARKERS.iter().any(|m| Self::contains(data, m))
    }

    fn detect_unauthorized_xapp(data: &[u8]) -> Vec<(usize, &'static str)> {
        let suspicious = [
            (b"xApp_exfil" as &[u8], "exfiltration xApp"),
            (b"mirror_e2", "E2 interface mirror xApp"),
            (b"ric_backdoor", "RIC backdoor component"),
            (b"unauthorized_xapp", "explicitly unauthorized xApp"),
        ];
        let mut hits = Vec::new();
        for (pattern, desc) in &suspicious {
            if let Some(pos) = data.windows(pattern.len()).position(|w| w == *pattern) {
                hits.push((pos, *desc));
            }
        }
        hits
    }

    fn detect_fronthaul_tampering(data: &[u8]) -> Option<usize> {
        // eCPRI message type 0xFF is reserved — its presence in firmware
        // indicates non-standard fronthaul manipulation.
        let ecpri_reserved = &[0x10, 0xFF]; // eCPRI header: proto rev 1, msg type 0xFF
        data.windows(ecpri_reserved.len())
            .position(|w| w == ecpri_reserved)
    }

    fn scan(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        if !Self::has_oran_marker(data) {
            return findings;
        }

        let xapp_hits = Self::detect_unauthorized_xapp(data);
        for (off, desc) in &xapp_hits {
            findings.push(
                Finding::new(
                    "open_ran",
                    Severity::Critical,
                    "Unauthorized xApp/rApp in O-RAN firmware",
                    &format!(
                        "O-RAN component firmware contains reference to {desc} at offset \
                         0x{off:08X}. The near-RT RIC should only host operator-approved \
                         xApps; an unauthorized component can intercept E2 telemetry, \
                         manipulate radio resource scheduling, or mirror user-plane data.",
                    ),
                )
                .with_confidence(0.84)
                .with_details(serde_json::json!({
                    "offset": format!("0x{off:08X}"),
                    "description": desc,
                }))
                .with_recommendation(
                    "Audit xApp/rApp catalog on near-RT and non-RT RIC; verify \
                     container image signatures; check A1/E2 policy logs for \
                     unauthorized subscriptions; review SMO access controls.",
                ),
            );
        }

        if let Some(off) = Self::detect_fronthaul_tampering(data) {
            findings.push(
                Finding::new(
                    "open_ran",
                    Severity::High,
                    "Non-standard eCPRI message type in O-RAN DU firmware",
                    &format!(
                        "O-RAN DU firmware contains a reserved eCPRI message type (0xFF) \
                         at offset 0x{off:08X}. Reserved message types on the fronthaul \
                         interface indicate custom protocol extensions that could be used \
                         for covert data exfiltration over the RU-DU link.",
                    ),
                )
                .with_confidence(0.74)
                .with_details(serde_json::json!({
                    "offset": format!("0x{off:08X}"),
                    "ecpri_msg_type": "0xFF (reserved)",
                }))
                .with_recommendation(
                    "Capture and analyze fronthaul traffic for non-standard eCPRI \
                     messages; verify DU firmware integrity against vendor baseline; \
                     audit O-RAN M-plane configuration for unauthorized changes.",
                ),
            );
        }

        findings
    }
}

impl Detector for OpenRanDetector {
    fn name(&self) -> &str {
        "open_ran"
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
    fn fires_on_rogue_xapp() {
        let mut v = b"O-RAN.WG near-RT RIC firmware\n".to_vec();
        v.extend_from_slice(b"xApp_exfil handler registered");
        let findings = OpenRanDetector::new().scan(&v);
        assert!(findings.iter().any(|f| f.severity == Severity::Critical));
    }

    #[test]
    fn fires_on_fronthaul_tamper() {
        let mut v = b"O-DU FAPI_ fronthaul config\n".to_vec();
        v.extend_from_slice(&[0x10, 0xFF, 0x00, 0x20]);
        let findings = OpenRanDetector::new().scan(&v);
        assert!(findings.iter().any(|f| f.severity == Severity::High));
    }

    #[test]
    fn quiet_on_clean_oran() {
        let v = b"O-RAN.WG standard DU firmware v2.1".to_vec();
        assert!(OpenRanDetector::new().scan(&v).is_empty());
    }
}
