use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};

// CCSDS (Consultative Committee for Space Data Systems) protocol markers
const CCSDS_MARKERS: &[&[u8]] = &[b"CCSDS", b"TC_FRAME", b"CLTU", b"COP-1", b"FARM", b"MAP_ID"];

const SPACE_LINK_MARKERS: &[&[u8]] =
    &[b"SLE_RAF", b"SLE_RCF", b"SLE_CLTU", b"FCLTU", b"space_link"];

pub struct CcsdsTelecommandDetector;

impl Default for CcsdsTelecommandDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl CcsdsTelecommandDetector {
    pub fn new() -> Self {
        Self
    }

    fn contains(data: &[u8], needle: &[u8]) -> bool {
        data.windows(needle.len()).any(|w| w == needle)
    }

    fn has_ccsds_marker(data: &[u8]) -> bool {
        CCSDS_MARKERS.iter().any(|m| Self::contains(data, m))
            || SPACE_LINK_MARKERS.iter().any(|m| Self::contains(data, m))
    }

    fn detect_auth_bypass(data: &[u8]) -> Vec<(usize, &'static str)> {
        let bypass_markers: &[(&[u8], &str)] = &[
            (b"disable_sdls", "SDLS encryption/auth bypass"),
            (b"skip_tc_auth", "telecommand authentication skip"),
            (b"clear_key", "encryption key clear"),
            (b"replay_cltu", "CLTU frame replay"),
            (b"forge_mac", "MAC forgery for telecommand auth"),
        ];
        let mut hits = Vec::new();
        for (pat, desc) in bypass_markers {
            if let Some(pos) = data.windows(pat.len()).position(|w| w == *pat) {
                hits.push((pos, *desc));
            }
        }
        hits
    }

    fn detect_protocol_manipulation(data: &[u8]) -> Vec<(usize, &'static str)> {
        let manipulation_markers: &[(&[u8], &str)] = &[
            (b"inject_tc_packet", "TC packet injection"),
            (b"modify_map_id", "MAP ID manipulation"),
            (b"bypass_cop1", "COP-1 bypass (frame sequence)"),
            (b"spoof_vcid", "Virtual Channel ID spoofing"),
        ];
        let mut hits = Vec::new();
        for (pat, desc) in manipulation_markers {
            if let Some(pos) = data.windows(pat.len()).position(|w| w == *pat) {
                hits.push((pos, *desc));
            }
        }
        hits
    }

    fn scan(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        if !Self::has_ccsds_marker(data) {
            return findings;
        }

        let auth_hits = Self::detect_auth_bypass(data);
        if !auth_hits.is_empty() {
            let first = auth_hits[0].0;
            let descs: Vec<&str> = auth_hits.iter().map(|(_, d)| *d).collect();
            findings.push(
                Finding::new(
                    "ccsds_telecommand",
                    Severity::Critical,
                    "CCSDS telecommand authentication bypass in firmware",
                    &format!(
                        "Space data link firmware contains {} SDLS/telecommand \
                         authentication bypass indicators. First at offset 0x{first:08X}. \
                         Bypassing CCSDS Space Data Link Security enables unauthorized \
                         spacecraft commanding — a direct path to loss of mission.",
                        auth_hits.len(),
                    ),
                )
                .with_confidence(0.90)
                .with_details(serde_json::json!({
                    "indicators": descs,
                    "first_offset": format!("0x{first:08X}"),
                }))
                .with_recommendation(
                    "CRITICAL: Verify SDLS key state via authenticated telemetry; \
                     rotate TC encryption keys immediately; audit SLE provider \
                     access logs; verify ground station firmware integrity; engage \
                     mission security officer.",
                ),
            );
        }

        let proto_hits = Self::detect_protocol_manipulation(data);
        if !proto_hits.is_empty() {
            let first = proto_hits[0].0;
            let descs: Vec<&str> = proto_hits.iter().map(|(_, d)| *d).collect();
            findings.push(
                Finding::new(
                    "ccsds_telecommand",
                    Severity::High,
                    "CCSDS protocol manipulation in space link firmware",
                    &format!(
                        "Space data link firmware contains {} protocol manipulation \
                         capabilities. First at offset 0x{first:08X}. Manipulating \
                         CCSDS TC frames, virtual channels, or COP-1 sequence control \
                         can inject unauthorized commands or desynchronize the command \
                         link.",
                        proto_hits.len(),
                    ),
                )
                .with_confidence(0.82)
                .with_details(serde_json::json!({
                    "indicators": descs,
                    "first_offset": format!("0x{first:08X}"),
                }))
                .with_recommendation(
                    "Verify COP-1 frame sequence counters; check FARM state for \
                     rejected frames; audit CLTU history for anomalous patterns; \
                     verify SLE connection authentication.",
                ),
            );
        }

        findings
    }
}

impl Detector for CcsdsTelecommandDetector {
    fn name(&self) -> &str {
        "ccsds_telecommand"
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
    fn fires_on_auth_bypass() {
        let mut v = b"CCSDS TC_FRAME SDLS processor\n".to_vec();
        v.extend_from_slice(b"disable_sdls=1\nskip_tc_auth=true\n");
        let findings = CcsdsTelecommandDetector::new().scan(&v);
        assert!(findings.iter().any(|f| f.severity == Severity::Critical));
    }

    #[test]
    fn fires_on_protocol_manipulation() {
        let mut v = b"CCSDS COP-1 FARM SLE_CLTU\n".to_vec();
        v.extend_from_slice(b"inject_tc_packet=enabled\n");
        let findings = CcsdsTelecommandDetector::new().scan(&v);
        assert!(findings.iter().any(|f| f.severity == Severity::High));
    }

    #[test]
    fn quiet_on_clean_ccsds() {
        let v = b"CCSDS TC_FRAME COP-1 nominal processing firmware".to_vec();
        assert!(CcsdsTelecommandDetector::new().scan(&v).is_empty());
    }
}
