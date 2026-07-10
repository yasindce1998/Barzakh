use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};

// SIM/UICC JavaCard applet markers
const JAVACARD_MARKERS: &[&[u8]] = &[
    b"\xA0\x00\x00\x00\x09", // ETSI SIM toolkit AID prefix
    b"\xA0\x00\x00\x00\x87", // GSM/3GPP AID prefix
    b"\xA0\x00\x00\x01\x51", // GlobalPlatform AID prefix
];

const CAP_MAGIC: &[u8] = &[0xDE, 0xCA, 0xFF, 0xED]; // JavaCard CAP file magic
const ESIM_MARKERS: &[&[u8]] = &[b"ISD-R", b"ISD-P", b"euicc", b"SM-DP+"];

// Suspicious STK (SIM Toolkit) commands that indicate exfiltration
const SUSPICIOUS_STK: &[&[u8]] = &[
    &[0xD0, 0x13], // SEND SHORT MESSAGE proactive command
    &[0xD0, 0x35], // OPEN CHANNEL (BIP — data over bearer)
    &[0xD0, 0x37], // SEND DATA (BIP)
];

pub struct SimAppletDetector;

impl Default for SimAppletDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl SimAppletDetector {
    pub fn new() -> Self {
        Self
    }

    fn contains(data: &[u8], needle: &[u8]) -> bool {
        data.windows(needle.len()).any(|w| w == needle)
    }

    fn has_sim_marker(data: &[u8]) -> bool {
        JAVACARD_MARKERS.iter().any(|m| Self::contains(data, m))
            || Self::contains(data, CAP_MAGIC)
            || ESIM_MARKERS.iter().any(|m| Self::contains(data, m))
    }

    fn count_stk_exfil_commands(data: &[u8]) -> Vec<usize> {
        let mut offsets = Vec::new();
        for pattern in SUSPICIOUS_STK {
            let mut i = 0;
            while i + pattern.len() <= data.len() {
                if &data[i..i + pattern.len()] == *pattern {
                    offsets.push(i);
                }
                i += 1;
            }
        }
        offsets
    }

    fn check_unauthorized_aids(data: &[u8]) -> Vec<(usize, &'static str)> {
        // Non-standard AIDs that don't match known operator/vendor prefixes
        let known_bad_aids: &[(&[u8], &str)] = &[
            (b"\xA0\x00\x00\x00\x09\x00\x01\xFF", "non-standard STK AID"),
            (
                b"\xD2\x76\x00\x01\x18",
                "unknown vendor AID in telecom domain",
            ),
        ];
        let mut hits = Vec::new();
        for (aid, desc) in known_bad_aids {
            if let Some(pos) = data.windows(aid.len()).position(|w| w == *aid) {
                hits.push((pos, *desc));
            }
        }
        hits
    }

    fn scan(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        if !Self::has_sim_marker(data) {
            return findings;
        }

        let stk_hits = Self::count_stk_exfil_commands(data);
        if stk_hits.len() >= 3 {
            let first = stk_hits[0];
            findings.push(
                Finding::new(
                    "sim_applet",
                    Severity::Critical,
                    "SIM Toolkit exfiltration commands in applet",
                    &format!(
                        "SIM/eSIM applet image contains {} STK proactive commands for \
                         SEND SMS or OPEN CHANNEL (BIP). First at offset 0x{first:08X}. \
                         Malicious SIM applets use these to silently exfiltrate data \
                         (location, IMSI, call records) via SMS or data bearer without \
                         user visibility (Simjacker/S@T-class attack).",
                        stk_hits.len(),
                    ),
                )
                .with_confidence(0.82)
                .with_details(serde_json::json!({
                    "stk_command_count": stk_hits.len(),
                    "first_offset": format!("0x{first:08X}"),
                }))
                .with_recommendation(
                    "Audit SIM applet inventory via OTA platform; verify applet \
                     signatures against MNO-approved certificate chain; disable \
                     S@T Browser if not required by operator services.",
                ),
            );
        }

        let bad_aids = Self::check_unauthorized_aids(data);
        for (off, desc) in &bad_aids {
            findings.push(
                Finding::new(
                    "sim_applet",
                    Severity::High,
                    "Unauthorized applet AID in SIM filesystem",
                    &format!(
                        "SIM image contains {desc} at offset 0x{off:08X}. This AID \
                         does not match any known operator or platform applet — may \
                         indicate a rogue applet installed via compromised OTA keys.",
                    ),
                )
                .with_confidence(0.72)
                .with_details(serde_json::json!({
                    "offset": format!("0x{off:08X}"),
                    "description": desc,
                }))
                .with_recommendation(
                    "Query GlobalPlatform registry for full applet list; cross-reference \
                     with operator's authorized applet catalog; rotate OTA keys if \
                     unauthorized installation confirmed.",
                ),
            );
        }

        findings
    }
}

impl Detector for SimAppletDetector {
    fn name(&self) -> &str {
        "sim_applet"
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
    fn fires_on_stk_exfil() {
        let mut v = Vec::new();
        v.extend_from_slice(b"\xA0\x00\x00\x00\x09\x00\x01"); // SIM AID
        for _ in 0..4 {
            v.extend_from_slice(&[0xD0, 0x13]); // SEND SMS
            v.extend_from_slice(&[0x00; 16]);
        }
        let findings = SimAppletDetector::new().scan(&v);
        assert!(findings.iter().any(|f| f.severity == Severity::Critical));
    }

    #[test]
    fn quiet_without_sim_marker() {
        let mut v = vec![0u8; 128];
        v[0..2].copy_from_slice(&[0xD0, 0x13]);
        assert!(SimAppletDetector::new().scan(&v).is_empty());
    }

    #[test]
    fn quiet_on_clean_sim() {
        let v = b"\xA0\x00\x00\x00\x09 normal SIM toolkit applet".to_vec();
        assert!(SimAppletDetector::new().scan(&v).is_empty());
    }
}
