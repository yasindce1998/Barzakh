use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};

const IMS_MARKERS: &[&[u8]] = &[
    b"IMS_SERVICE",
    b"volte_stack",
    b"SIP/2.0",
    b"P-CSCF",
    b"ims_registration",
];

const OFONNO_MARKERS: &[&[u8]] = &[b"oFono", b"RIL_REQUEST", b"RILJ_"];

const NOP_ARM_A64: &[u8] = &[0x1F, 0x20, 0x03, 0xD5]; // AArch64 NOP
const MIN_SLED: usize = 48;

pub struct ImsFirmwareDetector;

impl Default for ImsFirmwareDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl ImsFirmwareDetector {
    pub fn new() -> Self {
        Self
    }

    fn contains(data: &[u8], needle: &[u8]) -> bool {
        data.windows(needle.len()).any(|w| w == needle)
    }

    fn has_ims_marker(data: &[u8]) -> bool {
        IMS_MARKERS.iter().any(|m| Self::contains(data, m))
            || OFONNO_MARKERS.iter().any(|m| Self::contains(data, m))
    }

    fn find_nop_sled(data: &[u8]) -> Option<(usize, usize)> {
        let pat = NOP_ARM_A64;
        let mut best_off = 0;
        let mut best_len = 0;
        let mut i = 0;
        while i + pat.len() <= data.len() {
            if &data[i..i + pat.len()] == pat {
                let start = i;
                while i + pat.len() <= data.len() && &data[i..i + pat.len()] == pat {
                    i += pat.len();
                }
                let len = i - start;
                if len > best_len {
                    best_len = len;
                    best_off = start;
                }
            } else {
                i += 1;
            }
        }
        if best_len >= MIN_SLED {
            Some((best_off, best_len))
        } else {
            None
        }
    }

    fn check_sip_intercept(data: &[u8]) -> bool {
        let intercept_markers: &[&[u8]] = &[b"INVITE sip:", b"pcap_dump", b"mirror_rtp"];
        intercept_markers
            .iter()
            .filter(|m| Self::contains(data, m))
            .count()
            >= 2
    }

    fn scan(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        if !Self::has_ims_marker(data) {
            return findings;
        }

        if let Some((off, len)) = Self::find_nop_sled(data) {
            findings.push(
                Finding::new(
                    "ims_firmware",
                    Severity::High,
                    "Code injection sled in IMS/VoLTE firmware",
                    &format!(
                        "IMS subsystem firmware contains a {len}-byte AArch64 NOP sled at \
                         offset 0x{off:08X}. The IMS stack firmware should not contain \
                         large NOP regions; this indicates an injected code stub for \
                         intercepting SIP signaling or RTP voice streams.",
                    ),
                )
                .with_confidence(0.78)
                .with_details(serde_json::json!({
                    "offset": format!("0x{off:08X}"),
                    "sled_length": len,
                }))
                .with_recommendation(
                    "Re-flash IMS firmware from carrier-signed build; audit SIP \
                     registration path for unauthorized INVITE mirroring; verify \
                     P-CSCF trust anchors.",
                ),
            );
        }

        if Self::check_sip_intercept(data) {
            findings.push(
                Finding::new(
                    "ims_firmware",
                    Severity::Critical,
                    "SIP/RTP interception capability in IMS firmware",
                    "IMS firmware contains multiple markers indicating SIP INVITE \
                     interception and RTP stream mirroring capability. This is \
                     consistent with a lawful-intercept implant or rogue wiretap \
                     embedded in the VoLTE signaling path.",
                )
                .with_confidence(0.88)
                .with_details(serde_json::json!({
                    "indicators": ["INVITE sip:", "pcap_dump or mirror_rtp"],
                }))
                .with_recommendation(
                    "Audit IMS firmware provenance; compare against vendor-signed \
                     baseline; check for unauthorized PCAP interfaces on modem \
                     diagnostic ports.",
                ),
            );
        }

        findings
    }
}

impl Detector for ImsFirmwareDetector {
    fn name(&self) -> &str {
        "ims_firmware"
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
    fn fires_on_injected_ims() {
        let mut v = Vec::new();
        v.extend_from_slice(b"IMS_SERVICE volte_stack v3.0\n");
        v.extend_from_slice(&NOP_ARM_A64.repeat(16));
        let findings = ImsFirmwareDetector::new().scan(&v);
        assert!(findings.iter().any(|f| f.severity == Severity::High));
    }

    #[test]
    fn fires_on_sip_intercept() {
        let mut v = Vec::new();
        v.extend_from_slice(b"IMS_SERVICE config\n");
        v.extend_from_slice(b"INVITE sip:target@ims.mnc\n");
        v.extend_from_slice(b"pcap_dump=/tmp/rtp\n");
        v.extend_from_slice(b"mirror_rtp=1\n");
        let findings = ImsFirmwareDetector::new().scan(&v);
        assert!(findings.iter().any(|f| f.severity == Severity::Critical));
    }

    #[test]
    fn quiet_on_clean_ims() {
        let v = b"IMS_SERVICE normal registration flow".to_vec();
        assert!(ImsFirmwareDetector::new().scan(&v).is_empty());
    }
}
