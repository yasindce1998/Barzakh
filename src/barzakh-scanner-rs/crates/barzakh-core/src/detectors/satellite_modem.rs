use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};

const VSAT_MARKERS: &[&[u8]] = &[b"VSAT", b"DVB-S2", b"DVB-RCS", b"iDirect", b"Hughes"];
const SATMODEM_MARKERS: &[&[u8]] = &[
    b"Gilat", b"Newtec", b"Comtech", b"SatLink", b"MODCOD", b"SCPC", b"MF-TDMA",
];

const NOP_MIPS: &[u8] = &[0x00, 0x00, 0x00, 0x00]; // MIPS NOP (sll $zero, $zero, 0)
const MIN_SLED: usize = 64;

pub struct SatelliteModemDetector;

impl Default for SatelliteModemDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl SatelliteModemDetector {
    pub fn new() -> Self {
        Self
    }

    fn contains(data: &[u8], needle: &[u8]) -> bool {
        data.windows(needle.len()).any(|w| w == needle)
    }

    fn has_satmodem_marker(data: &[u8]) -> bool {
        VSAT_MARKERS.iter().any(|m| Self::contains(data, m))
            || SATMODEM_MARKERS.iter().any(|m| Self::contains(data, m))
    }

    fn find_nop_sled(data: &[u8]) -> Option<(usize, usize)> {
        let mut best_off = 0;
        let mut best_len = 0;
        let mut i = 0;
        while i + NOP_MIPS.len() <= data.len() {
            if &data[i..i + NOP_MIPS.len()] == NOP_MIPS {
                let start = i;
                while i + NOP_MIPS.len() <= data.len() && &data[i..i + NOP_MIPS.len()] == NOP_MIPS {
                    i += NOP_MIPS.len();
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

    fn detect_traffic_mirror(data: &[u8]) -> Option<usize> {
        let markers: &[&[u8]] = &[
            b"traffic_mirror",
            b"dvb_capture",
            b"ts_dump",
            b"pid_filter_all",
        ];
        for m in markers {
            if let Some(pos) = data.windows(m.len()).position(|w| w == *m) {
                return Some(pos);
            }
        }
        None
    }

    fn scan(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        if !Self::has_satmodem_marker(data) {
            return findings;
        }

        if let Some((off, len)) = Self::find_nop_sled(data) {
            findings.push(
                Finding::new(
                    "satellite_modem",
                    Severity::Critical,
                    "Code injection sled in VSAT modem firmware",
                    &format!(
                        "Satellite modem firmware contains a {len}-byte MIPS NOP sled at \
                         offset 0x{off:08X}. VSAT modem firmware (iDirect/Hughes/Gilat) \
                         running on MIPS processors does not use padding of this size; \
                         indicates an implant injected for persistent satellite link \
                         interception.",
                    ),
                )
                .with_confidence(0.82)
                .with_details(serde_json::json!({
                    "offset": format!("0x{off:08X}"),
                    "sled_length": len,
                }))
                .with_recommendation(
                    "Re-flash satellite modem from vendor-signed firmware; verify \
                     DVB-S2 demodulator chain integrity; audit management interface \
                     for unauthorized remote access.",
                ),
            );
        }

        if let Some(pos) = Self::detect_traffic_mirror(data) {
            findings.push(
                Finding::new(
                    "satellite_modem",
                    Severity::High,
                    "Traffic mirroring capability in satellite modem firmware",
                    &format!(
                        "VSAT modem firmware contains traffic capture/mirroring markers \
                         at offset 0x{pos:08X}. This indicates the modem has been modified \
                         to passively mirror all DVB transport stream data — enabling \
                         bulk interception of satellite communications.",
                    ),
                )
                .with_confidence(0.80)
                .with_details(serde_json::json!({
                    "offset": format!("0x{pos:08X}"),
                }))
                .with_recommendation(
                    "Analyze modem's Ethernet interfaces for unauthorized traffic \
                     mirroring; verify firmware hash against operator baseline; check \
                     for covert exfiltration channel on management VLAN.",
                ),
            );
        }

        findings
    }
}

impl Detector for SatelliteModemDetector {
    fn name(&self) -> &str {
        "satellite_modem"
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
    fn fires_on_injected_vsat() {
        let mut v = b"iDirect VSAT DVB-S2 modem fw\n".to_vec();
        v.extend_from_slice(&[0x00; 128]); // MIPS NOP sled
        let findings = SatelliteModemDetector::new().scan(&v);
        assert!(findings.iter().any(|f| f.severity == Severity::Critical));
    }

    #[test]
    fn fires_on_traffic_mirror() {
        let mut v = b"Hughes VSAT modem firmware\n".to_vec();
        v.extend_from_slice(b"traffic_mirror=all_pids\n");
        let findings = SatelliteModemDetector::new().scan(&v);
        assert!(findings.iter().any(|f| f.severity == Severity::High));
    }

    #[test]
    fn quiet_on_clean_vsat() {
        let v = b"iDirect VSAT DVB-S2 modem firmware v4.2 clean".to_vec();
        assert!(SatelliteModemDetector::new().scan(&v).is_empty());
    }
}
