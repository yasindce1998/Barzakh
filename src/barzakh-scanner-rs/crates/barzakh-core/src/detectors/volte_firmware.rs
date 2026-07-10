use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};

const VOLTE_MARKERS: &[&[u8]] = &[
    b"VoLTE",
    b"VoNR",
    b"QoS_flow",
    b"EPS_bearer",
    b"PDN_GW",
    b"PCRF",
];

const MODEM_DSP_MARKERS: &[&[u8]] = &[b"QDSP6", b"Hexagon", b"cDSP", b"mDSP"];
const CODEC_MARKERS: &[&[u8]] = &[b"AMR-WB", b"EVS_codec", b"SILK"];

const SHELLCODE_PREAMBLE: &[u8] = &[0x7F, 0x45, 0x4C, 0x46]; // ELF magic in unexpected location

pub struct VolteFirmwareDetector;

impl Default for VolteFirmwareDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl VolteFirmwareDetector {
    pub fn new() -> Self {
        Self
    }

    fn contains(data: &[u8], needle: &[u8]) -> bool {
        data.windows(needle.len()).any(|w| w == needle)
    }

    fn has_volte_marker(data: &[u8]) -> bool {
        VOLTE_MARKERS.iter().any(|m| Self::contains(data, m))
            || MODEM_DSP_MARKERS.iter().any(|m| Self::contains(data, m))
    }

    fn find_embedded_elf(data: &[u8]) -> Vec<usize> {
        // An ELF header appearing after the first 0x1000 bytes of a VoLTE
        // DSP firmware blob is suspicious — DSP firmware uses proprietary formats.
        let mut hits = Vec::new();
        let start = 0x1000.min(data.len());
        for i in start..data.len().saturating_sub(4) {
            if &data[i..i + 4] == SHELLCODE_PREAMBLE {
                hits.push(i);
            }
        }
        hits
    }

    fn detect_codec_hook(data: &[u8]) -> Option<usize> {
        // Look for codec-path interception markers
        let hook_indicators: &[&[u8]] = &[b"codec_hook", b"amr_intercept", b"rtp_mirror"];
        for marker in hook_indicators {
            if let Some(pos) = data.windows(marker.len()).position(|w| w == *marker) {
                return Some(pos);
            }
        }
        None
    }

    fn scan(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        if !Self::has_volte_marker(data) {
            return findings;
        }

        let embedded_elfs = Self::find_embedded_elf(data);
        if !embedded_elfs.is_empty() {
            let off = embedded_elfs[0];
            findings.push(
                Finding::new(
                    "volte_firmware",
                    Severity::Critical,
                    "Embedded ELF binary in VoLTE DSP firmware",
                    &format!(
                        "VoLTE/VoNR modem DSP firmware contains an embedded ELF binary at \
                         offset 0x{off:08X}. DSP firmware blobs (Hexagon/QDSP6) use \
                         proprietary formats; an ELF at this location indicates a Linux \
                         userspace implant injected into the modem's application processor \
                         firmware partition for voice-call interception.",
                    ),
                )
                .with_confidence(0.82)
                .with_details(serde_json::json!({
                    "elf_offsets": embedded_elfs.iter().map(|o| format!("0x{o:08X}")).collect::<Vec<_>>(),
                    "count": embedded_elfs.len(),
                }))
                .with_recommendation(
                    "Extract and analyze the embedded ELF; re-flash modem firmware \
                     from carrier-signed build; audit modem's shared memory interface \
                     for unauthorized data extraction.",
                ),
            );
        }

        if let Some(pos) = Self::detect_codec_hook(data) {
            findings.push(
                Finding::new(
                    "volte_firmware",
                    Severity::High,
                    "Voice codec interception hook in VoLTE firmware",
                    &format!(
                        "VoLTE firmware contains codec-path interception markers at offset \
                         0x{pos:08X}. This indicates the AMR/EVS codec pipeline has been \
                         hooked to mirror decoded voice frames — a persistent wiretap at \
                         the modem layer that survives OS reinstalls.",
                    ),
                )
                .with_confidence(0.79)
                .with_details(serde_json::json!({
                    "offset": format!("0x{pos:08X}"),
                }))
                .with_recommendation(
                    "Compare codec DSP firmware against vendor baseline hash; audit \
                     modem diagnostic port for unauthorized PCM/RTP extraction; verify \
                     firmware signature chain.",
                ),
            );
        }

        findings
    }
}

impl Detector for VolteFirmwareDetector {
    fn name(&self) -> &str {
        "volte_firmware"
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
    fn fires_on_embedded_elf() {
        let mut v = vec![0u8; 0x2000];
        v[0..5].copy_from_slice(b"VoLTE");
        v[0x1000..0x1004].copy_from_slice(&[0x7F, 0x45, 0x4C, 0x46]);
        let findings = VolteFirmwareDetector::new().scan(&v);
        assert!(findings.iter().any(|f| f.severity == Severity::Critical));
    }

    #[test]
    fn fires_on_codec_hook() {
        let mut v = b"VoLTE QDSP6 modem firmware\n".to_vec();
        v.extend_from_slice(b"codec_hook=amr_wb_decode\n");
        let findings = VolteFirmwareDetector::new().scan(&v);
        assert!(findings.iter().any(|f| f.severity == Severity::High));
    }

    #[test]
    fn quiet_on_clean_volte() {
        let v = b"VoLTE QDSP6 modem firmware clean build v4.0".to_vec();
        assert!(VolteFirmwareDetector::new().scan(&v).is_empty());
    }
}
