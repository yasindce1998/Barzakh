use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};

const PLATFORM_MARKERS: &[&[u8]] = &[b"NVIDIA", b"Tegra", b"Jetson", b"DriveOS"];

const BOOTCHAIN_MARKERS: &[&[u8]] = &[
    b"bpmp_dmce_hook",
    b"override_pk_hash",
    b"skip_se_flash",
    b"pinmux_jtag_force",
];

const NSP_FW_MARKERS: &[&[u8]] = &[b"nsp_fw_patch", b"se_tunnel_key", b"mb1_sig_strip"];

pub struct NvidiaTegraDetector;

impl Default for NvidiaTegraDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl NvidiaTegraDetector {
    pub fn new() -> Self {
        Self
    }

    fn contains(data: &[u8], needle: &[u8]) -> bool {
        data.windows(needle.len()).any(|w| w == needle)
    }

    fn matched_markers(data: &[u8], markers: &[&[u8]]) -> Vec<String> {
        markers
            .iter()
            .filter(|m| Self::contains(data, m))
            .map(|m| String::from_utf8_lossy(m).into_owned())
            .collect()
    }

    fn scan(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        if !PLATFORM_MARKERS.iter().any(|m| Self::contains(data, m)) {
            return findings;
        }

        let boot_hits = Self::matched_markers(data, BOOTCHAIN_MARKERS);
        if !boot_hits.is_empty() {
            findings.push(
                Finding::new(
                    "nvidia_tegra",
                    Severity::Critical,
                    "Tegra boot chain implant",
                    &format!(
                        "NVIDIA Tegra/Jetson/Drive boot chain firmware contains {} boot \
                         chain implant indicator(s): {}. These markers indicate tampering \
                         with the BPMP, public key hash verification, SE flash loading, or \
                         JTAG pinmux forcing — enabling persistent pre-boot compromise of \
                         the platform.",
                        boot_hits.len(),
                        boot_hits.join(", "),
                    ),
                )
                .with_confidence(0.9)
                .with_details(serde_json::json!({
                    "indicators": boot_hits,
                }))
                .with_recommendation(
                    "Re-flash the boot chain (MB1/MB2/BPMP) from NVIDIA-signed images; \
                     verify the public key hash fuses against the expected root of trust; \
                     inspect pinmux/straps for forced JTAG enablement.",
                ),
            );
        }

        let nsp_hits = Self::matched_markers(data, NSP_FW_MARKERS);
        if !nsp_hits.is_empty() {
            findings.push(
                Finding::new(
                    "nvidia_tegra",
                    Severity::High,
                    "NVIDIA Security Processor firmware tampering",
                    &format!(
                        "Firmware contains {} NVIDIA Security Processor (NSP/SE) tampering \
                         indicator(s): {}. Modified security processor firmware can strip \
                         image signatures, exfiltrate keys, or tunnel commands past \
                         hardware-enforced isolation.",
                        nsp_hits.len(),
                        nsp_hits.join(", "),
                    ),
                )
                .with_confidence(0.82)
                .with_details(serde_json::json!({
                    "indicators": nsp_hits,
                }))
                .with_recommendation(
                    "Compare NSP/SE firmware against the signed stock image; rotate any \
                     keys provisioned while the tampered firmware was active; audit SE \
                     keyslot usage.",
                ),
            );
        }

        findings
    }
}

impl Detector for NvidiaTegraDetector {
    fn name(&self) -> &str {
        "nvidia_tegra"
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
    fn fires_on_boot_chain_implant() {
        let mut v = b"NVIDIA Jetson Tegra X2 boot firmware\n".to_vec();
        v.extend_from_slice(b"override_pk_hash=1\nskip_se_flash=true\n");
        let findings = NvidiaTegraDetector::new().scan(&v);
        assert!(findings
            .iter()
            .any(|f| f.severity == Severity::Critical && f.title == "Tegra boot chain implant"));
    }

    #[test]
    fn fires_on_nsp_tampering() {
        let mut v = b"Tegra DriveOS image\n".to_vec();
        v.extend_from_slice(b"nsp_fw_patch=1\n");
        let findings = NvidiaTegraDetector::new().scan(&v);
        assert!(findings.iter().any(|f| f.severity == Severity::High
            && f.title == "NVIDIA Security Processor firmware tampering"));
    }

    #[test]
    fn quiet_on_clean_tegra() {
        let v = b"NVIDIA Jetson Tegra production boot chain v1.0".to_vec();
        assert!(NvidiaTegraDetector::new().scan(&v).is_empty());
    }

    #[test]
    fn quiet_without_platform_marker() {
        let v = b"generic firmware override_pk_hash=1".to_vec();
        assert!(NvidiaTegraDetector::new().scan(&v).is_empty());
    }
}
