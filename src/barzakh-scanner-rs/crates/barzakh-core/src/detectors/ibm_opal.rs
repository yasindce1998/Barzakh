use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};

const PLATFORM_MARKERS: &[&[u8]] = &[b"OPAL", b"skiboot", b"skiroot", b"PowerPC"];

const OPAL_HOOK_MARKERS: &[&[u8]] = &[
    b"opal_call_hook",
    b"opal_nvram_backdoor",
    b"secureboot_toggle",
    b"opal_flash_persist",
];

pub struct IbmOpalDetector;

impl Default for IbmOpalDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl IbmOpalDetector {
    pub fn new() -> Self {
        Self
    }

    fn contains(data: &[u8], needle: &[u8]) -> bool {
        data.windows(needle.len()).any(|w| w == needle)
    }

    fn matched_markers(data: &[u8]) -> Vec<String> {
        OPAL_HOOK_MARKERS
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

        let hits = Self::matched_markers(data);
        if !hits.is_empty() {
            findings.push(
                Finding::new(
                    "ibm_opal",
                    Severity::High,
                    "OPAL call hook detected",
                    &format!(
                        "IBM POWER OPAL/skiboot firmware contains {} tampering \
                         indicator(s): {}. Hooked OPAL calls can redirect hypervisor \
                         services, backdoor NVRAM persistence, toggle secure boot state, \
                         or persist implants into system flash.",
                        hits.len(),
                        hits.join(", "),
                    ),
                )
                .with_confidence(0.84)
                .with_details(serde_json::json!({
                    "indicators": hits,
                }))
                .with_recommendation(
                    "Rebuild skiboot/skiroot from trusted sources and verify against \
                     signed distributions; reset NVRAM to factory defaults; verify secure \
                     boot state via ibm,secure-boot device tree properties; re-flash PNOR \
                     from a trusted image.",
                ),
            );
        }

        findings
    }
}

impl Detector for IbmOpalDetector {
    fn name(&self) -> &str {
        "ibm_opal"
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
    fn fires_on_opal_call_hook() {
        let mut v = b"skiboot OPAL firmware for PowerPC\n".to_vec();
        v.extend_from_slice(b"opal_call_hook=1\nopal_nvram_backdoor=true\n");
        let findings = IbmOpalDetector::new().scan(&v);
        assert!(findings
            .iter()
            .any(|f| f.severity == Severity::High && f.title == "OPAL call hook detected"));
    }

    #[test]
    fn fires_on_skiroot_marker() {
        let mut v = b"skiroot image\n".to_vec();
        v.extend_from_slice(b"secureboot_toggle=off\n");
        let findings = IbmOpalDetector::new().scan(&v);
        assert!(findings
            .iter()
            .any(|f| f.severity == Severity::High && f.title == "OPAL call hook detected"));
    }

    #[test]
    fn quiet_on_clean_skiboot() {
        let v = b"skiboot OPAL production firmware v6.8 PowerPC".to_vec();
        assert!(IbmOpalDetector::new().scan(&v).is_empty());
    }

    #[test]
    fn quiet_without_platform_marker() {
        let v = b"generic firmware with opal_call_hook but no POWER platform".to_vec();
        assert!(IbmOpalDetector::new().scan(&v).is_empty());
    }
}
