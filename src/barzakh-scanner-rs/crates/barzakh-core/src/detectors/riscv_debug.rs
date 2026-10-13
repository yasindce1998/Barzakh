use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};

const PLATFORM_MARKERS: &[&[u8]] = &[b"RISC-V", b"dmi", b"DebugModule"];

const DEBUG_UNLOCK_MARKERS: &[&[u8]] =
    &[b"dmi_unlock", b"hart_debug_enable", b"abstract_cmd_inject"];

pub struct RiscVDebugDetector;

impl Default for RiscVDebugDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl RiscVDebugDetector {
    pub fn new() -> Self {
        Self
    }

    fn contains(data: &[u8], needle: &[u8]) -> bool {
        data.windows(needle.len()).any(|w| w == needle)
    }

    fn matched_markers(data: &[u8]) -> Vec<String> {
        DEBUG_UNLOCK_MARKERS
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
                    "riscv_debug",
                    Severity::High,
                    "RISC-V debug interface unlocked",
                    &format!(
                        "RISC-V firmware contains {} unauthorized debug module enablement \
                         indicator(s): {}. An unlocked Debug Module Interface grants \
                         hart-level halt/resume, register and memory access via abstract \
                         commands, bypassing all software-enforced access control.",
                        hits.len(),
                        hits.join(", "),
                    ),
                )
                .with_confidence(0.85)
                .with_details(serde_json::json!({
                    "indicators": hits,
                }))
                .with_recommendation(
                    "Restore debug module lockdown (dmdisabled/hart debug-enable bits) via \
                     trusted firmware; check debug request strap pins; on parts with \
                     permanent disable fuses, verify they are blown on production units.",
                ),
            );
        }

        findings
    }
}

impl Detector for RiscVDebugDetector {
    fn name(&self) -> &str {
        "riscv_debug"
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
    fn fires_on_debug_unlock() {
        let mut v = b"RISC-V DebugModule dmi access layer\n".to_vec();
        v.extend_from_slice(b"dmi_unlock=1\nhart_debug_enable=all\n");
        let findings = RiscVDebugDetector::new().scan(&v);
        assert!(findings
            .iter()
            .any(|f| f.severity == Severity::High && f.title == "RISC-V debug interface unlocked"));
    }

    #[test]
    fn quiet_on_clean_debug_module() {
        let v = b"RISC-V DebugModule locked production image dmi disabled".to_vec();
        assert!(RiscVDebugDetector::new().scan(&v).is_empty());
    }

    #[test]
    fn quiet_without_platform_marker() {
        let v = b"generic firmware with hart_debug_enable marker only".to_vec();
        assert!(RiscVDebugDetector::new().scan(&v).is_empty());
    }
}
