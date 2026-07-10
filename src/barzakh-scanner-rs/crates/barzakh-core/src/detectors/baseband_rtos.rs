use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};

// RTOS markers used in cellular basebands
const THREADX_MARKERS: &[&[u8]] = &[b"ThreadX", b"tx_thread_", b"tx_timer_", b"_tx_initialize"];
const NUCLEUS_MARKERS: &[&[u8]] = &[b"Nucleus PLUS", b"NU_", b"TCC_Task_"];
const REX_MARKERS: &[&[u8]] = &[b"REX_CORE", b"rex_def_task", b"rex_init"];
const IGUANA_MARKERS: &[&[u8]] = &[b"QuRT", b"qurt_thread", b"ADSP_"];

// Interrupt vector table manipulation indicators
const IVT_HOOK_SIG: &[u8] = &[0x00, 0x00, 0x00, 0xEA]; // ARM B (branch) at vector offset

pub struct BasebandRtosDetector;

impl Default for BasebandRtosDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl BasebandRtosDetector {
    pub fn new() -> Self {
        Self
    }

    fn contains(data: &[u8], needle: &[u8]) -> bool {
        data.windows(needle.len()).any(|w| w == needle)
    }

    fn has_rtos_marker(data: &[u8]) -> bool {
        THREADX_MARKERS.iter().any(|m| Self::contains(data, m))
            || NUCLEUS_MARKERS.iter().any(|m| Self::contains(data, m))
            || REX_MARKERS.iter().any(|m| Self::contains(data, m))
            || IGUANA_MARKERS.iter().any(|m| Self::contains(data, m))
    }

    fn detect_ivt_hooks(data: &[u8]) -> Vec<usize> {
        // The first 32 bytes of an ARM image are the interrupt vector table.
        // Each entry is a branch instruction. Look for branches that point
        // far outside the normal vector range (> 0x10000 from base).
        let mut suspicious = Vec::new();
        if data.len() < 32 {
            return suspicious;
        }
        for i in (0..32).step_by(4) {
            if i + 4 <= data.len() && data[i + 3] == 0xEA {
                let offset_field = u32::from_le_bytes([data[i], data[i + 1], data[i + 2], 0x00]);
                let target = (offset_field << 2).wrapping_add(8 + i as u32);
                if target > 0x10000 {
                    suspicious.push(i);
                }
            }
        }
        suspicious
    }

    fn detect_task_injection(data: &[u8]) -> Option<usize> {
        // Look for thread creation with suspicious names
        let suspicious_names: &[&[u8]] = &[b"spy_task", b"exfil_", b"hook_isr", b"shadow_"];
        for name in suspicious_names {
            if let Some(pos) = data.windows(name.len()).position(|w| w == *name) {
                return Some(pos);
            }
        }
        None
    }

    fn scan(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        if !Self::has_rtos_marker(data) {
            return findings;
        }

        let ivt_hooks = Self::detect_ivt_hooks(data);
        if !ivt_hooks.is_empty() {
            findings.push(
                Finding::new(
                    "baseband_rtos",
                    Severity::Critical,
                    "Interrupt vector table hooks in baseband RTOS",
                    &format!(
                        "Baseband RTOS firmware has {} interrupt vector entries branching \
                         to addresses far outside the normal vector range (>0x10000). \
                         Hooking the IVT gives an implant first-stage execution on every \
                         interrupt — persistent control of the modem processor.",
                        ivt_hooks.len(),
                    ),
                )
                .with_confidence(0.83)
                .with_details(serde_json::json!({
                    "hooked_vectors": ivt_hooks,
                }))
                .with_recommendation(
                    "Compare IVT against known-good RTOS image; reflash baseband \
                     firmware via secure boot recovery; audit modem diagnostic port \
                     for unauthorized access.",
                ),
            );
        }

        if let Some(pos) = Self::detect_task_injection(data) {
            findings.push(
                Finding::new(
                    "baseband_rtos",
                    Severity::High,
                    "Suspicious RTOS task in baseband firmware",
                    &format!(
                        "Baseband RTOS image contains a thread/task with an implant-associated \
                         name at offset 0x{pos:08X}. Legitimate baseband tasks follow vendor \
                         naming conventions; this suggests an injected surveillance task.",
                    ),
                )
                .with_confidence(0.76)
                .with_details(serde_json::json!({
                    "offset": format!("0x{pos:08X}"),
                }))
                .with_recommendation(
                    "Enumerate RTOS task list via debug interface; compare against \
                     vendor task manifest; investigate task's memory mappings and \
                     IPC channels.",
                ),
            );
        }

        findings
    }
}

impl Detector for BasebandRtosDetector {
    fn name(&self) -> &str {
        "baseband_rtos"
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
    fn fires_on_ivt_hook() {
        let mut v = vec![0u8; 256];
        v[0..7].copy_from_slice(b"ThreadX");
        // Plant a far branch at vector offset 0
        v[8] = 0x00;
        v[9] = 0x80;
        v[10] = 0x01;
        v[11] = 0xEA; // Branch to ~0x60008
        let findings = BasebandRtosDetector::new().scan(&v);
        assert!(findings.iter().any(|f| f.severity == Severity::Critical));
    }

    #[test]
    fn fires_on_suspicious_task() {
        let mut v = b"ThreadX baseband RTOS v5.8\n".to_vec();
        v.extend_from_slice(b"spy_task");
        let findings = BasebandRtosDetector::new().scan(&v);
        assert!(findings.iter().any(|f| f.severity == Severity::High));
    }

    #[test]
    fn quiet_on_clean_rtos() {
        let v = b"ThreadX baseband RTOS v5.8 normal build".to_vec();
        assert!(BasebandRtosDetector::new().scan(&v).is_empty());
    }
}
