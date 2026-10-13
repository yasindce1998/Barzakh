use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};

const PLATFORM_MARKERS: &[&[u8]] = &[b"FreeRTOS", b"ThreadX", b"Mbed"];

const RTOS_IMPLANT_MARKERS: &[&[u8]] = &[b"svc_hook_table", b"task_inject", b"wdt_disable_persist"];

pub struct IotRtosDetector;

impl Default for IotRtosDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl IotRtosDetector {
    pub fn new() -> Self {
        Self
    }

    fn contains(data: &[u8], needle: &[u8]) -> bool {
        data.windows(needle.len()).any(|w| w == needle)
    }

    fn matched_markers(data: &[u8]) -> Vec<String> {
        RTOS_IMPLANT_MARKERS
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
                    "iot_rtos",
                    Severity::Critical,
                    "RTOS implant detected",
                    &format!(
                        "RTOS firmware contains {} implant indicator(s): {}. Hooked \
                         supervisor-call tables and injected tasks execute with kernel \
                         privileges, while persistent watchdog disablement keeps the \
                         implant alive by preventing watchdog-triggered resets.",
                        hits.len(),
                        hits.join(", "),
                    ),
                )
                .with_confidence(0.89)
                .with_details(serde_json::json!({
                    "indicators": hits,
                }))
                .with_recommendation(
                    "Re-flash the device with a vendor-signed RTOS image; audit the \
                     kernel's SVC dispatch table and task list against the stock build; \
                     verify watchdog reset behavior under load.",
                ),
            );
        }

        findings
    }
}

impl Detector for IotRtosDetector {
    fn name(&self) -> &str {
        "iot_rtos"
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
    fn fires_on_rtos_implant() {
        let mut v = b"FreeRTOS kernel scheduler\n".to_vec();
        v.extend_from_slice(b"svc_hook_table=patched\ntask_inject=implant_task\n");
        let findings = IotRtosDetector::new().scan(&v);
        assert!(findings
            .iter()
            .any(|f| f.severity == Severity::Critical && f.title == "RTOS implant detected"));
    }

    #[test]
    fn quiet_on_clean_rtos() {
        let v = b"FreeRTOS kernel production build v10.5 scheduler".to_vec();
        assert!(IotRtosDetector::new().scan(&v).is_empty());
    }

    #[test]
    fn quiet_without_platform_marker() {
        let v = b"generic firmware with svc_hook_table marker only".to_vec();
        assert!(IotRtosDetector::new().scan(&v).is_empty());
    }
}
