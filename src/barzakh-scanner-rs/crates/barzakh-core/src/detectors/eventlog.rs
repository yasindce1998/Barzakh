use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};

const TCG_EVENT_HEADER_SIZE: usize = 32;
const EV_NO_ACTION: u32 = 0x03;
const EV_SEPARATOR: u32 = 0x04;
const EV_EFI_VARIABLE_DRIVER_CONFIG: u32 = 0x80000001;
const EV_EFI_BOOT_SERVICES_APPLICATION: u32 = 0x80000003;

pub struct EventLogDetector;

impl Default for EventLogDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl EventLogDetector {
    pub fn new() -> Self {
        Self
    }

    fn parse_event_log(&self, data: &[u8]) -> Vec<TcgEvent> {
        let mut events = Vec::new();
        let mut offset = 0;

        while offset + TCG_EVENT_HEADER_SIZE <= data.len() {
            let pcr_index =
                u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap_or([0; 4]));
            let event_type =
                u32::from_le_bytes(data[offset + 4..offset + 8].try_into().unwrap_or([0; 4]));
            let event_size =
                u32::from_le_bytes(data[offset + 28..offset + 32].try_into().unwrap_or([0; 4]))
                    as usize;

            if event_size > data.len() - offset - TCG_EVENT_HEADER_SIZE {
                break;
            }

            let digest = data[offset + 8..offset + 28].to_vec();
            let event_data = data
                [offset + TCG_EVENT_HEADER_SIZE..offset + TCG_EVENT_HEADER_SIZE + event_size]
                .to_vec();

            events.push(TcgEvent {
                pcr_index: pcr_index as u8,
                event_type,
                digest,
                event_data,
            });

            offset += TCG_EVENT_HEADER_SIZE + event_size;
        }

        events
    }

    fn check_event_order(&self, events: &[TcgEvent]) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut seen_separator = false;

        for (i, event) in events.iter().enumerate() {
            if event.event_type == EV_SEPARATOR {
                seen_separator = true;
            }

            // Events after separator in PCR[0-6] are suspicious
            if seen_separator
                && event.pcr_index <= 6
                && event.event_type != EV_SEPARATOR
                && event.event_type != EV_NO_ACTION
            {
                findings.push(
                    Finding::new(
                        "eventlog",
                        Severity::High,
                        "Event logged after separator",
                        &format!(
                            "Event type 0x{:08X} in PCR[{}] at index {} appears after \
                             the separator event. This violates TCG spec and may indicate \
                             log manipulation.",
                            event.event_type, event.pcr_index, i
                        ),
                    )
                    .with_confidence(0.80)
                    .with_details(serde_json::json!({
                        "event_index": i,
                        "pcr_index": event.pcr_index,
                        "event_type": format!("0x{:08X}", event.event_type),
                    })),
                );
            }
        }

        findings
    }

    fn check_missing_measurements(&self, events: &[TcgEvent]) -> Vec<Finding> {
        let mut findings = Vec::new();

        let has_boot_app = events
            .iter()
            .any(|e| e.event_type == EV_EFI_BOOT_SERVICES_APPLICATION);

        if !has_boot_app && !events.is_empty() {
            findings.push(Finding::new(
                "eventlog",
                Severity::Medium,
                "No boot application measurement in event log",
                "Expected at least one EV_EFI_BOOT_SERVICES_APPLICATION event. \
                 Its absence may indicate the event log is incomplete or truncated.",
            ));
        }

        let has_secureboot_var = events
            .iter()
            .any(|e| e.event_type == EV_EFI_VARIABLE_DRIVER_CONFIG && e.pcr_index == 7);

        if !has_secureboot_var && !events.is_empty() {
            findings.push(Finding::new(
                "eventlog",
                Severity::Medium,
                "No Secure Boot variable measurement in PCR[7]",
                "Expected EV_EFI_VARIABLE_DRIVER_CONFIG events in PCR[7] for Secure Boot policy. \
                 Absence may indicate the event log was tampered with to hide policy changes.",
            ));
        }

        findings
    }
}

impl Detector for EventLogDetector {
    fn name(&self) -> &str {
        "eventlog"
    }

    fn detect(&self, target_path: &Path) -> Result<Vec<Finding>, DetectorError> {
        self.detect_context(&crate::ScanContext::load(target_path)?)
    }
    fn detect_context(&self, context: &crate::ScanContext) -> Result<Vec<Finding>, DetectorError> {
        let data = context.shared_bytes();
        let mut findings = Vec::new();

        let events = self.parse_event_log(&data);

        if events.is_empty() {
            return Ok(findings);
        }

        findings.extend(self.check_event_order(&events));
        findings.extend(self.check_missing_measurements(&events));

        Ok(findings)
    }
}

#[derive(Debug)]
#[allow(dead_code)]
struct TcgEvent {
    pcr_index: u8,
    event_type: u32,
    digest: Vec<u8>,
    event_data: Vec<u8>,
}
