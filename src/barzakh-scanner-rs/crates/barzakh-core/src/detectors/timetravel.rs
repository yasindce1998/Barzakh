use std::collections::HashMap;
use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};

const AGTT_MAGIC: &[u8; 4] = b"AGTT";
const AGTT_HEADER_SIZE: usize = 64;
const TRACE_RECORD_SIZE: usize = 48;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
enum EventType {
    MemoryRead = 0,
    MemoryWrite = 1,
    IoRead = 2,
    IoWrite = 3,
    MsrRead = 4,
    MsrWrite = 5,
    Interrupt = 6,
    FunctionCall = 7,
    FunctionReturn = 8,
    Unknown = 0xFF,
}

impl From<u8> for EventType {
    fn from(val: u8) -> Self {
        match val {
            0 => Self::MemoryRead,
            1 => Self::MemoryWrite,
            2 => Self::IoRead,
            3 => Self::IoWrite,
            4 => Self::MsrRead,
            5 => Self::MsrWrite,
            6 => Self::Interrupt,
            7 => Self::FunctionCall,
            8 => Self::FunctionReturn,
            _ => Self::Unknown,
        }
    }
}

#[derive(Debug, Clone)]
struct TraceHeader {
    version: u16,
    architecture: u16,
    record_count: u64,
    start_timestamp: u64,
    end_timestamp: u64,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct TraceEvent {
    timestamp_ns: u64,
    event_type: EventType,
    access_type: u8,
    flags: u16,
    pc: u64,
    address: u64,
    value: u64,
    aux_data: u32,
}

// Known BST function offsets for tracking access patterns
const BST_OFFSETS: &[(&str, u64)] = &[
    ("RaiseTPL", 0x18),
    ("RestoreTPL", 0x20),
    ("AllocatePages", 0x28),
    ("FreePages", 0x30),
    ("GetMemoryMap", 0x38),
    ("AllocatePool", 0x40),
    ("FreePool", 0x48),
    ("LoadImage", 0xC8),
    ("StartImage", 0xD0),
    ("ExitBootServices", 0xE8),
    ("LocateProtocol", 0x140),
    ("InstallProtocolInterface", 0x80),
    ("HandleProtocol", 0x98),
];

pub struct TimeTravelDetector;

impl Default for TimeTravelDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl TimeTravelDetector {
    pub fn new() -> Self {
        Self
    }

    fn parse_header(data: &[u8]) -> Option<TraceHeader> {
        if data.len() < AGTT_HEADER_SIZE {
            return None;
        }

        if &data[0..4] != AGTT_MAGIC {
            return None;
        }

        let version = u16::from_le_bytes(data[4..6].try_into().ok()?);
        let architecture = u16::from_le_bytes(data[6..8].try_into().ok()?);
        let record_count = u64::from_le_bytes(data[8..16].try_into().ok()?);
        let start_timestamp = u64::from_le_bytes(data[16..24].try_into().ok()?);
        let end_timestamp = u64::from_le_bytes(data[24..32].try_into().ok()?);

        Some(TraceHeader {
            version,
            architecture,
            record_count,
            start_timestamp,
            end_timestamp,
        })
    }

    fn parse_events(data: &[u8], header: &TraceHeader) -> Vec<TraceEvent> {
        let mut events = Vec::new();
        let max_records = header.record_count as usize;

        for i in 0..max_records {
            let offset = AGTT_HEADER_SIZE + i * TRACE_RECORD_SIZE;
            if offset + TRACE_RECORD_SIZE > data.len() {
                break;
            }

            let record = &data[offset..offset + TRACE_RECORD_SIZE];

            let timestamp_ns = u64::from_le_bytes(record[0..8].try_into().unwrap_or([0; 8]));
            let event_type = EventType::from(record[8]);
            let access_type = record[9];
            let flags = u16::from_le_bytes(record[10..12].try_into().unwrap_or([0; 2]));
            let pc = u64::from_le_bytes(record[16..24].try_into().unwrap_or([0; 8]));
            let address = u64::from_le_bytes(record[24..32].try_into().unwrap_or([0; 8]));
            let value = u64::from_le_bytes(record[32..40].try_into().unwrap_or([0; 8]));
            let aux_data = u32::from_le_bytes(record[40..44].try_into().unwrap_or([0; 4]));

            events.push(TraceEvent {
                timestamp_ns,
                event_type,
                access_type,
                flags,
                pc,
                address,
                value,
                aux_data,
            });
        }

        events
    }

    fn detect_bst_access_patterns(&self, events: &[TraceEvent]) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Track writes to BST offsets
        let mut bst_writes: HashMap<u64, Vec<&TraceEvent>> = HashMap::new();

        for event in events {
            if event.event_type == EventType::MemoryWrite {
                for &(_, bst_offset) in BST_OFFSETS {
                    // Check if the write address could be a BST pointer write
                    if event.address & 0xFFF == bst_offset & 0xFFF {
                        bst_writes.entry(bst_offset).or_default().push(event);
                    }
                }
            }
        }

        // Flag BST entries written multiple times (hook installation/restoration)
        for (&offset, writes) in &bst_writes {
            if writes.len() >= 2 {
                let service_name = BST_OFFSETS
                    .iter()
                    .find(|(_, o)| *o == offset)
                    .map(|(n, _)| *n)
                    .unwrap_or("Unknown");

                findings.push(
                    Finding::new(
                        "timetravel",
                        Severity::High,
                        &format!("BST hook installation detected: {}", service_name),
                        &format!(
                            "Service '{}' (BST+0x{:X}) was written {} times. \
                             Multiple writes indicate hook installation \
                             (original→hook→possibly restore pattern).",
                            service_name,
                            offset,
                            writes.len(),
                        ),
                    )
                    .with_confidence(0.85)
                    .with_details(serde_json::json!({
                        "service": service_name,
                        "bst_offset": format!("0x{:X}", offset),
                        "write_count": writes.len(),
                        "first_write_pc": format!("0x{:016X}", writes[0].pc),
                        "first_write_ts": writes[0].timestamp_ns,
                        "last_write_pc": format!("0x{:016X}", writes.last().unwrap().pc),
                        "last_write_ts": writes.last().unwrap().timestamp_ns,
                    }))
                    .with_recommendation(
                        "Trace shows BST pointer being overwritten. Analyze the writer PC \
                         to identify the hooking module.",
                    ),
                );
            }
        }

        findings
    }

    fn detect_hook_sequence(&self, events: &[TraceEvent]) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Look for classic hook sequence: read BST entry, write BST entry (save + replace)
        let mut i = 0;
        while i + 1 < events.len() {
            let ev = &events[i];
            let next = &events[i + 1];

            // Pattern: MemoryRead from BST offset followed closely by MemoryWrite to same offset
            if ev.event_type == EventType::MemoryRead
                && next.event_type == EventType::MemoryWrite
                && (ev.address & 0xFFF) == (next.address & 0xFFF)
                && next.timestamp_ns - ev.timestamp_ns < 1_000_000
            // Within 1ms
            {
                let offset = ev.address & 0xFFF;
                if let Some(&(service, _)) = BST_OFFSETS.iter().find(|(_, o)| *o == offset) {
                    findings.push(
                        Finding::new(
                            "timetravel",
                            Severity::Critical,
                            &format!("Hook install sequence: read+write {} at same offset", service),
                            &format!(
                                "Classic hook pattern detected: read original pointer for '{}' \
                                 (save) immediately followed by write (replace) at same BST offset. \
                                 Time delta: {} ns. Writer PC: 0x{:016X}.",
                                service,
                                next.timestamp_ns - ev.timestamp_ns,
                                next.pc,
                            ),
                        )
                        .with_confidence(0.92)
                        .with_details(serde_json::json!({
                            "service": service,
                            "read_pc": format!("0x{:016X}", ev.pc),
                            "write_pc": format!("0x{:016X}", next.pc),
                            "read_value": format!("0x{:016X}", ev.value),
                            "write_value": format!("0x{:016X}", next.value),
                            "time_delta_ns": next.timestamp_ns - ev.timestamp_ns,
                        }))
                        .with_recommendation(
                            "Time-travel trace captures hook installation in progress. \
                             The writer PC identifies the hooking driver.",
                        ),
                    );
                }
            }
            i += 1;
        }

        findings
    }

    fn detect_timing_anomalies(&self, events: &[TraceEvent], header: &TraceHeader) -> Vec<Finding> {
        let mut findings = Vec::new();

        if events.len() < 2 {
            return findings;
        }

        // Check for timestamp gaps (may indicate trace tampering)
        let total_duration = header.end_timestamp.saturating_sub(header.start_timestamp);
        if total_duration == 0 {
            return findings;
        }

        let mut max_gap: u64 = 0;
        let mut gap_start_idx = 0;
        for i in 1..events.len() {
            let gap = events[i]
                .timestamp_ns
                .saturating_sub(events[i - 1].timestamp_ns);
            if gap > max_gap {
                max_gap = gap;
                gap_start_idx = i - 1;
            }
        }

        // Flag if largest gap > 50% of total trace duration
        if max_gap > total_duration / 2 && total_duration > 1_000_000 {
            findings.push(
                Finding::new(
                    "timetravel",
                    Severity::Medium,
                    "Suspicious timing gap in execution trace",
                    &format!(
                        "Largest gap between events is {} ns ({:.1}% of total trace). \
                         Gap occurs at event index {}. May indicate trace splicing or \
                         hidden execution.",
                        max_gap,
                        (max_gap as f64 / total_duration as f64) * 100.0,
                        gap_start_idx,
                    ),
                )
                .with_confidence(0.60)
                .with_details(serde_json::json!({
                    "max_gap_ns": max_gap,
                    "total_duration_ns": total_duration,
                    "gap_percentage": (max_gap as f64 / total_duration as f64) * 100.0,
                    "gap_at_index": gap_start_idx,
                })),
            );
        }

        findings
    }
}

impl Detector for TimeTravelDetector {
    fn name(&self) -> &str {
        "timetravel"
    }

    fn detect(&self, target_path: &Path) -> Result<Vec<Finding>, DetectorError> {
        self.detect_context(&crate::ScanContext::load(target_path)?)
    }
    fn detect_context(&self, context: &crate::ScanContext) -> Result<Vec<Finding>, DetectorError> {
        let data = context.shared_bytes();
        let mut findings = Vec::new();

        // Check if this is an AGTT trace file
        let header = match Self::parse_header(&data) {
            Some(h) => h,
            None => return Ok(findings), // Not a trace file, skip
        };

        let events = Self::parse_events(&data, &header);

        if events.is_empty() {
            return Ok(findings);
        }

        findings.extend(self.detect_bst_access_patterns(&events));
        findings.extend(self.detect_hook_sequence(&events));
        findings.extend(self.detect_timing_anomalies(&events, &header));

        // Summary
        if !findings.is_empty() {
            findings.push(
                Finding::new(
                    "timetravel",
                    Severity::Info,
                    "Time-travel trace analysis summary",
                    &format!(
                        "Analyzed {} trace events over {} ns. Architecture: {}. \
                         Found {} suspicious patterns.",
                        events.len(),
                        header.end_timestamp.saturating_sub(header.start_timestamp),
                        match header.architecture {
                            0 => "x86_64",
                            1 => "ARM64",
                            _ => "Unknown",
                        },
                        findings.len(),
                    ),
                )
                .with_details(serde_json::json!({
                    "total_events": events.len(),
                    "trace_duration_ns": header.end_timestamp.saturating_sub(header.start_timestamp),
                    "version": header.version,
                    "architecture": header.architecture,
                })),
            );
        }

        Ok(findings)
    }
}
