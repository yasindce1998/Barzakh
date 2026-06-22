use std::fs;
use std::path::Path;

use tempfile::TempDir;

use barzakh_core::{BarzakhScanner, Finding, ReportFormat, Severity};

fn create_test_firmware(dir: &Path, name: &str, content: &[u8]) -> std::path::PathBuf {
    let path = dir.join(name);
    fs::write(&path, content).unwrap();
    path
}

fn dummy_firmware() -> Vec<u8> {
    let mut data = vec![0u8; 4096];
    data[0..2].copy_from_slice(b"MZ");
    data
}

fn firmware_with_high_entropy_region() -> Vec<u8> {
    let mut data = vec![0u8; 8192];
    // Fill a region with pseudo-random (high-entropy) bytes
    for i in 0..4096 {
        data[4096 + i] = ((i * 7 + 13) % 256) as u8;
    }
    data
}

fn firmware_with_fv_header() -> Vec<u8> {
    let mut data = vec![0u8; 65536];
    // Place _FVH signature at offset 40 (FV header starts at 0)
    data[40..44].copy_from_slice(b"_FVH");
    // GUID at offset 0 (16 bytes)
    data[0..16].copy_from_slice(&[
        0xA1, 0x31, 0x1B, 0x5B, 0x62, 0x95, 0xD2, 0x11, 0x8E, 0x3F, 0x00, 0xA0, 0xC9, 0x69, 0x72,
        0x3B,
    ]);
    // FV length at offset 32 (u64 LE) = 0x10000
    data[32..40].copy_from_slice(&0x10000u64.to_le_bytes());
    // FV header length at offset 48 (u16 LE) = 56
    data[48..50].copy_from_slice(&56u16.to_le_bytes());
    data
}

fn firmware_with_bst_hook() -> Vec<u8> {
    let mut data = vec![0u8; 65536];
    // Place BST signature "BOOTSERV" at a page-aligned offset
    let bst_pos = 0x1000;
    let sig: u64 = 0x56524553_544F4F42; // "BOOTSERV"
    data[bst_pos..bst_pos + 8].copy_from_slice(&sig.to_le_bytes());

    // Write a function pointer outside DXE range at LoadImage (offset 0xC8)
    let hook_ptr: u64 = 0xDEAD_0000_BEEF_0000;
    let ptr_offset = bst_pos + 0xC8;
    data[ptr_offset..ptr_offset + 8].copy_from_slice(&hook_ptr.to_le_bytes());
    data
}

fn firmware_with_mbr_hook() -> Vec<u8> {
    let mut data = vec![0u8; 1024];
    // IVT entry for INT 13h at offset 0x4C (vector 0x13 * 4)
    // Point it to a suspicious high-memory address
    let hook_segment: u16 = 0x9FC0;
    let hook_offset: u16 = 0x0100;
    data[0x4C..0x4E].copy_from_slice(&hook_offset.to_le_bytes());
    data[0x4E..0x50].copy_from_slice(&hook_segment.to_le_bytes());
    // MBR boot signature at 510-511
    data[510] = 0x55;
    data[511] = 0xAA;
    data
}

fn agtt_trace_with_hook() -> Vec<u8> {
    let mut data = vec![0u8; 64 + 48 * 4];
    // AGTT header
    data[0..4].copy_from_slice(b"AGTT");
    data[4..6].copy_from_slice(&1u16.to_le_bytes()); // version
    data[6..8].copy_from_slice(&0u16.to_le_bytes()); // x86_64
    data[8..16].copy_from_slice(&4u64.to_le_bytes()); // 4 records
    data[16..24].copy_from_slice(&1000u64.to_le_bytes()); // start ts
    data[24..32].copy_from_slice(&100_000_000u64.to_le_bytes()); // end ts

    // Record 0: MemoryRead from BST LoadImage offset (0xC8)
    let rec0_off = 64;
    data[rec0_off..rec0_off + 8].copy_from_slice(&5000u64.to_le_bytes()); // timestamp
    data[rec0_off + 8] = 0; // MemoryRead
    data[rec0_off + 24..rec0_off + 32].copy_from_slice(&0x0700_00C8u64.to_le_bytes()); // address with 0xC8 low

    // Record 1: MemoryWrite to same BST offset (hook install)
    let rec1_off = 64 + 48;
    data[rec1_off..rec1_off + 8].copy_from_slice(&5500u64.to_le_bytes()); // timestamp (500ns later)
    data[rec1_off + 8] = 1; // MemoryWrite
    data[rec1_off + 24..rec1_off + 32].copy_from_slice(&0x0700_00C8u64.to_le_bytes());
    data[rec1_off + 32..rec1_off + 40].copy_from_slice(&0xDEAD_BEEFu64.to_le_bytes()); // value

    // Record 2: another write to same offset (second hook/restore)
    let rec2_off = 64 + 48 * 2;
    data[rec2_off..rec2_off + 8].copy_from_slice(&50_000_000u64.to_le_bytes());
    data[rec2_off + 8] = 1; // MemoryWrite
    data[rec2_off + 24..rec2_off + 32].copy_from_slice(&0x0700_00C8u64.to_le_bytes());

    // Record 3: function call
    let rec3_off = 64 + 48 * 3;
    data[rec3_off..rec3_off + 8].copy_from_slice(&90_000_000u64.to_le_bytes());
    data[rec3_off + 8] = 7; // FunctionCall

    data
}

// ============================================================
// Tests
// ============================================================

#[test]
fn test_scanner_creation_with_all_detectors() {
    let scanner = BarzakhScanner::new(None);
    assert_eq!(scanner.detector_count(), 30);
}

#[test]
fn test_scanner_has_expected_detectors() {
    let scanner = BarzakhScanner::new(None);
    let expected = [
        "pcr",
        "memory",
        "hook",
        "eventlog",
        "entropy",
        "secureboot",
        "runtime",
        "smm",
        "firmware_volume",
        "spi_integrity",
        "self_erasure",
        "mbr",
        "pcr_oracle",
        "firmware_differ",
        "attestation",
        "live",
        "timetravel",
        "symexec",
    ];
    for name in &expected {
        assert!(scanner.has_detector(name), "Missing detector: {}", name);
    }
}

#[test]
fn test_scan_empty_file() {
    let tmp = TempDir::new().unwrap();
    let target = create_test_firmware(tmp.path(), "empty.bin", &[]);

    let mut scanner = BarzakhScanner::new(None);
    let result = scanner.scan(&target, None);

    assert!(result.scan_info.duration_seconds >= 0.0);
    assert_eq!(result.summary.total_findings, result.findings.len());
}

#[test]
fn test_scan_dummy_firmware() {
    let tmp = TempDir::new().unwrap();
    let target = create_test_firmware(tmp.path(), "firmware.bin", &dummy_firmware());

    let mut scanner = BarzakhScanner::new(None);
    let result = scanner.scan(&target, None);

    assert!(result.scan_info.duration_seconds >= 0.0);
    assert!(result.scan_info.target.contains("firmware.bin"));
}

#[test]
fn test_scan_with_specific_detectors() {
    let tmp = TempDir::new().unwrap();
    let target = create_test_firmware(tmp.path(), "firmware.bin", &dummy_firmware());

    let mut scanner = BarzakhScanner::new(None);
    let result = scanner.scan(&target, Some(&["entropy", "mbr"]));

    for finding in &result.findings {
        assert!(
            finding.detector == "entropy" || finding.detector == "mbr",
            "Unexpected detector in findings: {}",
            finding.detector
        );
    }
}

#[test]
fn test_report_generation_json() {
    let tmp = TempDir::new().unwrap();
    let target = create_test_firmware(tmp.path(), "firmware.bin", &dummy_firmware());
    let report_path = tmp.path().join("report.json");

    let mut scanner = BarzakhScanner::new(None);
    scanner.scan(&target, None);
    scanner
        .generate_report(&report_path, ReportFormat::Json)
        .unwrap();

    let content = fs::read_to_string(&report_path).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
    assert!(parsed.get("timestamp").is_some());
    assert!(parsed.get("summary").is_some());
    assert!(parsed.get("findings").is_some());
}

#[test]
fn test_report_generation_html() {
    let tmp = TempDir::new().unwrap();
    let target = create_test_firmware(tmp.path(), "firmware.bin", &dummy_firmware());
    let report_path = tmp.path().join("report.html");

    let mut scanner = BarzakhScanner::new(None);
    scanner.scan(&target, None);
    scanner
        .generate_report(&report_path, ReportFormat::Html)
        .unwrap();

    let content = fs::read_to_string(&report_path).unwrap();
    assert!(content.contains("<!DOCTYPE html>"));
    assert!(content.contains("Barzakh Scanner Report"));
}

#[test]
fn test_report_generation_markdown() {
    let tmp = TempDir::new().unwrap();
    let target = create_test_firmware(tmp.path(), "firmware.bin", &dummy_firmware());
    let report_path = tmp.path().join("report.md");

    let mut scanner = BarzakhScanner::new(None);
    scanner.scan(&target, None);
    scanner
        .generate_report(&report_path, ReportFormat::Markdown)
        .unwrap();

    let content = fs::read_to_string(&report_path).unwrap();
    assert!(content.contains("# Barzakh Scanner Report"));
    assert!(content.contains("## Summary"));
}

#[test]
fn test_report_without_scan_fails() {
    let tmp = TempDir::new().unwrap();
    let report_path = tmp.path().join("report.json");

    let scanner = BarzakhScanner::new(None);
    let result = scanner.generate_report(&report_path, ReportFormat::Json);
    assert!(result.is_err());
}

#[test]
fn test_entropy_detector_high_entropy() {
    let tmp = TempDir::new().unwrap();
    let target = create_test_firmware(
        tmp.path(),
        "packed.bin",
        &firmware_with_high_entropy_region(),
    );

    let mut scanner = BarzakhScanner::new(None);
    let result = scanner.scan(&target, Some(&["entropy"]));

    let entropy_findings: Vec<&Finding> = result
        .findings
        .iter()
        .filter(|f| f.detector == "entropy")
        .collect();
    assert!(
        !entropy_findings.is_empty(),
        "Entropy detector should flag high-entropy region"
    );
}

#[test]
fn test_introspection_bst_hook_detection() {
    let tmp = TempDir::new().unwrap();
    let target = create_test_firmware(tmp.path(), "hooked.bin", &firmware_with_bst_hook());

    let mut scanner = BarzakhScanner::new(None);
    let result = scanner.scan(&target, Some(&["live"]));

    let hook_findings: Vec<&Finding> = result
        .findings
        .iter()
        .filter(|f| f.detector == "live" && f.severity >= Severity::High)
        .collect();
    assert!(
        !hook_findings.is_empty(),
        "Live detector should find BST hook pointing outside DXE range"
    );
}

#[test]
fn test_mbr_detector_ivt_hook() {
    let tmp = TempDir::new().unwrap();
    let target = create_test_firmware(tmp.path(), "mbr.bin", &firmware_with_mbr_hook());

    let mut scanner = BarzakhScanner::new(None);
    let result = scanner.scan(&target, Some(&["mbr"]));

    let mbr_findings: Vec<&Finding> = result
        .findings
        .iter()
        .filter(|f| f.detector == "mbr")
        .collect();
    assert!(
        !mbr_findings.is_empty(),
        "MBR detector should flag suspicious IVT hook"
    );
}

#[test]
fn test_timetravel_hook_detection() {
    let tmp = TempDir::new().unwrap();
    let target = create_test_firmware(tmp.path(), "trace.agtt", &agtt_trace_with_hook());

    let mut scanner = BarzakhScanner::new(None);
    let result = scanner.scan(&target, Some(&["timetravel"]));

    let tt_findings: Vec<&Finding> = result
        .findings
        .iter()
        .filter(|f| f.detector == "timetravel")
        .collect();
    assert!(
        !tt_findings.is_empty(),
        "Time-travel detector should find BST hook pattern in trace"
    );
}

#[test]
fn test_firmware_volume_detector() {
    let tmp = TempDir::new().unwrap();
    let target = create_test_firmware(tmp.path(), "fv.bin", &firmware_with_fv_header());

    let mut scanner = BarzakhScanner::new(None);
    let result = scanner.scan(&target, Some(&["firmware_volume"]));

    // Should parse without panicking; may or may not produce findings depending on checksum
    assert!(result.scan_info.duration_seconds >= 0.0);
}

#[test]
fn test_attestation_detector_on_fv() {
    let tmp = TempDir::new().unwrap();
    let target = create_test_firmware(tmp.path(), "fw.bin", &firmware_with_fv_header());

    let mut scanner = BarzakhScanner::new(None);
    let result = scanner.scan(&target, Some(&["attestation"]));

    // Attestation detector parses FV and evaluates trust scores
    assert!(result.scan_info.duration_seconds >= 0.0);
}

#[test]
fn test_scan_summary_counts() {
    let tmp = TempDir::new().unwrap();
    let target = create_test_firmware(tmp.path(), "hooked.bin", &firmware_with_bst_hook());

    let mut scanner = BarzakhScanner::new(None);
    let result = scanner.scan(&target, None);

    let expected_critical = result
        .findings
        .iter()
        .filter(|f| f.severity == Severity::Critical)
        .count();
    let expected_high = result
        .findings
        .iter()
        .filter(|f| f.severity == Severity::High)
        .count();

    assert_eq!(result.summary.critical_count, expected_critical);
    assert_eq!(result.summary.high_count, expected_high);
    assert_eq!(result.summary.total_findings, result.findings.len());
}

#[test]
fn test_bootkit_detected_flag() {
    let tmp = TempDir::new().unwrap();
    let target = create_test_firmware(tmp.path(), "hooked.bin", &firmware_with_bst_hook());

    let mut scanner = BarzakhScanner::new(None);
    let result = scanner.scan(&target, Some(&["live"]));

    // BST hook should trigger critical findings → bootkit_detected = true
    if result.summary.critical_count > 0 || result.summary.high_count >= 3 {
        assert!(result.summary.bootkit_detected);
    }
}

#[test]
fn test_corpus_validation() {
    let tmp = TempDir::new().unwrap();

    // Create a mini corpus: 1 malicious, 1 clean
    create_test_firmware(
        tmp.path(),
        "malicious_sample.bin",
        &firmware_with_bst_hook(),
    );
    create_test_firmware(tmp.path(), "clean_sample.bin", &dummy_firmware());

    let scanner = BarzakhScanner::new(None);
    let metrics = scanner.validate_against_corpus(tmp.path()).unwrap();

    assert_eq!(metrics.true_positives + metrics.false_negatives, 1);
    assert_eq!(metrics.true_negatives + metrics.false_positives, 1);
    assert!(metrics.true_positive_rate >= 0.0 && metrics.true_positive_rate <= 1.0);
    assert!(metrics.false_positive_rate >= 0.0 && metrics.false_positive_rate <= 1.0);
}

#[test]
fn test_finding_serialization() {
    let finding = Finding::new("test", Severity::High, "Test Finding", "Description")
        .with_confidence(0.9)
        .with_details(serde_json::json!({"key": "value"}))
        .with_recommendation("Fix it");

    let json = serde_json::to_string(&finding).unwrap();
    let deserialized: Finding = serde_json::from_str(&json).unwrap();

    assert_eq!(deserialized.detector, "test");
    assert_eq!(deserialized.severity, Severity::High);
    assert_eq!(deserialized.confidence, 0.9);
    assert_eq!(deserialized.recommendation.as_deref(), Some("Fix it"));
}

#[test]
fn test_severity_ordering() {
    assert!(Severity::Critical > Severity::High);
    assert!(Severity::High > Severity::Medium);
    assert!(Severity::Medium > Severity::Low);
    assert!(Severity::Low > Severity::Info);
}

#[test]
fn test_scan_performance() {
    let tmp = TempDir::new().unwrap();
    // 1MB firmware image
    let data = vec![0xCCu8; 1024 * 1024];
    let target = create_test_firmware(tmp.path(), "large.bin", &data);

    let mut scanner = BarzakhScanner::new(None);
    let result = scanner.scan(&target, None);

    assert!(
        result.scan_info.duration_seconds < 30.0,
        "Scan took {:.2}s, expected < 30s",
        result.scan_info.duration_seconds
    );
}

#[test]
fn test_parallel_scan_determinism() {
    let tmp = TempDir::new().unwrap();
    let target = create_test_firmware(tmp.path(), "firmware.bin", &firmware_with_bst_hook());

    let mut scanner1 = BarzakhScanner::new(None);
    let mut scanner2 = BarzakhScanner::new(None);

    let result1 = scanner1.scan(&target, None);
    let result2 = scanner2.scan(&target, None);

    // Same input should produce same findings count
    assert_eq!(
        result1.summary.total_findings,
        result2.summary.total_findings
    );
    assert_eq!(
        result1.summary.critical_count,
        result2.summary.critical_count
    );
}
