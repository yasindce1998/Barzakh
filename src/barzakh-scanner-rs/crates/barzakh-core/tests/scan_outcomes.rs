use barzakh_core::detector::DetectorError;
use barzakh_core::{BarzakhScanner, Detector, DetectorStatus, Finding, ScanContext, ScanStatus};
use std::path::Path;

struct Broken;
impl Detector for Broken {
    fn name(&self) -> &str {
        "broken"
    }
    fn detect(&self, _: &Path) -> Result<Vec<Finding>, DetectorError> {
        panic!("regression panic")
    }
}

#[test]
fn bad_inputs_never_pass() {
    let dir = tempfile::tempdir().unwrap();
    let empty = dir.path().join("empty");
    std::fs::write(&empty, []).unwrap();
    let mut scanner = BarzakhScanner::new(None);
    for path in [dir.path().join("missing"), empty, dir.path().to_path_buf()] {
        let result = scanner.scan(&path, None);
        assert_eq!(result.status, ScanStatus::Failed);
        assert_eq!(result.exit_code(), 2);
        assert!(!result.errors.is_empty());
    }
    let context = ScanContext::from_bytes("empty".into(), Vec::new());
    assert_eq!(
        scanner.scan_context(&context, None).status,
        ScanStatus::Failed
    );
}

#[cfg(unix)]
#[test]
fn special_files_are_rejected_without_reading() {
    assert!(ScanContext::load(Path::new("/dev/zero")).is_err());
}

#[test]
fn errors_and_unknown_detectors_are_explicit() {
    let context = ScanContext::from_bytes("fixture".into(), vec![0; 4096]);
    let mut scanner = BarzakhScanner::new(None);
    scanner.register_detector(Box::new(Broken));
    let result = scanner.scan_context(&context, Some(&["entropy", "broken"]));
    assert_eq!(result.status, ScanStatus::Partial);
    assert_eq!(result.exit_code(), 2);
    assert!(result
        .detector_runs
        .iter()
        .any(|r| r.status == DetectorStatus::Error));
    assert!(result.findings.iter().all(|f| f.detector != "broken"));
    assert_eq!(
        scanner.scan_context(&context, Some(&["typo"])).status,
        ScanStatus::Failed
    );
    assert_eq!(
        scanner
            .scan_context(&context, Some(&["entropy", "typo"]))
            .status,
        ScanStatus::Partial
    );
}

#[test]
fn snapshot_survives_file_removal_for_every_builtin() {
    let file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(file.path(), [0u8; 4096]).unwrap();
    let context = ScanContext::load(file.path()).unwrap();
    let hash = context.sha256().to_owned();
    file.close().unwrap();
    let result = BarzakhScanner::new(None).scan_context(&context, None);
    assert_eq!(
        result.status,
        ScanStatus::Complete,
        "{:?}",
        result.detector_runs
    );
    assert_eq!(result.input_sha256.as_deref(), Some(hash.as_str()));
    assert!(result.detector_runs.len() > 100);
}

#[test]
fn failed_json_reports_preserve_outcomes_and_html_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let mut scanner = BarzakhScanner::new(None);
    scanner.scan(&dir.path().join("missing"), None);
    let output = dir.path().join("result.json");
    scanner
        .generate_report(&output, barzakh_core::ReportFormat::Json)
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&std::fs::read(&output).unwrap()).unwrap();
    assert_eq!(json["status"], "failed");
    assert!(scanner
        .generate_report(&output, barzakh_core::ReportFormat::Html)
        .is_err());
}

#[test]
fn limit_is_enforced_before_scan() {
    let file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(file.path(), [1u8; 128]).unwrap();
    assert!(ScanContext::load_with_limit(file.path(), 64).is_err());
    let context = ScanContext::from_bytes("too-big".into(), vec![1; 128]);
    let mut scanner = BarzakhScanner::new(None);
    scanner.max_image_bytes = 64;
    assert_eq!(
        scanner.scan_context(&context, None).status,
        ScanStatus::Failed
    );
}
