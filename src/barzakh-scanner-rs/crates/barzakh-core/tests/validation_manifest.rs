use barzakh_core::validation::{validate_manifest, CorpusManifest, CorpusSample};
use barzakh_core::{BarzakhScanner, ScanContext};

fn fixture(dir: &std::path::Path) -> CorpusManifest {
    std::fs::write(dir.join("clean.bin"), [0u8; 4096]).unwrap();
    let context = ScanContext::load(&dir.join("clean.bin")).unwrap();
    CorpusManifest {
        version: 1,
        provenance: "independent".into(),
        samples: vec![CorpusSample {
            path: "clean.bin".into(),
            sha256: context.sha256().into(),
            malicious: false,
            family: "ovmf".into(),
            vendor: "tianocore".into(),
            arch: "x86_64".into(),
            split: "test".into(),
            expected_detectors: Vec::new(),
        }],
    }
}

fn write(dir: &std::path::Path, manifest: &CorpusManifest) -> std::path::PathBuf {
    let path = dir.join("corpus.toml");
    std::fs::write(&path, toml::to_string(manifest).unwrap()).unwrap();
    path
}

#[test]
fn verifies_hashes_and_requires_classes_in_strict_mode() {
    let dir = tempfile::tempdir().unwrap();
    let mut manifest = fixture(dir.path());
    let mut scanner = BarzakhScanner::new(None);
    let path = write(dir.path(), &manifest);
    let report = validate_manifest(&mut scanner, &path, false, Some("test")).unwrap();
    assert_eq!(report.evaluated, 1);
    assert!(report.recall.is_none());
    assert!(validate_manifest(&mut scanner, &path, true, None).is_err());
    manifest.samples[0].sha256 = "0".repeat(64);
    let path = write(dir.path(), &manifest);
    assert!(validate_manifest(&mut scanner, &path, false, None).is_err());
}

#[test]
fn rejects_family_leakage_and_missing_required_samples() {
    let dir = tempfile::tempdir().unwrap();
    let mut manifest = fixture(dir.path());
    manifest.samples.push(CorpusSample {
        path: "missing.bin".into(),
        sha256: "1".repeat(64),
        malicious: true,
        family: "ovmf".into(),
        vendor: "tianocore".into(),
        arch: "x86_64".into(),
        split: "train".into(),
        expected_detectors: vec!["hook".into()],
    });
    let mut scanner = BarzakhScanner::new(None);
    let path = write(dir.path(), &manifest);
    assert!(validate_manifest(&mut scanner, &path, false, Some("test"))
        .unwrap_err()
        .to_string()
        .contains("leaks"));
    manifest.samples[1].family = "other".into();
    let path = write(dir.path(), &manifest);
    assert!(validate_manifest(&mut scanner, &path, true, None)
        .unwrap_err()
        .to_string()
        .contains("missing"));
    assert_eq!(
        validate_manifest(&mut scanner, &path, false, None)
            .unwrap()
            .skipped,
        ["missing.bin"]
    );
}

#[test]
fn expected_detector_not_applicable_is_a_miss_not_an_omission() {
    let dir = tempfile::tempdir().unwrap();
    let mut manifest = fixture(dir.path());
    manifest.samples[0].malicious = true;
    manifest.samples[0].expected_detectors = vec!["nvram_verifier".into()];
    let path = write(dir.path(), &manifest);
    let report = validate_manifest(&mut BarzakhScanner::new(None), &path, false, None).unwrap();
    assert_eq!(
        report.per_detector["nvram_verifier"]
            .confusion
            .false_negatives,
        1
    );
}
