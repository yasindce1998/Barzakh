//! Real-firmware corpus validation (Phase 0.1 of docs/ROADMAP.md).
//!
//! Scans the real samples under `test-data/real/` and enforces
//! verdict-level precision on real-world images:
//!
//! * clean/ (pinned OVMF firmware + Microsoft-signed shim boot loaders):
//!   bootkit-verdict FPR must be <= 10%.
//! * malicious/ (manually placed real bootkit samples): verdict TPR must
//!   be >= 90%.
//!
//! The test skips (passes) when neither directory contains samples:
//! populate the clean corpus with `scripts/fetch-real-corpus.sh` and
//! place malicious samples manually (see test-data/real/manifest.toml).

use std::fs;
use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    // crates/barzakh-adversary -> barzakh-scanner-rs -> src -> repo root
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(4)
        .expect("repo root")
        .to_path_buf()
}

fn list_samples(dir: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let Ok(read_dir) = fs::read_dir(dir) else {
        return files;
    };
    for entry in read_dir.flatten() {
        let path = entry.path();
        if path.is_file() {
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if name.starts_with('.') || name == "README.md" {
                continue;
            }
            files.push(path);
        }
    }
    files.sort();
    files
}

#[test]
fn real_corpus_validation() {
    let root = repo_root();
    let clean = list_samples(&root.join("test-data").join("real").join("clean"));
    let malicious = list_samples(&root.join("test-data").join("real").join("malicious"));
    let strict = std::env::var("BARZAKH_REQUIRE_REAL_CORPUS").as_deref() == Ok("1");
    if strict {
        assert!(
            !clean.is_empty() && !malicious.is_empty(),
            "strict real-corpus validation requires both clean and malicious samples"
        );
    }
    let manifest: toml::Value =
        toml::from_str(&fs::read_to_string(root.join("test-data/real/manifest.toml")).unwrap())
            .unwrap();
    for (kind, samples) in [("clean", &clean), ("malicious", &malicious)] {
        let declared = manifest[kind].as_array().unwrap();
        if strict {
            assert_eq!(
                samples.len(),
                declared.len(),
                "missing or undeclared {kind} samples"
            );
        }
        for sample in samples {
            let name = sample.file_name().unwrap().to_str().unwrap();
            let entry = declared
                .iter()
                .find(|e| e["name"].as_str() == Some(name))
                .expect("sample must be declared");
            let expected = entry
                .get("sha256")
                .and_then(|s| s.as_str())
                .expect("present samples require a reviewed SHA-256 in the manifest");
            let context = barzakh_core::ScanContext::load(sample).unwrap();
            assert_eq!(context.sha256(), expected, "hash mismatch for {name}");
        }
    }

    if clean.is_empty() && malicious.is_empty() {
        eprintln!(
            "real corpus not present — skipping \
             (run scripts/fetch-real-corpus.sh to populate it)"
        );
        return;
    }

    let mut scanner = barzakh_core::BarzakhScanner::new(None);

    if !clean.is_empty() {
        let mut flagged = Vec::new();
        for path in &clean {
            let result = scanner.scan(path, None);
            assert_eq!(
                result.status,
                barzakh_core::ScanStatus::Complete,
                "incomplete real-corpus scan: {}",
                path.display()
            );
            if result.summary.bootkit_detected {
                flagged.push(path.display().to_string());
            }
        }
        let fpr = flagged.len() as f64 / clean.len() as f64;
        eprintln!(
            "clean corpus: {} files, {} flagged (FPR {:.1}%)",
            clean.len(),
            flagged.len(),
            fpr * 100.0
        );
        assert!(
            fpr <= 0.10,
            "real clean-firmware FPR {:.1}% exceeds 10%; flagged: {:?}",
            fpr * 100.0,
            flagged
        );
    }

    if !malicious.is_empty() {
        let mut missed = Vec::new();
        let mut detected = 0usize;
        for path in &malicious {
            let result = scanner.scan(path, None);
            assert_eq!(
                result.status,
                barzakh_core::ScanStatus::Complete,
                "incomplete real-corpus scan: {}",
                path.display()
            );
            if result.summary.bootkit_detected {
                detected += 1;
            } else {
                missed.push(path.display().to_string());
            }
        }
        let tpr = detected as f64 / malicious.len() as f64;
        eprintln!(
            "malicious corpus: {} files, {} detected (TPR {:.1}%)",
            malicious.len(),
            detected,
            tpr * 100.0
        );
        assert!(
            tpr >= 0.90,
            "real malicious-sample TPR {:.1}% below 90%; missed: {:?}",
            tpr * 100.0,
            missed
        );
    }
}
