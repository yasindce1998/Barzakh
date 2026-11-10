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
