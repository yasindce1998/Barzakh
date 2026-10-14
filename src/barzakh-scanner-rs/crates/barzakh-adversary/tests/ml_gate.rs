//! ML anomaly-model gate (Phase 0.2 of docs/ROADMAP.md).
//!
//! Trains the combined model (isolation forest + logistic regression) on
//! the generated adversary corpus and enforces the acceptance criteria:
//! the isolation forest must reach TPR >= 0.80 at FPR <= 0.02, and the
//! classifier must reach TPR >= 0.90 at FPR <= 0.05.
//!
//! Ignored by default (corpus generation + training): run explicitly via
//! `cargo test -p barzakh-adversary -- --ignored ml_anomaly_gate`.

use barzakh_ml::train::TrainedModel;

#[test]
#[ignore]
fn ml_anomaly_gate() {
    let dir = tempfile::tempdir().unwrap();
    let files = barzakh_adversary::corpus::generate_corpus(dir.path()).unwrap();
    assert!(!files.is_empty(), "corpus should generate files");

    let model =
        TrainedModel::train_from_corpus(dir.path()).expect("model should train on the corpus");
    let report = model
        .evaluate_corpus(dir.path())
        .expect("evaluation should run on the corpus");

    eprintln!(
        "iforest: TPR {:.3} (TP {} FN {}) FPR {:.3} (FP {} TN {})",
        report.iforest_tpr,
        report.iforest_true_positives,
        report.iforest_false_negatives,
        report.iforest_fpr,
        report.iforest_false_positives,
        report.iforest_true_negatives
    );
    eprintln!(
        "classifier: TPR {:.3} FPR {:.3} AUC {:.3}",
        report.classifier_tpr, report.classifier_fpr, report.classifier_auc
    );

    assert!(
        report.iforest_tpr >= 0.80,
        "isolation-forest TPR {:.3} below 0.80",
        report.iforest_tpr
    );
    assert!(
        report.iforest_fpr <= 0.02,
        "isolation-forest FPR {:.3} above 0.02 ({} of {} benign flagged)",
        report.iforest_fpr,
        report.iforest_false_positives,
        report.iforest_true_negatives + report.iforest_false_positives
    );
    assert!(
        report.classifier_tpr >= 0.90,
        "classifier TPR {:.3} below 0.90",
        report.classifier_tpr
    );
    assert!(
        report.classifier_fpr <= 0.05,
        "classifier FPR {:.3} above 0.05",
        report.classifier_fpr
    );
}
