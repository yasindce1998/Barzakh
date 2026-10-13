# Barzakh: Machine-Learning Analysis

> **Last Updated:** 2026-10-13 | **Applies to:** `ml` CLI, `ml_anomaly` and `nlp_strings` detectors

---

## 🧠 Overview

Barzakh pairs its 132 deterministic detectors with a lightweight, dependency-free ML layer for problems where fixed heuristics underperform: novel implants that match no known signature, and obfuscated string content that simple pattern rules miss. Everything is implemented in pure Rust — no Python runtime, no external model files beyond the trained JSON.

| Component | Technique | Purpose |
|-----------|-----------|---------|
| Feature extraction | Global entropy, printable ratio, PE/MZ counts, high-entropy windows, string stats | Turn a binary into a feature vector |
| `ml_anomaly` detector | Isolation forest | Flag unusual firmware images with no labeled data |
| Binary classifier | Logistic regression (gradient descent) | Malicious vs. benign, trained on a corpus |
| `nlp_strings` detector | String-sequence NLP analysis | Obfuscation indicators, dual-use API sequences, encoded shellcode |

Back to [README](../README.md).

---

## 🔬 Feature Extraction

Every image (or corpus sample) is reduced to a fixed feature vector:

| Feature | Description | Bootkit signal |
|---------|-------------|----------------|
| Log2 size | Base-2 logarithm of image size | Implanted blobs appended to small firmware |
| Global entropy | Shannon entropy over all bytes | Packed/encrypted payload blobs |
| Printable ratio | Fraction of printable ASCII | Implanted shellcode vs. legitimate code/data mix |
| Zero ratio | Fraction of zero bytes | Missing/erased regions typical of tampering |
| MZ count | Occurrences of `MZ` headers | Injected PE/COFF modules at unusual offsets |
| FVH count | UEFI firmware-volume header signatures | Rogue firmware volumes |
| Max run length | Longest run of identical bytes | Padding/erased regions |
| High-entropy window | Max/mean entropy over sliding windows | Localized encryption that global entropy dilutes |
| String count | Extracted ASCII strings | Anomalous string densities typical of implants |

Features feed both the isolation forest and the logistic-regression classifier.

---

## 🌲 Isolation-Forest Anomaly Detection (`ml_anomaly`)

The isolation forest flags images whose feature vectors are *easy to isolate* — few random splits suffice to separate them from the training population. This requires no labels, making it the first line of defense against novel implants:

- Trained on a population of known-good firmware profiles
- Scores each scan target with an anomaly score in `[0, 1]`
- Emits a finding when the score exceeds the model's threshold
- Severity is proportional to the score distance above threshold

Because it is unsupervised, `ml_anomaly` runs on every scan by default once a model has been trained and registered.

---

## 📈 Logistic-Regression Classifier

A supervised binary classifier (malicious vs. benign) trained on corpus features via batch gradient descent:

1. `barzakh-adversary corpus` generates labeled malicious + clean pairs
2. Features are extracted per sample
3. Weights are fitted by gradient descent (fixed learning rate, L2 regularization)
4. The trained model emits a probability; ≥ 0.5 (configurable) → malicious

The classifier complements the deterministic detectors: where a signature detector asks *"is this BlackLotus?"*, the classifier asks *"does this look like any implant we've seen?"*.

---

## 💬 NLP String Analysis (`nlp_strings`)

The `nlp_strings` detector applies sequence analysis to extracted strings:

| Indicator | Example |
|-----------|---------|
| Obfuscation markers | Long runs of non-ASCII, XOR-key artifacts, string stacking |
| Dual-use API sequences | Consecutive runtime/driver API names in unusual order (e.g. `AllocatePool` → `CopyMem` → `SetVirtualAddressMap` chains typical of hooks) |
| Base64/hex shellcode strings | Decodable blobs whose decoded entropy exceeds code-like thresholds |

---

## 🏋️ Training Workflow

```
┌───────────────────┐      ┌──────────────────┐      ┌─────────────────────┐
│ barzakh-adversary │─────▶│ Feature          │─────▶│ Model training      │
│ corpus --output   │      │ extraction       │      │ ┌─────────────────┐ │
│ ./corpus          │      │ (entropy, PE,    │      │ │ isolation forest│ │
│ (malicious +      │      │  strings, ...)   │      │ │ + logistic      │ │
│  clean pairs)     │      └──────────────────┘      │ │   regression    │ │
└───────────────────┘                                │ └─────────────────┘ │
                                                     └──────────┬──────────┘
                                                                │
                                            ┌───────────────────▼──────────────────┐
                                            │ ml train --corpus DIR                │
                                            │        --output model.json           │
                                            └───────────────────┬──────────────────┘
                                                                │
                                     ┌──────────────────────────┼─────────────────────┐
                                     ▼                          ▼                     ▼
                            ┌────────────────┐        ┌────────────────┐      ┌───────────────┐
                            │ ml evaluate    │        │ ml_anomaly     │      │ classifier    │
                            │ (TPR/FPR/AUC)  │        │ detector runs  │      │ scores scans  │
                            └────────────────┘        │ on every scan  │      └───────────────┘
                                                      └────────────────┘
```

### Train

```bash
# 1. Generate a labeled corpus
barzakh-adversary corpus --output ./corpus

# 2. Train the model
barzakh-scanner ml train --corpus DIR --output model.json

# With a custom corpus directory:
barzakh-scanner ml train --corpus ./corpus --output model.json
```

### Evaluate

```bash
# 3. Measure quality (TPR, FPR, confusion matrix)
barzakh-scanner ml evaluate --corpus DIR --model model.json
```

```text
Corpus:        255 samples (128 malicious, 127 clean)
Isolation forest:  TPR 0.62  FPR 0.01
Logistic regression: TPR 0.86  FPR 0.00  AUC 0.99
Confusion matrix (classifier):
              predicted malicious  predicted benign
  actual malicious        110                 18
  actual benign             0                127
```

(Numbers from the bundled corpus generator; retrain on your own firmware corpus for deployment-relevant metrics.)

Retrain whenever the corpus grows — the adversary's payload generators evolve alongside detectors (see UC-O5 in [USECASES.md](USECASES.md)).

---

## 🗂️ Model Format Notes

`model.json` is a plain JSON document — versioned, portable, and diff-friendly:

```json
{
  "format": "barzakh-ml-model",
  "version": 1,
  "trained_at": "2026-10-13T09:00:00Z",
  "features": ["log2_size", "entropy", "printable_ratio", "zero_ratio", "mz_count",
               "fvh_count", "max_run_length", "high_entropy_window", "string_count"],
  "isolation_forest": {
    "trees": [/* serialized split/leaf nodes */],
    "subsample_size": 256,
    "normalizer": {/* per-feature min/max scaling */},
    "feature_ranges": [/* training feature ranges for out-of-range penalties */]
  },
  "logistic_regression": {
    "weights": [1.24, -0.51, 2.03, 0.87, 3.11, 2.45, -0.33, 0.19, 1.05],
    "bias": -1.72,
    "trained_on": 255,
    "epochs": 500,
    "final_loss": 0.083
  },
  "anomaly_threshold": 0.87,
  "corpus_stats": {"samples": 255, "malicious": 128, "benign": 127}
}
```

| Field | Purpose |
|-------|---------|
| `features` | Ordered feature names — vectors must match at inference time |
| `isolation_forest` | Serialized trees, feature normalization, and training ranges |
| `logistic_regression` | Fitted weights/bias and training metadata |
| `anomaly_threshold` | Data-driven anomaly cutoff (95th percentile of clean training scores) |
| `corpus_stats` | Provenance: what the model was trained on |

**Compatibility rule:** the scanner refuses to apply a model whose `features` list differs from the runtime extractor's — retrain after any feature-set change.

---

## 📚 Related

- [FUZZING.md](FUZZING.md) — robustness benchmarking of detectors
- [USECASES.md](USECASES.md) — purple-team iteration loop (UC-O5)
- [README](../README.md) — project overview
