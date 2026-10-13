# Barzakh: Machine-Learning Analysis

> **Last Updated:** 2026-10-13 | **Applies to:** `ml` CLI, `ml_anomaly` and `nlp_strings` detectors

---

## 🧠 Overview

Barzakh pairs its 121 deterministic detectors with a lightweight, dependency-free ML layer for problems where fixed heuristics underperform: novel implants that match no known signature, and obfuscated string content that simple pattern rules miss. Everything is implemented in pure Rust — no Python runtime, no external model files beyond the trained JSON.

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
| Global entropy | Shannon entropy over all bytes | Packed/encrypted payload blobs |
| Printable ratio | Fraction of printable ASCII | Implanted shellcode vs. legitimate code/data mix |
| PE/MZ counts | Occurrences of `MZ`/`PE\0\0` headers | Injected PE/COFF modules at unusual offsets |
| High-entropy window | Max/mean entropy over sliding 4 KiB windows | Localized encryption that global entropy dilutes |
| String stats | String count, mean length, charset distribution | Anomalous string densities typical of implants |

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
Corpus:        128 samples (64 malicious, 64 clean)
Isolation forest:  TPR 0.94  FPR 0.03
Logistic regression: TPR 0.97  FPR 0.02  AUC 0.99
Confusion matrix (classifier):
              predicted malicious  predicted benign
  actual malicious        62                  2
  actual benign            1                 63
```

Retrain whenever the corpus grows — the adversary's payload generators evolve alongside detectors (see UC-O5 in [USECASES.md](USECASES.md)).

---

## 🗂️ Model Format Notes

`model.json` is a plain JSON document — versioned, portable, and diff-friendly:

```json
{
  "format": "barzakh-ml-model",
  "version": 1,
  "trained_at": "2026-10-13T09:00:00Z",
  "features": ["global_entropy", "printable_ratio", "pe_count", "mz_count",
               "high_entropy_window_max", "high_entropy_window_mean",
               "string_count", "string_mean_length"],
  "isolation_forest": {
    "trees": 100,
    "subsample_size": 256,
    "threshold": 0.62,
    "nodes": [/* serialized split/leaf data */]
  },
  "logistic_regression": {
    "learning_rate": 0.1,
    "iterations": 500,
    "l2": 0.001,
    "weights": [1.24, -0.51, 2.03, 0.87, 3.11, 2.45, -0.33, 0.19],
    "bias": -1.72,
    "threshold": 0.5
  },
  "corpus_stats": {"samples": 128, "malicious": 64, "benign": 64}
}
```

| Field | Purpose |
|-------|---------|
| `features` | Ordered feature names — vectors must match at inference time |
| `isolation_forest` | Serialized trees + anomaly threshold |
| `logistic_regression` | Fitted weights/bias + classification threshold |
| `corpus_stats` | Provenance: what the model was trained on |

**Compatibility rule:** the scanner refuses to apply a model whose `features` list differs from the runtime extractor's — retrain after any feature-set change.

---

## 📚 Related

- [FUZZING.md](FUZZING.md) — robustness benchmarking of detectors
- [USECASES.md](USECASES.md) — purple-team iteration loop (UC-O5)
- [README](../README.md) — project overview
