# Barzakh: Protocol-Aware Fuzzing Engine

> **Last Updated:** 2026-10-13 | **Applies to:** `barzakh-scanner fuzz`, `barzakh-adversary robustness`

---

## 🎯 Overview

Firmware parsers are a dominant source of real-world UEFI vulnerabilities (LogoFAIL, PixieFail, Bootkitty's GRUB parsing, CVE-2024-7344 reloader paths). Barzakh's fuzzing engine attacks *protocol-level* structure rather than raw bytes: it generates structurally valid message seeds for UEFI-relevant protocols, applies structure-aware mutations, and measures which parsers break — and, critically, which **detectors fail to notice**.

Two complementary harnesses exist:

| Harness | Binary | What it measures |
|---------|--------|------------------|
| Protocol-aware fuzzing | `barzakh-scanner fuzz` | Parser robustness + detection gaps on structured protocol inputs |
| Byte-level payload mutation | `barzakh-adversary robustness` | Detector TPR decay under payload mutation |

Back to [README](../README.md).

---

## 🧪 Protocol-Aware Fuzzing

```bash
barzakh-scanner fuzz --protocol dhcpv6 --iterations 5000 --output-dir ./fuzz-out
```

### Supported Protocols

| Protocol | Surface modeled | Real-world reference |
|----------|-----------------|----------------------|
| `dhcpv6` | DHCPv6 option parsing (network boot) | PixieFail (CVE-2023-45229+) |
| `bmp` | BitMap image parsing (logo/images) | LogoFAIL (CVE-2023-40238) |
| `capsule` | UEFI capsule update headers and payloads | CapsuleHijack module |
| `httpboot` | HTTP boot response/URI handling | Network stack parsing |
| `tcg` | TCG/TPM2 command structures | CVE-2023-1017/1018 |
| `hii` | HII (Human Interface Infrastructure) string/font packages | Setup/Config parsing |

### Structure-Aware Seed Generation

The engine does not mutate random bytes from nothing — it emits **structurally valid seeds** first: well-formed DHCPv6 solicit messages, correct capsule headers, valid BMP file tables. Mutations are then applied *relative to* that structure, so each test case remains parseable enough to reach deep code paths.

### Mutation Strategies

| Strategy | Effect |
|----------|--------|
| Bit flip | Single-bit corruption — checksum/CRC validation coverage |
| Byte insert | Shifts offsets — length-field consistency coverage |
| Length-field overflow | Sets length fields beyond buffer bounds — the classic firmware overflow class |
| Chunk duplicate | Repeats structural blocks — parser loop handling |
| Header truncate | Cuts headers short — missing-field handling |
| Magic corrupt | Replaces magic values — validation fallback behavior |

### Structural-Novelty Coverage Tracking

Instead of raw code coverage, the engine tracks **structural novelty**: a mutation that produces a previously-unseen structural state (e.g. `option_count > max`, `length > remaining_buffer`) is recorded as a new coverage point. This keeps iteration budgets focused on interesting states rather than byte-level churn.

### Detection-Gap Reporting

Every crash-inducing or anomaly-inducing input is **scanned with the full detector set**. The report lists inputs that caused parser anomalies yet produced no detector finding — the detection gaps:

```text
=== Fuzz Report: dhcpv6 (5000 iterations) ===
Structural states covered:  312 / 341
Crash-inducing inputs:      7
Anomaly-inducing inputs:    43

Detection gaps (anomaly inputs with NO detector finding): 5
  gap-001  length-field overflow in option 27 (IA_NA)
  gap-002  chunk-duplicated option 6 (domain list)
  ...
```

Gap outputs land in `--output-dir` for follow-up: feed them to detector development (UC-D5 in [USECASES.md](USECASES.md)).

---

## 🔁 Existing Mutation Harness (`fuzz --mutate`)

The byte-level mutation harness predates protocol-aware fuzzing and remains useful for quick checks:

```bash
barzakh-scanner fuzz --mutate --target fw.bin --iterations 1000 --output-dir ./fuzz-out
```

It applies the same mutation strategies to an arbitrary input binary rather than protocol seeds — useful for smoke-testing detector stability against corrupted firmware images.

---

## 📉 Robustness Benchmark

While the fuzzing engine probes parsers, the robustness benchmark probes **detectors**: how quickly does true-positive rate decay as payloads mutate away from their canonical form?

```bash
barzakh-adversary robustness --iterations 200
```

The benchmark:

1. Generates a canonical malicious payload (e.g. `trampoline`)
2. Applies byte-level mutations, one at a time, for N iterations
3. Scans each mutant with the full detector set
4. Measures TPR decay — the fraction of mutants still detected per mutation count

```text
=== Robustness Benchmark (200 iterations) ===
Payload            Iter 0     Iter 50    Iter 100   Iter 150   Iter 200
trampoline         100%       96%        88%        79%        71%
boot_services_hook 100%       98%        93%        90%        85%
pe_inject          100%       91%        77%        62%        48%   ← weak
```

**Interpretation:** a detector whose TPR decays steeply is signature-bound — it matches exact bytes rather than structure. Detector work should target the weak rows (structural validation, CRC checks, pointer-range analysis) exactly as described in UC-O4/UC-D5.

---

## 🔄 Workflow

```
┌────────────────┐    seeds     ┌──────────────┐   mutants    ┌───────────────┐
│ Protocol model │─────────────▶│ Mutation     │─────────────▶│ Parser +      │
│ (dhcpv6, bmp,  │              │ strategies   │              │ detector run  │
│  capsule, ...) │              └──────────────┘              └──────┬────────┘
└────────────────┘                                                   │
                                                        ┌────────────▼─────────────┐
                                                        │ Structural-novelty       │
                                                        │ coverage + detection-gap │
                                                        │ report (output-dir)      │
                                                        └────────────┬─────────────┘
                                                                     │
                                                       ┌─────────────▼──────────────┐
                                                       │ barzakh-adversary robustness│
                                                       │ (TPR decay measurement)    │
                                                       └────────────────────────────┘
```

## 📚 Related

- [ML.md](ML.md) — anomaly detection over fuzz outputs
- [SCENARIOS.md](SCENARIOS.md) — multi-stage attack chains
- [USECASES.md](USECASES.md) — detection-gap-driven development loop
- [README](../README.md) — project overview
