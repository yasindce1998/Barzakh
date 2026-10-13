# Barzakh: Attack Scenario Builder

> **Last Updated:** 2026-10-13 | **Applies to:** `barzakh-adversary scenario`

---

## 🎯 Overview

Single payloads test single detectors. Real bootkits are **chains**: a DXE foothold installs SMM persistence, which in turn hooks runtime services. The scenario builder composes existing payload generators into multi-stage attack chains, materializes each stage in dependency order, scans each one, and reports a per-stage detection chain — verifying that *later stages are detected*, not just the first link.

Back to [README](../README.md).

---

## 🛠️ CLI

```bash
# List bundled and discovered scenarios
barzakh-adversary scenario list

# Show a scenario's definition
barzakh-adversary scenario show smm-persistence-chain

# Run a scenario: generate stage payloads into DIR, scan each, report the chain
barzakh-adversary scenario run --name smm-persistence-chain --output ./scenario-out

# Run a custom scenario from a TOML file
barzakh-adversary scenario run --file custom.toml --output ./scenario-out
```

### `scenario list`

```text
Scenario                Stages   MITRE                       Description
blacklotus-chain        3        T1542.001, T1542.003        Secure Boot bypass → bootkit install → persistence
smm-persistence-chain   3        T1542.001, T1542.003        DXE foothold → SMM persistence → runtime hook
mobile-bootchain        3        T1542.001                   Mobile boot chain compromise (bootloader → GKI → Trusty)
```

Bundled scenarios live in `scenarios/*.toml`:

| File | Chain |
|------|-------|
| `scenarios/blacklotus-chain.toml` | Secure Boot bypass → bootkit install → persistence |
| `scenarios/smm-persistence-chain.toml` | DXE foothold → SMM persistence → runtime hook |
| `scenarios/mobile-bootchain.toml` | Mobile boot chain: bootloader → kernel (GKI) → TEE |

---

## 📝 Scenario Format (TOML)

```toml
[scenario]
name = "smm-persistence-chain"
description = "DXE foothold → SMM persistence → runtime hook"
architecture = "x86_64"
mitre = ["T1542.001", "T1542.003"]

[[stages]]
payload = "boot_services_hook"
label = "foothold"

[[stages]]
payload = "smm_timing_anomaly"
label = "smm-persistence"
depends_on = ["foothold"]

[[stages]]
payload = "runtime_services_hook"
label = "runtime-hook"
depends_on = ["smm-persistence"]
```

| Field | Meaning |
|-------|---------|
| `scenario.name` | Scenario identifier (used by `--name`) |
| `scenario.description` | Human-readable chain summary |
| `scenario.architecture` | `x86_64` or `aarch64` — selects payload generators |
| `scenario.mitre` | ATT&CK technique tags surfaced in reports |
| `stages[].payload` | Any payload name from `barzakh-adversary list` |
| `stages[].label` | Stage identifier other stages reference |
| `stages[].depends_on` | Labels that must run before this stage (DAG edges) |

Stages form a dependency DAG. `scenario run` topologically sorts the stages and executes them in dependency order; a cycle is a validation error.

---

## ▶️ Scenario Run

`scenario run --name <name> --output DIR`:

1. Parses and validates the scenario (unknown payloads, cycles, missing labels)
2. Generates each stage's payload into `DIR` **in dependency order**
3. Scans each stage image with the full detector set
4. Prints the per-stage detection chain table
5. **Verifies later stages are detected** — the run fails if a dependent stage lands undetected

### Output Layout

```text
./scenario-out/
├── 01-foothold.bin          # boot_services_hook stage image
├── 01-foothold.json         # scan report for stage 1
├── 02-smm-persistence.bin   # smm_timing_anomaly stage image
├── 02-smm-persistence.json
├── 03-runtime-hook.bin
├── 03-runtime-hook.json
└── chain-summary.json       # per-stage detections + verdict
```

### Visual Chain Rendering

The CLI prints the chain with per-stage detection results:

```text
=== Scenario: smm-persistence-chain (x86_64) ===
Description: DXE foothold → SMM persistence → runtime hook
MITRE: T1542.001, T1542.003

  ┌─[ foothold ]───────────────────────────────┐
  │ payload:  boot_services_hook               │
  │ detected: ✓ 2 findings (boot_services_hook,│
  │              trampoline)                   │
  └──────────────────────┬─────────────────────┘
                         │ depends_on
  ┌─[ smm-persistence ]──▼─────────────────────┐
  │ payload:  smm_timing_anomaly               │
  │ detected: ✓ 1 finding (smm_timing)         │
  └──────────────────────┬─────────────────────┘
                         │ depends_on
  ┌─[ runtime-hook ]─────▼─────────────────────┐
  │ payload:  runtime_services_hook            │
  │ detected: ✓ 1 finding (runtime_services)   │
  └────────────────────────────────────────────┘

Stage detection chain:
  Stage              Payload               Detected   Findings
  foothold           boot_services_hook    ✓          2
  smm-persistence    smm_timing_anomaly    ✓          1
  runtime-hook       runtime_services_hook ✓          1

VERDICT: PASS — all stages detected (3/3)
```

A stage that lands undetected is flagged `✗` and the verdict becomes `FAIL — detection gap at stage <label>`, exiting non-zero so CI can gate on it.

---

## 🔄 Usage in the Purple-Team Loop

Scenarios extend the single-payload loop (UC-O5 in [USECASES.md](USECASES.md)):

1. **Red:** add a new stage to a scenario (e.g. a capsule-abuse persistence link)
2. **Blue:** tune or add the detector that should catch it
3. **Validate:** `scenario run` must report `PASS` — every stage detected, in order
4. **Regress-proof:** CI runs bundled scenarios; a `FAIL` verdict blocks merge

Scenario chain reports also feed the [dashboard](DASHBOARD.md) (`GET /api/scenarios`) and pair with the [robustness benchmark](FUZZING.md) to measure how detection holds as each stage mutates.

## 📚 Related

- [FUZZING.md](FUZZING.md) — robustness benchmarking
- [USECASES.md](USECASES.md) — purple-team iteration
- [INTEL.md](INTEL.md) — ATT&CK technique mappings
- [README](../README.md) — project overview
