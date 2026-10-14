# Barzakh: Flagship Platform Roadmap

> **Last Updated:** 2026-10-14 | **Status:** Planning — post-v0.5 platform expansion

---

## 🧭 Vision

Barzakh today is a **point-in-time scanner plus adversary workbench**: 132 detectors, 127 payloads, threat intel, ML, REST dashboard, and a monitoring agent — all validated against a synthetic corpus inside CI. The goal of this roadmap is to evolve it into a **continuous, memory-safe, hardware-verified firmware security platform** that:

1. Runs **continuously** (kernel telemetry, not periodic scripts)
2. Targets the **2025–2026 threat frontier** (early-boot DMA, NVRAM state tampering)
3. Is written in **pure Rust end-to-end** — user space, kernel (eBPF), and firmware (`no_std` UEFI)
4. Extends safely at fleet scale (**Wasm-sandboxed policies**)
5. Is **reproducible by anyone** (QEMU + OVMF + swtpm cyber range in CI)

And it eliminates the two architectural sins of legacy tools (CHIPSEC-era): point-in-time Python audits, and Ring 0 helper drivers that expose raw physical memory to user space (a BYOVD-class attack surface of their own making).

Back to [README](../README.md).

---

## 📊 Baseline (October 2026)

Everything below **exists and is green in CI** — this plan builds on it, it does not replace it:

| Layer | Assets |
|-------|--------|
| Offense (C) | 27 EDK II BootkitPkg modules (simulation-only, kill-switched), LegacyBootkit 16-bit |
| Offense (Rust) | 127 payload generators, scenario chains, robustness benchmark, fuzzing harness |
| Defense | 132 detectors, risk scoring, SARIF/CSV/ECS/CEF/LEEF reporting, baselines |
| Intel | IOC feeds (47 bundled), YARA-subset engine, MISP export, ATT&CK mapping |
| ML | Isolation forest + logistic classifier (AUC 0.99), `nlp_strings` |
| Services | barzakh-server (REST + dashboard, :8420), barzakh-agent (SIEM forwarding), SQLite history + KB |
| Range (partial) | `qemu-run.sh`, `qemu-e2e.sh`, `capture-baseline.sh` already use `q35,smm=on` + swtpm |
| Detectors relevant to Pillar 2 | `iommu_dmar`, `acpi_integrity`, `pcr`, `pcr_replay`, `pcr_oracle`, `eventlog`, `secureboot*`, `s3_bootscript`, `smm_timing` |

---

## 🗺️ Plan Overview

Sequencing rationale: **Phase 0** pays down credibility debt (real firmware, security of the platform itself). **Phase 1** targets the threat frontier first because it extends the existing detector/payload architecture with no new infrastructure. **Phase 2** (cyber range) lands early because every later phase needs it as its test bench. Phases 3–5 then build the new runtime surfaces.

| Phase | Pillar | Theme | Effort | Depends on |
|-------|--------|-------|--------|------------|
| 0 | — | Foundation & credibility hardening | M | — |
| 1 | 2 | Early-boot DMA + NVRAM threat frontier | M | 0 |
| 2 | 5 | QEMU/OVMF/swtpm cyber-range in CI | M | 0 |
| 3 | 1 | eBPF Ring 0 → Ring -2 runtime telemetry | L | 2 |
| 4 | 4 | Wasm policy & forensics engine | M | 0 |
| 5 | 3 | `no_std` Rust UEFI & Standalone MM research | XL | 2 |

Effort scale: **S** < 1 week · **M** 1–3 weeks · **L** 3–6 weeks · **XL** a quarter or more.

---

## Phase 0 — Foundation & Credibility (hardening)

The platform must be trustworthy before it is extended.

| # | Work item | Detail | Acceptance criteria |
|---|-----------|--------|---------------------|
| 0.1 | **Real-firmware corpus** | Add a second clean corpus of real vendor images (UEFI capsules, coreboot builds, vendor BIOS dumps) + ground-truth malicious set (LoJax-style droppers, BlackLotus samples) under `test-data/real/` | FPR ≤ 10% measured on real clean firmware; known-bootkit TPR ≥ 90%; documented in TESTING.md |
| 0.2 | **ML anomaly hardening** | Structure-aware features (FV layout, PE header distances), per-family thresholds or ensemble verdict; feeds off 0.1 | iforest TPR ≥ 0.80 at FPR ≤ 0.02 on corpus |
| 0.3 | **Platform security** | API-key auth on `barzakh-server`, TLS/reverse-proxy docs, HMAC-signed agent webhooks | Auth enforced by default; webhook signature verified by a test receiver |
| 0.4 | **Async scan API** | `POST /api/scans` → `{"scan_id"}` + background execution with `status: running→complete` polling (store schema gains a status column) | Large-image scans don't block the event loop; dashboard polls |
| 0.5 | **Intel ingestion** | STIX/TAXII feed ingestion + auto-refresh of IOC feeds (`intel-update.sh` grows a real transport) | A public STIX feed round-trips into scan findings |
| 0.6 | **First tagged release** | Tag `v0.5.0`; exercise the release workflow (4 triple-named binaries, binstall metadata); publish Docker images | `cargo binstall barzakh-scanner` works |
| 0.7 | **Scheduled fuzzing CI** | Weekly `schedule:` job running the fuzz harness, filing detector-gap issues automatically | One full cycle completes green |
| 0.8 | **YARA parity** | Regex strings, `pe` module subset, external variables | A curated pack of real-world rules runs unmodified |

---

## Phase 1 — Pillar 2: The 2025–2026 Threat Frontier

> **Threat rationale:** the frontier has moved from legacy boot-sector hooks to two pre-OS blind spots: (a) firmware that enables VT-d/AMD-Vi in setup but fails to enforce DMA remapping during the PEI→early-DXE window (CVE-2025-11901, CVE-2025-14302 class), and (b) Secure Boot bypasses via vulnerable Microsoft-signed UEFI binaries and custom PE loaders performing arbitrary NVRAM writes (CVE-2025-3052, CVE-2024-7344 class).

Extends existing assets: `iommu_dmar` detector, `dmar_neuter` / `asus_nvram_redirect` payloads, the PCR replay engine (`pcr_oracle`), and `eventlog`.

### Defense modules (`barzakh-core/src/detectors/`)

| Module | Detects | Implementation notes |
|--------|---------|---------------------|
| `dmar_enforcement` (extends `iommu_dmar`) | DMAR table present but RMRR/protected-region coverage never activated before `ExitBootServices` | Parse ACPI DMAR (already partially done); additionally scan the DXE dependency graph / dispatch order in firmware images for evidence that DMA-protection drivers ran pre-handoff; flag "IOMMU enabled in setup, no enforcement artifacts" |
| `ivrs_table` | AMD-Vi (IVRS) tampering — remap-hole creation, missing unity mappings | Mirror of the DMAR work for `IVRS` ACPI table structure + integrity |
| `nvram_verifier` | Silent Secure Boot downgrades and rogue DXE loads: live UEFI variable state (`PK`, `KEK`, `db`, `dbx`, `BootOrder`, `SysPrepOrder`) cross-checked against the TPM 2.0 event log (`tcg_efi_specid_event`, `PCR[0–7]` extends) | Combines the existing `pcr_replay` engine with efivarfs dumps (`/sys/firmware/efi/efivars`) or image-extracted NVRAM; deterministic replay: variable writes must appear as measured events — an unmeasured `db` write is a finding |
| `pe_loader_bypass` | CVE-2024-7344-class custom PE loaders: signed UEFI binaries loading unsigned payloads with hand-rolled loaders | Extend existing PE analysis: signed parent + unsigned child mapping pattern, non-standard image mapping (no `LoadImage` telemetry in event log) |

### Offense modules (`barzakh-adversary/src/payloads/`)

| Payload | Models |
|---------|--------|
| `dma_window_bypass` | PCIe DMA write into DXE structures before `ExitBootServices` (targets the PEI→DXE unprotected window) |
| `dmar_remap_hole` | Forged DMAR with unity-mapped physical ranges (extends `dmar_neuter`) |
| `nvram_silent_downgrade` | `db`/`dbx` mutation absent from the TCG event log |
| `signed_loader_chain` | Signed-binary → custom-loader → unsigned-payload chain (CVE-2024-7344 emulation) |

### Acceptance criteria
- All four detectors fire on their paired payloads and stay silent on the Phase 0 real-firmware corpus (FPR budget respected).
- Scenario chains `dma-preboot-chain` and `nvram-downgrade-chain` added to `scenarios/` and validated end-to-end.
- Regression corpus E2E gate stays ≥ 80% TPR / ≤ 10% FPR with the new detectors included.

---

## Phase 2 — Pillar 5: Cyber-Range CI Harness

> Anyone must be able to reproduce the full attack-and-detect loop without touching physical hardware.

| Component | Role | Implementation notes |
|-----------|------|---------------------|
| **QEMU (`q35`, `smm=on`)** | Full x86_64 emulation: TSEG SMRAM locking, ICH9 SPI controller, PCIe topology | Already proven by `capture-baseline.sh` — promote to a first-class crate |
| **Patched OVMF** | Reproducible UEFI image with toggleable implants (vulnerable `SwSmiHandler`, unlocked S3 script, DXE protocol hook, Phase 1 DMA/NVRAM faults) | Build via a `RangeKitPkg` DSC that wraps the existing BootkitPkg modules behind build flags; containerize the EDK II toolchain |
| **swtpm** | TPM 2.0 root-of-trust emulation for `PCR[0–7]` extends and attestation mismatch tests | Already integrated in scripts; move under the range API |
| **`barzakh-range` runner** (new binary or `barzakh-adversary range` subcommand) | Boots a minimal Linux kernel in QEMU, triggers Ring -2 exploits via APMC port `0xB2`, dumps memory/PCR state, and asserts the Barzakh agent/scanner catches the anomaly | Declarative test manifest (TOML, consistent with scenarios); exit code drives CI |

### Acceptance criteria
- `barzakh-range up --suite ring-2` reproduces attack → detect → assert in one command, headless, < 10 minutes.
- A dedicated GitHub Actions job boots the range on every push and nightly.
- The range demonstrates at least one *intentional miss* (kill-switched implant variant) to prove the assertion path can fail.

---

## Phase 3 — Pillar 1: Continuous Ring 0 → Ring -2 Telemetry (Rust + eBPF)

> Replace point-in-time register polling with an always-on kernel sensor — **without** shipping a BYOVD-class raw-memory driver.

### 3a. SMI jitter profiler (`crates/barzakh-ebpf/`, new)

- Built on **aya** (pure-Rust eBPF: no libbpf, no clang, memory-safe loader — itself a statement against legacy Ring 0 helpers).
- **Per-core SMI latency histogram:** perf-event attachment to the MSR PMU (`msr/smi/`, `msr/aperf/`, `msr/mperf/`) on all logical cores, plus `bpf_ktime_get_ns` gap analysis around context-switch and IRQ-entry tracepoints. Normal SMI residency is 10–100 µs; an SMM implant walking OS page tables or scanning physical RAM blows cache state and pushes residency past **300 µs** — the sensor streams per-core histograms over a **BPF ring buffer** and alerts on threshold breach.
- eBPF can't execute `rdmsr` directly — the MSR PMU route is what keeps this a pure-eBPF design (no kernel module, no `/dev/mem`).

### 3b. Zero-trust runtime services guard

- Hash the in-memory `EFI_RUNTIME_SERVICES` table (`GetVariable`, `SetVariable`, `ConvertPointer`, …) — Linux already exposes runtime table pointers via `/sys/firmware/efi/runtime/` — on every S3 sleep/wake transition.
- Audit chipset lock bits on the same cadence: `SMRAMC.D_LCK`, `BIOS_CNTL.BLE` (PCI config 00:1f.0 via sysfs), `MSR_SMM_FEATURE_CONTROL` (via the msr PMU/devfs), all from **unprivileged-or-narrowly-privileged user space** — never a raw-memory IOCTL.
- Integrated into `barzakh-agent` as a new telemetry source with SIEM export (ECS/CEF/LEEF events already implemented).

### Acceptance criteria
- The Phase 2 range boots a guest with the sensor loaded; a simulated SMM implant (inflated SMI handler work) trips the latency alert within one SMI.
- A real-hardware pilot (one lab board) runs the guard for 72 h with zero false SMI alerts at the chosen threshold.
- No new kernel modules, no `/dev/mem`, no writable physical-memory IOCTLs anywhere in the tree (CI-checked).

---

## Phase 4 — Pillar 4: Wasm Policy & Forensics Engine

> Firmware forensics policies today are brittle root-running Python scripts. Barzakh's extensibility ladder is TOML rules → IOC feeds → YARA → ML; Wasm is the top rung: **hot-reloadable, memory-sandboxed, fleet-distributable** detection logic.

- **New crate `crates/barzakh-policy/`** embedding **wasmi** (pure-Rust interpreter — consistent with the zero-C-dependency ethos, unlike a Cranelift JIT).
- **Host ABI (`barzakh-policy-abi`):** versioned, capability-scoped host functions — read image bytes/windows, query parsed structures (FV tree, ACPI tables, event log), emit findings with severity. No clock, no network, no filesystem: strict sandbox.
- **Policy authors write Rust**, compile to a `.wasm` target, and ship modules to `barzakh-server` / `barzakh-agent` / Kubernetes DaemonSets; policies hot-reload without restart.
- **Signed policies:** ed25519 signatures over module hashes; the server/agent refuse unsigned modules outside an explicit dev mode.
- Reference policies shipped as examples: unvalidated `gBS` callouts in `EFI_FV_FILETYPE_MM` PE32+ binaries, S3 Boot Script opcode audits, hardware lock-baseline enforcement — i.e., the checks that would otherwise hardcode into detectors.
- **Verification harness:** each policy runs inside the Phase 2 cyber range before promotion (attack-and-detect as CI for policies).

### Acceptance criteria
- A rule authored in Rust → compiled → signed → hot-loaded into a running server adds a detection with zero downtime.
- Policy evaluation overhead ≤ 1 ms per 1 MB of image on commodity hardware.
- A malicious policy attempting out-of-sandbox access is terminated with a clean error, proven by a negative test.

---

## Phase 5 — Pillar 3: Pure-Rust `no_std` UEFI & Standalone MM (the Patina era)

> The firmware industry is migrating from C/EDK II toward pure-Rust cores (Patina and allied efforts). The Ring -2 vulnerability class shifts from buffer overflows to **FFI and confused-deputy boundaries** between legacy C SMM drivers and Rust components. Barzakh should own the offensive *and* defensive research tooling for that boundary.

- **New Rust firmware package** (sibling to BootkitPkg, e.g. `src/RustKitPkg/`) targeting `x86_64-unknown-uefi` (tier-2), using `r_efi` for bindings; built with the same kill-switch discipline (simulation-first, opt-in functional mode, time-bomb, air-gap).
- **Offense:** `no_std` DXE/SMM implants modeling CommBuffer confused-deputy abuse across the C↔Rust boundary — attacker-controlled `CommBuffer` sizes, aliasing, and TOCTOU between validation and use.
- **Defense — SMRAM canary & trap-page allocator:** a Rust `Standalone MM` driver prototype that:
  - places unmapped guard pages around the SMM save-state map (`SMBASE + 0xFC00`),
  - seeds canary structures at SMRAM region boundaries,
  - traps unauthorized dereferences **before** `RIP`/`CR3` corruption is achievable, logging the faulting address to a protected log page.
- **Fuzzing the boundary:** structure-aware CommBuffer fuzzing of the C↔Rust FFI seam (extends the existing protocol fuzzing harness), running continuously in the Phase 2 range.
- Every module remains simulation-only by default; hardware flashing stays behind the existing LAB_TESTING.md gates.

### Acceptance criteria
- A Rust DXE module boots inside range OVMF and is detectable by the scanner (new detector for the Rust-UEFI module signature/binary pattern).
- The canary/trap-page driver demonstrably catches a simulated CommBuffer overrun in QEMU (fault logged, SMI handler survives).
- At least one C↔Rust confused-deputy pattern found by the boundary fuzzer is documented as a detection rule.

---

## 🔗 Dependency Graph

```
Phase 0 (hardening)
   ├──▶ Phase 1 (DMA + NVRAM frontier)      ──┐
   ├──▶ Phase 4 (Wasm policy)                │
   └──▶ Phase 2 (cyber range) ──▶ Phase 3 (eBPF telemetry)
                            └───▶ Phase 5 (no_std UEFI / Standalone MM)
                                            ◀── Phase 1 payloads run in the range
```

- Phase 1 and Phase 4 proceed independently after Phase 0.
- Phase 2 is the shared test bench: Phases 3 and 5 both consume it.
- Phase 1's new payloads/scenarios become Phase 2's first range suites.

---

## 📈 Consolidated Success Metrics

| Metric | Current | Target | Phase |
|--------|---------|--------|-------|
| Clean corpus | synthetic only | + real vendor firmware set | 0.1 |
| iforest TPR / FPR @ corpus | 0.62 / 0.01 | ≥ 0.80 / ≤ 0.02 | 0.2 |
| Server auth / signed webhooks | none | enforced by default | 0.3 |
| Reproducible attack-detect loop | scripts, manual | one command, CI-gated | 2 |
| Runtime SMI telemetry | none | per-core histogram, ≤ 1 SMI to alert | 3 |
| Detection-rule deploy latency | binary release | hot-reload ≤ seconds, sandboxed | 4 |
| Rust firmware modules | 0 | canary/trap-page Standalone MM driver in range | 5 |
| Raw-memory kernel attack surface | none | still none (CI-enforced) | all |

---

## ⚠️ Risk Register

| Risk | Mitigation |
|------|------------|
| eBPF/aya kernel-version fragmentation | Feature-detect at load; fall back to perf-stat sampling; pin minimum kernel (e.g. 5.15 LTS) |
| QEMU SMI/TSEG emulation gaps | Treat range as regression bench, not ground truth; Phase 3 pilot includes real hardware |
| EDK II + Rust toolchain friction (`no_std` UEFI) | Isolate in RustKitPkg behind a separate DSC; keep C BootkitPkg as the stable path |
| Wasm sandbox escape / ABI churn | wasmi interpreter (no JIT), versioned ABI, signed modules, negative tests in CI |
| Real-firmware licensing | Distribute only hashes + fetch scripts, never vendor images |
| Scope creep across 5 pillars | Phase gates with the acceptance criteria above; nothing advances without its gate |

---

## 📚 Documentation Deliverables

Each phase ships with docs in the house style (contract-first, like DASHBOARD.md/AGENT.md):

| Doc | Phase |
|-----|-------|
| `docs/RUNTIME_TELEMETRY.md` — eBPF sensor config, ABI, SIEM events | 3 |
| `docs/CYBER_RANGE.md` — range suites, manifests, CI job | 2 |
| `docs/WASM_POLICY.md` — policy ABI, signing, hot-reload | 4 |
| `docs/RUST_UEFI.md` — RustKitPkg build modes, kill-switches, boundary fuzzing | 5 |
| `docs/DMA_PROTECTION.md` + `docs/NVRAM_VERIFIER.md` — new detector contracts | 1 |

---

*This roadmap is a living document — update the baseline table and metrics as phases land.*
