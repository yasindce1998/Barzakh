# Changelog

All notable changes to the Barzakh firmware security platform.
Format based on [Keep a Changelog](https://keepachangelog.com/); the
project follows semantic versioning. Dates are ISO-8601.

## [Unreleased]

### Phase 0 — Foundation & credibility hardening

#### Added
- **Real-firmware corpus validation gate (0.1).** Pinned, SHA-256-verified
  real images (OVMF firmware from the Arch `edk2-ovmf` package,
  Microsoft-signed shim 15.8 boot loaders from Ubuntu's `shim-signed`)
  fetched by `scripts/fetch-real-corpus.sh`; `test-data/real/manifest.toml`
  documents every pin plus manual-placement slots for real malware
  samples (LoJax, BlackLotus — never auto-fetched). The
  `real_corpus` test enforces verdict FPR ≤ 10% on clean real images
  (currently 0% on all 9) and TPR ≥ 90% when malicious samples are
  present. Wired into CI.
- **ML anomaly hardening (0.2).** Four structure-aware features (content
  islands, binary content ratio, valid PE chains, FFS header count),
  dead-split avoidance in isolation trees, degenerate-range anomaly
  penalties, 98th-percentile thresholds, and Youden-J-calibrated
  classifier thresholds. Isolation forest on the corpus: TPR 0.993 at
  FPR 0.015 (requirement ≥ 0.80 at ≤ 0.02); classifier TPR 1.000 /
  AUC 1.000. CI-enforced by the `ml_anomaly_gate` test.
- **Platform security (0.3).** Optional API-key authentication on every
  `barzakh-server` `/api/*` endpoint (`--api-key` / `BARZAKH_API_KEY`,
  constant-time comparison, `/api/health` stays open; loud startup
  warning when unset — documented deviation from "on by default").
  HMAC-SHA256-signed agent webhooks (`X-Barzakh-Timestamp` /
  `X-Barzakh-Signature`) verified by a live test receiver. New
  `docs/DEPLOYMENT.md` with nginx/Caddy TLS termination and systemd
  units.
- **Async scan API (0.4).** `POST /api/scans` returns `202 Accepted`
  with a `running` scan id and executes on the blocking thread pool;
  status polling `running → complete | failed` with error messages.
  SQLite store gains `status`/`error` columns with in-place migration
  of pre-existing databases. Dashboard polls and shows scan status.
  Verified live: 4 MB OVMF submissions return in 9 ms, health probes
  stay at 5 ms mid-scan.
- **STIX 2.1 ingestion (0.5).** `barzakh-intel` parses STIX bundles
  (CISA/MISP/TAXII-shaped) and converts firmware-relevant indicators
  (SHA-256 hashes, file names) into native IOC feeds, with family
  attribution via `indicates` relationships. `barzakh-scanner intel
  stix` converts; `scripts/intel-update.sh --stix` grows a real
  transport (also fixes a pre-existing script syntax error).
- **Weekly fuzzing workflow (0.7).** `.github/workflows/fuzz-weekly.yml`
  runs protocol-aware fuzzing (dhcpv6, bmp, capsule, httpboot, tcg, hii)
  and the mutation/robustness harness weekly (Mondays 03:00 UTC) or on
  demand via `workflow_dispatch`. JSON reports are kept as 90-day
  artifacts and summarized into the run page. Detector gaps are filed
  as GitHub issues automatically — one issue per evading payload,
  deduplicated by title, persistent gaps get a weekly comment instead
  of duplicates; gap filing never fails the workflow. Iteration budgets
  are tuned from local measurements (protocol fuzzing is ~free; the
  harness gets iterations/20 since each payload mutation is a full
  detector sweep).
- **YARA parity (0.8).** The `barzakh-intel` YARA-subset engine now
  runs real-world rules unmodified: regex strings (`/…/` with
  ascii/wide/nocase), text modifiers (wide/nocase/fullword), multi-line
  hex bodies, occurrence counts (`#a`), `filesize` with KB/MB suffixes,
  a `pe` module subset (`is_pe`, `machine`, `subsystem`,
  `number_of_sections`, `timestamp`, `entry_point`, `characteristics`,
  `sections[n].name`, plus the standard constants), string operators
  (`contains`/`startswith`/`endswith`/`matches /regex/`), `of` set
  expressions with wildcards (`2 of ($a, $b)`, `2 of ($a*)`, `N% of
  them`), integer arithmetic and bitwise operators, rule tags,
  `private`/`global` prefixes, quote-aware `//` and `/* */` comment
  stripping, and external variables via `--define NAME=VALUE` (typed
  automatically; the scanned file's name is available as `filename`).
  Acceptance proven by the curated pack
  `intel-rules/packs/realworld-firmware.yar` — rules modeled on public
  research for LoJax, BlackLotus, MoonBounce, ESPectre and Bootkitty
  plus deployment-gated rules — which parses and fires on synthetic
  infected images while staying quiet on clean ones
  (`crates/barzakh-intel/tests/yara_parity.rs`).

### Changed
- Detector precision rebuilt on realistic structure (Phase 0.1 fallout):
  shared EDK2 varstore parser backing the secureboot/auth_variable
  detectors; PixieFail DHCPv6 option qualification; HECI triple-cluster
  RMW requirement; AMT SOL channel requiring port bytes *and* label;
  memory PE-in-runtime skipping the target's own header page; tightened
  SMM, self-erasure, microcode, voltage-glitch, ME-DMA, fTPM and
  entropy checks. All 10 real clean images scan verdict-clean.
- Isolation-forest anomaly cutoff moved from the 95th to the 98th
  percentile of clean training scores; classifier decision thresholds
  are calibrated per model instead of fixed at 0.5.
- `POST /api/scans` API contract: `201 complete` → `202 running` with
  polling (dashboard updated automatically).

### Fixed
- Quadratic symbolic-execution blowup eliminated (11.4 s → 215 ms on a
  4 MB OVMF image).
- `scripts/intel-update.sh` was unparseable (missing `)` in the
  `SCRIPT_DIR` command substitution).

### Phase 1 — pre-boot DMA & NVRAM threat frontier

#### Added
- Four detectors + four adversary payloads for the pre-boot attack
  surface: `dmar_enforcement` (Intel DMAR remapping-structure walk —
  RMRR unity mappings / full-memory remap holes, CVE-2025-11901/14302
  class), `ivrs_table` (AMD-Vi counterpart), `nvram_verifier`
  (authenticated-variable store cross-checked against the TCG event
  log — unmeasured Secure Boot variable writes, CVE-2025-3052/7344
  class, dbx-older-than-db downgrades), `pe_loader_bypass`
  (signed-loader-maps-unsigned-child-PE, CVE-2024-7344 class, with
  WX-section and certificate-table analysis). Payloads `dmar_remap_hole`,
  `dma_window_bypass`, `nvram_silent_downgrade`, `signed_loader_chain`;
  scenarios `dma-preboot-chain`, `nvram-downgrade-chain`. Docs:
  `docs/DMA_PROTECTION.md`, `docs/NVRAM_VERIFIER.md`.

### Phase 5 — pure-Rust `no_std` UEFI research package

#### Added
- `src/RustKitPkg`: a standalone Rust crate targeting
  `x86_64-unknown-uefi` (`r_efi`) with host-testable logic — modeling
  the C↔Rust confused-deputy boundary of the emerging Patina-era
  firmware stack. `commbuffer` (vulnerable double-fetch validation as an
  adversary/fuzzer oracle + hardened single-copy validation), `canary`
  (SMRAM canary & trap-page allocator with guard bands and a checksummed
  fault log), `mode` (kill-switch discipline mirroring BootkitPkg:
  simulation-first default, research-gated functional mode, time-bomb,
  air-gap). `rustkit-dxe` firmware binary boots under range OVMF
  (q35, `smm=on`, swtpm TPM 2.0) — proven by serial markers
  `BARZAKH-RUSTKIT-BOOTED`, `CANARY-SELFTEST-PASS`,
  `SMI-HANDLER-SURVIVED` (evidence in `docs/evidence/`). New
  `rust_uefi_module` detector (Rust-UEFI binary identification +
  CommBuffer TOCTOU rule) verified against the real compiled `.efi`;
  payloads `rustkit_implant`, `commbuffer_toctou`; scenario
  `rustkit-ffi-chain`; CommBuffer protocol fuzz seed.

### Phase 2 — cyber range (attack → detect → assert)

#### Added
- **`barzakh-scanner range up|list`** — a headless cyber range that
  reproduces the full firmware attack loop against real VM firmware:
  boots QEMU q35 (`smm=on`, swtpm TPM 2.0, OVMF pflash, `-display
  none`), deploys adversary payloads through a spec-conformant FAT16
  ESP attached as **removable USB storage** at
  `\EFI\BOOT\BOOTX64.EFI` (the LoJax/BlackLotus vector) — wrapped as a
  minimal *valid* x64 UEFI PE application the firmware actually
  `LoadImage()`s and `StartImage()`s — waits for boot-completion
  markers on serial, captures guest RAM via the QEMU monitor
  (`pmemsave`), scans every artifact with the full detector suite and
  asserts the expected detections. Exit code drives CI.
- Declarative TOML suites in `range/`: **`ring-2`** (armed
  `boot_services_hook`, `smm_timing_anomaly`, `pxe_icmp_overflow`
  implants must be detected on the deployed artifacts; the `hook`
  implant must also be found in the captured guest RAM
  (`expect_in_memory`); clean golden-boot control must stay
  verdict-clean) and **`intentional-miss`** (kill-switched dormant
  variants deployed through the exact same pipeline must NOT be
  detected — the falsifiable negative proving the assertion path can
  fail).
- Assertion semantics tuned for real firmware: expected/absent findings
  are asserted on the deployment artifacts (deterministic,
  implant-attributable); captured guest memory is real firmware state
  (genuine OVMF structures legitimately trip medium-severity
  heuristics) and is therefore recorded as live-range evidence and only
  ever positively asserted.
- Tool discovery without root: `BARZAKH_QEMU`/`BARZAKH_SWTPM`/
  `BARZAKH_OVMF_CODE`/`BARZAKH_OVMF_VARS` → `PATH` →
  `~/barzakh-tools` user prefix (installed by
  `scripts/install-range-tools.sh`) → system OVMF paths.
  `--dry-run`, `--keep`, `--skip-memory-scan`, `--json` modes.
- CI: a dedicated `range-test` GitHub Actions job (QEMU + OVMF + swtpm
  via apt) runs both suites live on pushes to `main` and nightly, with
  dry-run manifest validation on PRs. Docs: `docs/RANGE.md`.

### CVE coverage

#### Added
- **`pxe_icmp_overflow` detector + adversary payload for
  CVE-2026-97631 / GHSA-99cj-7hg9-mp4m** (CVSS 9.5): EDK II
  `NetworkPkg/UefiPxeBcDxe` copies oversized ICMP error messages past
  the fixed 504-byte `EFI_PXE_BASE_CODE_MODE.IcmpError` field during
  PXE boot — both `PxeBcIcmpErrorDpcHandle` (IPv4) and
  `PxeBcIcmp6ErrorDpcHandle` (IPv6) enforce no length limit and advance
  the destination by cumulative rather than per-fragment length —
  enabling unauthenticated network attackers to corrupt DXE memory and
  execute ring-0 code before Secure Boot. The detector requires a
  well-formed ICMPv4 error header with embedded IPv4 header, a
  sustained data run past the 504-byte field, and past-boundary
  corroboration (smashed adjacent mode structure or a fake-event
  signature); verified quiet on the 9 clean real-firmware images. A
  dormant payload variant and a range case in both suites exercise the
  kill-switched path.

### Fixed (Phase 2 fallout)
- **Scanner OOM on large memory dumps eliminated.** The
  `s3_bootscript` integrity walk emitted one Finding per two bytes of
  zero-filled RAM (a 256 MB guest-RAM capture OOM'd past 13 GB of
  RSS). Zero runs are now skipped wholesale — erased memory is not a
  corrupted table — and integrity findings are capped; a length-0
  entry among non-zero bytes is still reported. Regression tests cover
  both behaviors, and the 256 MB capture now scans in ~60 s.

## [0.5.0] — 2026-10-12

### Added
- Platform crates: `barzakh-server` (REST API + dashboard),
  `barzakh-agent` (continuous tamper monitoring, ECS/CEF/LEEF SIEM
  export, webhooks), `barzakh-store` (SQLite history + knowledge base),
  `barzakh-intel` (IOC feeds, YARA-subset rules, ATT&CK mapping, MISP
  export), `barzakh-ml` (isolation-forest anomaly detection +
  logistic-regression classifier).
- Scenario framework: chained multi-stage attack emulation
  (DMA pre-boot chain, NVRAM downgrade chain, RustKit FFI chain).
- Protocol-aware fuzzing (`barzakh-scanner fuzz --protocol
  dhcpv6|bmp|capsule|httpboot|tcg|hii`) and a payload/robustness
  harness with detection-gap reporting.
- Telecom/satellite, Android boot, Apple/iOS, Windows and wireless
  firmware detector families — 131 detectors and 127 payloads at
  release time.
- Simulation-mode kill-switches, time-bombs and air-gap guards for all
  EDK II components; CI-enforced anti-CHIPSEC stance (no kernel
  modules, no `/dev/mem`, no raw-memory IOCTLs).

## [0.4.0] — 2026-09-02

### Added
- 14 detectors across DMA/IOMMU, Secure Boot, Apple/iOS, Windows,
  Android, and wireless firmware; matching adversarial payloads.
- Corrupted-baseline and SPI-region detector fixes; corpus FPR
  reporting corrected.

## [0.3.0] — 2026-08-18

### Added
- 16 telecom/satellite detectors and payloads; fuzzing harness;
  README/detector-count synchronization.

## [0.2.0] — 2026-07-30

### Added
- 9 Android boot-security modules covering 2026+ attack surfaces;
  clippy and corpus alignment fixes.

## [0.1.0] — 2026-07-15

### Added
- Initial public release: core scanner architecture (detector trait,
  parallel sweep, risk scoring, bootkit verdict), EDK II bootkit
  simulation components with FVB2/PCI/MSR persistence paths, first
  detector families (BlackLotus, LoJax, MoonBounce, CosmicStrand,
  MosaicRegressor), baseline diffing, SARIF/HTML/Markdown/CSV reporting.
