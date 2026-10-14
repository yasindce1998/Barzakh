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
