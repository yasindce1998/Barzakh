# Barzakh Scanner

**An advanced firmware security research platform — built to hunt what antivirus can't see.**

Barzakh is a high-performance detection and red-team engine written in Rust that operates where traditional security tooling goes blind: below the OS, inside the silicon. It ships **132 detectors** and **127 adversarial payloads** spanning Ring 0 to Ring -4 — from UEFI DXE drivers through Intel ME, AMD PSP, ARM TrustZone, Apple Secure Enclave, and Android Verified Boot — plus platform services for threat intelligence (IOC feeds, YARA-subset rules, MISP export), machine-learning analysis, SQLite history and knowledge base, a REST API with web dashboard, and a continuous monitoring agent with SIEM forwarding. An automated fuzzing harness continuously discovers detector blind spots.

> **One scanner. Every boot chain. Every architecture.**
> x86_64 · AArch64 · RISC-V · Android · iOS/Apple Silicon · POWER · NVIDIA Tegra · Automotive · IoT

## Why Barzakh?

| | |
|---|---|
| **132 Detectors** | From UEFI Secure Boot to Intel ME manufacturing mode to iOS Secure Enclave |
| **127 Red-Team Payloads** | Generate realistic attack firmware on demand — rootkits, rollbacks, chain breaks |
| **Automated Fuzzing** | Continuous generate → scan → gap discovery loop finds what your detectors miss |
| **Full Chain Coverage** | Android (pKVM → DICE → GKI → Trusty) and iOS (iBoot → PPL → SEP → LocalPolicy) validated end-to-end |
| **Ring -3 to Ring -4** | Intel ME, AMD PSP/SMU, CPU microcode, voltage glitch, Rowhammer — nothing is out of scope |
| **Platform Services** | Threat intel, ML scoring, REST API + dashboard, monitoring agent — all in one workspace |
| **Zero Runtime Dependencies** | Pure Rust, single static binary, no Python/Java/Docker required |

## Detection Capabilities

### Core Detectors

| Detector | Technique | Targets |
|----------|-----------|---------|
| PCR Analysis | TPM measurement comparison | Tampered boot measurements |
| PCR Replay | Event log reconstruction | Forged PCR values |
| PCR Oracle | Statistical anomaly detection | Subtle measurement drift |
| Memory Scanner | Runtime memory analysis | Injected PE images in EfiRuntimeServicesCode |
| Hook Detection | Boot Services table inspection | Modified function pointers |
| Runtime Hooks | Runtime Services monitoring | Post-ExitBootServices persistence |
| Firmware Volume | FV structure validation | Malicious DXE driver injection |
| Firmware Differ | Binary diff against baseline | Unauthorized firmware modifications |
| Entropy Analysis | Shannon entropy profiling | Packed/encrypted payloads |
| Event Log | TCG event sequence analysis | Anomalous boot sequences |
| Secure Boot | Signature chain validation | Bypassed/disabled Secure Boot |
| SMM Detection | SMI handler analysis | SMM-based rootkits |
| SPI Integrity | Flash region verification | SPI flash persistence (LoJax-style) |
| MBR/VBR | Legacy boot sector analysis | MBR/VBR infectors |
| Introspection | Code flow analysis | Trampolines and code injection |
| Self-Erasure | Anti-forensics detection | Evidence destruction patterns |
| Symbolic Execution | Path constraint solving | Obfuscated trigger conditions |
| Time-Travel Debug | Execution trace replay | Hidden execution paths |

### Intel ME / Management Engine (Ring -3)

| Detector | Technique | Targets |
|----------|-----------|---------|
| HECI Traffic | HECI/MEI command analysis | Suspicious host-ME communication |
| ME SPI Region | ME region structure validation | Tampered ME firmware partitions |
| AMT/SOL | AMT provisioning state inspection | Unauthorized remote management |
| fTPM Integrity | TPM2 command stream analysis | Forged fTPM responses |
| ME Manufacturing Mode | Flash descriptor FITM bit inspection | ME stuck in manufacturing/debug mode |
| ME Version Chain | $MN2 manifest SVN chain analysis | ME firmware version rollback attacks |
| Boot Guard KM | Key Manifest / BPM structure + hash validation | Forged Boot Guard key manifests |
| CSME Update | Update capsule integrity + version continuity | CSME update tampering / version skipping |

### AMD PSP / SMU (Ring -3)

| Detector | Technique | Targets |
|----------|-----------|---------|
| AMD PSP | PSP directory/entry validation | Tampered AMD Platform Security Processor firmware |
| PSP Version Chain | PSP directory SVN chain analysis | PSP firmware version rollback |
| PSP Trustlets | PSP L2 directory entry type validation | Rogue trustlet / TA injection |
| SMU Firmware | SMU magic + signature + size validation | System Management Unit firmware tampering |
| PSP Secure Debug | Debug unlock token / policy detection | Unauthorized PSP debug access |

### Platform Security

| Detector | Technique | Targets |
|----------|-----------|---------|
| Intel Boot Guard | ACM/KM/BPM structure analysis | Boot Guard policy bypass, SVN rollback |
| Auth Variable | Authenticated variable validation | PK/KEK/db rollback, missing signatures |

### Boot Process Integrity

| Detector | Technique | Targets |
|----------|-----------|---------|
| LogoFAIL | BMP/image parser overflow detection | Malicious logo images triggering CVE-2023-40238 |
| PixieFail | DHCPv6/PXE option validation | Network boot stack exploits (CVE-2023-45229+) |
| BlackLotus | MOK/BCD manipulation detection | BlackLotus bootkit persistence |
| DXE Dispatcher | DEPEX section analysis | DXE load-order hijacking via dependency manipulation |
| PEI Implant | PEI Core/PEIM structure validation | Pre-EFI initialization phase rootkits |
| Capsule Update | Capsule header integrity checks | Firmware update mechanism abuse |

### Hardware/Bus Attacks

| Detector | Technique | Targets |
|----------|-----------|---------|
| CXL Device | CXL DVSEC/DMA range analysis | CXL.mem DMA attacks against system memory |
| Attestation | Remote attestation validation | Forged attestation evidence |
| Live Forensics | Runtime state analysis | Active bootkit indicators |

### ARM / TrustZone

| Detector | Technique | Targets |
|----------|-----------|---------|
| ARM TrustZone | OP-TEE TA header / SMC call / IMG4 analysis | TrustZone persistence, iBoot chain bypass |
| ARM TBBR | FIP header / NV counter / CoT hash validation | Trusted Board Boot chain-of-trust bypass |

### RISC-V

| Detector | Technique | Targets |
|----------|-----------|---------|
| OpenSBI | SBI extension table / mtvec / M-mode CSR analysis | OpenSBI firmware hooking, privilege escalation |
| PMP Bypass | PMP config / CSR write / NOP sled detection | Physical Memory Protection misconfiguration exploits |
| RISC-V BootROM | BootROM marker / boot chain analysis | BootROM compromise, embedded debug payloads |
| RISC-V Debug | Debug Module (DMI) / dcsr analysis | Unlocked M-mode debug access in production |

### Embedded & Specialty Platforms

| Detector | Technique | Targets |
|----------|-----------|---------|
| NVIDIA Tegra | BootROM/MB1 marker + Security Processor analysis | Tegra boot chain implants |
| NSP Command | NVDLA (NSP) command stream analysis | Unsigned DLA firmware, model tampering |
| IBM OPAL | OPAL/skiboot call table analysis | POWER hostboot tampering, call hooking |
| Automotive ECU | UDS/AUTOSAR reflash marker analysis | ECU backdoors, hidden diagnostic routines |
| CAN Injection | CAN frame / arbitration analysis | CAN bus injection backdoors |
| Zephyr IoT | MCUboot header / signature analysis | Zephyr signature bypass, image downgrade |
| IoT RTOS | FreeRTOS/ThreadX/Mbed image analysis | RTOS task table hooks |
| HPC Monitor | Cache-probe loop pattern analysis | BMC covert-channel exfiltration |

### Machine Learning

| Detector | Technique | Targets |
|----------|-----------|---------|
| ML Anomaly | Isolation forest over feature vectors | Novel implants matching no known signature |
| NLP Strings | String-sequence analysis | Obfuscated shellcode strings, dual-use API chains |

### Android Boot Chain

| Detector | Technique | Targets |
|----------|-----------|---------|
| Android AVB | Verified Boot rollback index validation | AVB version rollback attacks |
| Android VBMeta Chain | Full hash descriptor chain + rollback index consistency | vbmeta → boot/dtbo/vendor_boot integrity bypass |
| Android Init Verity | dm-verity/fs-verity + SELinux enforcement state | Disabled integrity for system/vendor partitions |
| Android Chain Validator | Unified pKVM → DICE → GKI → Trusty chain linkage | Any broken link in the Android trust chain |
| Android pKVM | Protected KVM hypervisor validation | pKVM escape / bypass attacks |
| Android DICE | DICE certificate chain / CDI derivation | Forged DICE attestation |
| Android GKI | Generic Kernel Image boot_signature validation | GKI tampering / unsigned kernel |
| Android Trusty | Trusty TEE structure / secure monitor markers | Trusty OS manipulation |

### iOS / Apple Silicon Boot Chain

| Detector | Technique | Targets |
|----------|-----------|---------|
| iOS iBoot | iBoot magic / IMG4 signature / entrypoint validation | iBoot patching, checkm8-style exploits |
| iOS PPL | Page Protection Layer lockdown markers (A12+) | PPL bypass for kernel page table manipulation |
| iOS Secure Enclave | SEP firmware / RTKit header / key attestation | SEP firmware tampering, key extraction |
| iOS LocalPolicy | Image4 `lpol` manifest / nonce-hash binding | Boot policy manipulation (1TR bypass) |
| iOS ANE Boot | Apple Neural Engine firmware / IMG4 `ane0` payload | ANE firmware injection |
| iOS TrustCache | Static/loadable trust cache validation | Unauthorized code execution via injected CDHashes |
| iOS AMFI | AMFI policy / entitlement enforcement | Code signing bypass |
| iOS KTRR | Kernel Text Read-only Region lockdown | KTRR bypass for kernel patching |
| iOS SEP Downgrade | SEP firmware version/nonce validation | SEP rollback attacks |

### Ring -4 / CPU Microarchitecture

| Detector | Technique | Targets |
|----------|-----------|---------|
| Microcode Injection | Intel MCU header / AMD equiv table analysis | Malicious CPU microcode updates in firmware |
| Spectre Gadgets | Indirect branch / CLFLUSH+RDTSC / barrier removal detection | Speculative execution side-channel gadgets |
| Thermal Covert | RAPL MSR / thermal throttle / P-state modulation analysis | Thermal/power covert channel patterns |
| Voltage Glitch | MSR 0x150 / DVFS / PMIC I2C write detection | Plundervolt/CLKscrew voltage fault injection |
| Debug Interface | DCI enable / JTAG TAP / DAP unlock / HDC MSR analysis | Unauthorized debug port exploitation |
| Rowhammer | CLFLUSH loop / TRR bypass / refresh suppression detection | Rowhammer exploitation patterns |

### 2024-2026 Threat Detectors

| Detector | Technique | Targets |
|----------|-----------|---------|
| Linux Bootchain | GRUB NOP-sled / vmlinuz integrity analysis | Bootkitty-style Linux UEFI bootkits |
| Reloader | PE-in-PE / signed loader exploitation | CVE-2024-7344 reloader.efi bypass |
| SBAT | SBAT generation counter validation | Secure Boot Advanced Targeting rollback |
| ESP Integrity | FAT32 / EFI bootloader path analysis | ESP partition persistence rootkits |
| Confidential VM | TDVF/SEV-SNP measurement validation | TDX injection, VMPL confusion attacks |
| BMC SPI | IPMI KCS / Redfish SPI targeting | BMC-to-host lateral movement |
| HTTP Boot | HTTP response + embedded PE detection | UEFI HTTP Boot MITM attacks |
| TPM Command | TPM2 command buffer size validation | CVE-2023-1017/1018 buffer overflow |
| WiFi DXE | Intel CNVi device / DXE dep-ex analysis | Wireless firmware DXE injection |
| Pluton | Pluton mailbox / DICE attestation analysis | Microsoft Pluton interception attacks |

## Installation

```bash
# Build from source
cd src/barzakh-scanner-rs
cargo build --release

# Binary outputs at:
#   target/release/barzakh-scanner    (defensive: scan, baseline, report, validate, detectors, history, kb, intel, ml, serve)
#   target/release/barzakh-adversary  (offensive: generate, list, corpus, validate, qemu, esp, scenario, robustness, fuzz)
#   target/release/barzakh-server     (REST API + web dashboard on port 8420)
#   target/release/barzakh-agent      (continuous monitoring with SIEM forwarding)
```

## Usage

### barzakh-scanner (Defensive)

```bash
# Scan a firmware image
barzakh-scanner scan --target firmware.bin

# Scan with baseline comparison
barzakh-scanner scan --target firmware.bin --baseline baseline.json

# Generate HTML report
barzakh-scanner report --target firmware.bin --format html --output report.html

# Run specific detectors only
barzakh-scanner scan --target dump.bin --scan-types pcr,memory,hook

# Validate detectors against test corpus
barzakh-scanner validate --corpus test-data/

# List all available detectors
barzakh-scanner detectors

# Show platform and build info
barzakh-scanner info

# Threat intelligence: apply IOC feeds and YARA-subset rules to a scan
barzakh-scanner scan --target firmware.bin --ioc-feed intel-feeds --yara intel-rules

# Review scan history (SQLite)
barzakh-scanner history list --db barzakh-history.sqlite

# Manage the firmware knowledge base
barzakh-scanner kb add --target fw.bin --vendor ASUS --device "PRIME Z690-A"
barzakh-scanner kb list

# Train and evaluate the ML layer
barzakh-scanner ml train --corpus ./corpus --output model.json
barzakh-scanner ml evaluate --corpus ./corpus --model model.json

# Export findings for a SIEM (SARIF/CSV/ECS/CEF/LEEF)
barzakh-scanner scan --target firmware.bin --format sarif --output findings.sarif

# Start the REST API + web dashboard
barzakh-scanner serve --port 8420 --db barzakh.db
```

### barzakh-agent (Monitoring)

```bash
# Continuous monitoring with SIEM forwarding (see docs/AGENT.md)
barzakh-agent --config agent.toml run
```

### barzakh-adversary (Offensive / Fuzzing)

```bash
# List all 127 adversarial payloads
barzakh-adversary list

# Generate payloads for a specific architecture
barzakh-adversary generate --arch x86_64

# Generate full test corpus (malicious + clean pairs)
barzakh-adversary corpus --output ./corpus

# Validate corpus against scanner (measure TPR/FPR)
barzakh-adversary validate --corpus ./corpus

# Run automated fuzzing harness (continuous gap discovery)
barzakh-adversary fuzz --iterations 10 --mutate --json

# Boot a payload in QEMU for live testing
barzakh-adversary qemu --payload trampoline

# Build ESP image for hardware testing
barzakh-adversary esp --payload dxe_persistence

# Run a multi-stage attack scenario chain (see docs/SCENARIOS.md)
barzakh-adversary scenario run --name smm-persistence-chain --output ./scenario-out

# Benchmark detector robustness under payload mutation
barzakh-adversary robustness --filter blacklotus --mutations 50
```

## Architecture

```
barzakh-scanner-rs/
├── Cargo.toml                    # Workspace root (8 crates, 4 binaries)
├── scenarios/                    # Bundled attack scenario TOMLs
└── crates/
    ├── barzakh-core/             # Library crate (detection engine)
    │   ├── src/
    │   │   ├── lib.rs            # Public API
    │   │   ├── scanner.rs        # Scan orchestration
    │   │   ├── baseline.rs       # Baseline configuration
    │   │   ├── scoring.rs        # Risk scoring
    │   │   ├── detector.rs       # Detector trait + types
    │   │   ├── detectors/        # 132 detection modules
    │   │   └── reports/          # HTML/JSON/Markdown/SARIF/CSV/ECS/CEF/LEEF reports
    │   └── tests/
    │       └── scanner_integration.rs
    ├── barzakh-cli/              # Binary crate (scanner + adversary + fuzz CLIs)
    │   └── src/
    │       ├── main.rs           # Scanner CLI (defensive commands)
    │       └── adversary_main.rs # Adversary CLI (offensive commands)
    ├── barzakh-adversary/        # Red-team payload & fuzzing engine
    │   ├── src/
    │   │   ├── lib.rs            # Payload trait + public API
    │   │   ├── payloads/         # 127 adversarial payload generators
    │   │   ├── harness/          # Automated fuzzing harness (generate → scan → gap → mutate)
    │   │   ├── validate/         # Scanner invocation + result comparison
    │   │   ├── corpus.rs         # Malicious/clean pair generator
    │   │   ├── scenario.rs       # Multi-stage attack scenario chains
    │   │   ├── robustness.rs     # Mutation robustness benchmarking
    │   │   └── deploy/           # ESP image builder + QEMU orchestration
    │   └── tests/
    │       └── integration.rs    # Generate → scan → assert detection
    ├── barzakh-intel/            # IOC feeds, YARA-subset engine, MISP export
    ├── barzakh-ml/               # Isolation forest + logistic regression + training
    ├── barzakh-store/            # SQLite scan history + firmware knowledge base
    ├── barzakh-server/           # REST API + web dashboard (barzakh-server)
    │   └── dashboard/            # Embedded HTML dashboard
    └── barzakh-agent/            # Continuous monitoring agent (barzakh-agent)
```

## Detection Metrics

| Metric | Target |
|--------|--------|
| True Positive Rate | >= 80% (CI-enforced) |
| False Positive Rate | <= 10% (CI-enforced) |
| Classifier AUC | >= 0.92 (measured 0.99 on the bundled corpus) |
| Mean Time to Detect | < 500ms |

## Development

```bash
# Run full test suite
cargo test

# Check formatting
cargo fmt --check

# Lint
cargo clippy -- -D warnings

# Security audit
cargo audit
```

## CI/CD

The workspace is gated by four CI jobs on every push:

- **Build Rust Scanner** — release build verification
- **Test Rust Scanner** — fmt + clippy + full test suite
- **Adversary Red-Team Tests** — payload generation + scanner detection validation + corpus E2E
- **Security Audit (Rust)** — dependency vulnerability scan via `cargo-audit`

## License

BSD-2-Clause-Patent
