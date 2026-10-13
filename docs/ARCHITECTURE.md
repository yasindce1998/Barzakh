# Barzakh: Technical Architecture & Implementation Details

This document outlines the in-depth technical specifications, system architecture, and low-level methodologies for Project Barzakh. 

## 1. System Architecture

The following sequence diagram illustrates the complete execution flow of the Barzakh environment from platform initialization to OS kernel transition.

```mermaid
sequenceDiagram
    participant FW as Firmware (SEC/PEI)
    participant DXE as DXE Phase
    participant Barzakh as Bootkit
    participant BDS as Boot Device Selection
    participant BL as OS Bootloader
    participant TPM as TPM 2.0 Module
    participant OS as OS Kernel

    FW->>DXE: Initialize hardware & drivers
    DXE->>Barzakh: Load malicious UEFI driver
    Barzakh->>DXE: Hook Boot Services Table
    DXE->>BDS: Hand off control
    BDS->>BL: Launch signed bootloader
    BL->>Barzakh: Invoke ExitBootServices()
    Barzakh->>BL: Intercept hook to patch kernel context in memory
    Barzakh->>TPM: Defensive attestation module records telemetry
    BL->>OS: Final transition to Ring-0 (Infection Complete)
```

## 2. Core Components Stack

| Component | Technology | Specification / Application |
| :--- | :--- | :--- |
| **Development Kit** | EDK II | Industry standard for UEFI firmware driver development. |
| **Languages** | C11, NASM, Rust | C for firmware-level implants, Rust for scanner and adversary tooling. |
| **Hypervisor** | QEMU + KVM | Hardware virtualization platform for running test environments. |
| **Firmware Payload** | OVMF | Specific Open Virtual Machine Firmware builds for deterministic reproducibility. |
| **Security Module** | TPM 2.0 | Hardware root of trust for PCR queries and event log measurements. |

### 2.1 Layered Architecture

```
┌───────────────────────────────────────────────────────────────────────┐
│  Layer 1: C Implants (BootkitPkg)                                     │
│  Real DXE drivers that model bootkit TTPs inside QEMU.                │
│  Simulation by default; functional mode opt-in via build flag.        │
├───────────────────────────────────────────────────────────────────────┤
│  Layer 2: Rust Adversary (barzakh-adversary)                          │
│  Red-team tooling that generates binary payloads, deploys them,       │
│  and validates scanner coverage in a closed loop.                     │
├───────────────────────────────────────────────────────────────────────┤
│  Layer 3: Rust Scanner (barzakh-core + barzakh-cli)                   │
│  Defense engine with 132 detectors (x86_64, ARM, RISC-V, Android,     │
│  Telecom, Satellite) — analyzes memory dumps and firmware images      │
│  for bootkit artifacts.                                               │
├───────────────────────────────────────────────────────────────────────┤
│  Layer 4: Platform Services                                           │
│  barzakh-intel (IOC feeds, YARA-subset rules, MISP export)            │
│  barzakh-ml (isolation forest + logistic regression)                  │
│  barzakh-store (SQLite history + knowledge base)                      │
│  barzakh-server (REST API + web dashboard, port 8420)                 │
│  barzakh-agent (continuous monitoring with SIEM forwarding)           │
└───────────────────────────────────────────────────────────────────────┘

Data flow:  Adversary generates payload → Scanner detects → Results validated
            C implants run in QEMU → Memory dump extracted → Scanner analyzes
```

## 3. Emulation Module: UEFI Hooking Mechanisms

### 3.1 DXE Phase Implantation
The bootkit payload is packaged as a standard UEFI DXE driver. It is introduced into the system either via simulated capsule updates or direct SPI flash modifications (strictly inside the hypervisor). 
* **Target:** Hooking the `EFI_BOOT_SERVICES` table.
* **Mechanism:** The driver locates the global `gBS` pointer and replaces function pointers such as `AllocatePool` and `CreateEvent` to track memory allocation of the legitimate OS bootloader (e.g., `bootmgfw.efi` or `GRUB`).

### 3.2 ExitBootServices Interception
To survive the transition from the UEFI environment to the OS kernel, the bootkit must intercept the hand-off.
* **Target:** `gBS->ExitBootServices`
* **Mechanism:** 
  1. The malware hooks `ExitBootServices`.
  2. When the OS bootloader calls this function to take control of memory mapping, the hook is triggered.
  3. The bootkit payload secures its own memory by marking it as `EfiRuntimeServicesCode` or `EfiRuntimeServicesData`, which the OS is legally bound to preserve.
  4. The hook attempts to patch the loaded OS kernel image in memory before returning execution to the original `ExitBootServices`.

### 3.3 Model Specific Register (MSR) Hooking
To emulate advanced stealth characteristics (e.g., hiding from EDRs running in Ring-0):
* **Target:** `IA32_LSTAR` or `IA32_SYSENTER_EIP` MSRs.
* **Mechanism:** The bootkit alters the system call handler routines, intercepting OS-level API calls before they reach the kernel, ensuring deep system introspection capabilities.

> **⚠️ Scope Justification:** MSR hooking extends beyond traditional bootkit persistence into rootkit-adjacent territory. This technique is included because real-world adversaries (e.g., CosmicStrand) employ it as a post-boot stealth mechanism, and the Barzakh-Scanner must be validated against it. This module is **read-only instrumentation** — it intercepts and logs system calls but does **not** modify kernel data structures, exfiltrate data, or establish persistence beyond the current boot session. This distinction keeps the implementation within the PRD's Non-Goals boundary (§3.3). If this is determined to exceed acceptable scope, the module can be disabled via the `BARZAKH_DISABLE_MSR_HOOK` build flag without affecting the core DXE/ExitBootServices emulation.

## 4. Defensive Attestation Module

This module ensures that the research acts as a "blue-team" tool, effectively logging and verifying the impact of the aforementioned hooks.

### 4.1 PCR Querying
* Utilizes the `EFI_TCG2_PROTOCOL`.
* Reads critical Platform Configuration Registers (PCRs), specifically PCR 0 (Core System Firmware), PCR 2 (Option ROMs), and PCR 4 (Boot Manager Code).
* Compares expected hash values (whitelisted boot process) against the compromised values to quantify detection efficacy.

### 4.2 TCG Event Log Parsing
* Extracts the TCG Event Log from firmware memory.
* Analyzes `EV_EFI_BOOT_SERVICES_APPLICATION` and `EV_EFI_BOOT_SERVICES_DRIVER` entries.
* Provides the ground truth data for the `Barzakh-Scanner` rule generation.

### 4.3 Telemetry & Attestation Data Flow

The following diagram illustrates how defensive telemetry flows from the UEFI environment through to the analysis pipeline, ensuring data integrity at each stage.

```mermaid
flowchart LR
    subgraph QEMU Sandbox
        A[BootkitPkg\nDXE Hooks] -->|Hook events| B[AttestationPkg]
        C[TPM 2.0 vTPM] -->|PCR values\nEvent Log| B
        B -->|Serial output\nCOM1| D[QEMU Serial Pipe]
        B -->|FAT32 partition\nwrite| E[Logging VDisk]
    end

    subgraph Host Analysis Environment
        D -->|Captured via\ntee/script| F[Raw Telemetry Logs]
        E -->|Mounted read-only\npost-test| F
        F -->|Parsed & normalized| G[Barzakh-Scanner\nRule Engine]
        G -->|Detection results| H[CI Report\nJSON/HTML]
        F -->|Archived| I[AES-256 Encrypted\nCold Storage]
    end

    style A fill:#f96,stroke:#333
    style G fill:#6f9,stroke:#333
    style I fill:#69f,stroke:#333
```

**Key invariants:**
* Telemetry never traverses a network — all data transfer is via serial pipe or mounted virtual disk.
* Raw logs are hashed (SHA-256) immediately upon extraction; hashes are recorded in the CI report for tamper detection.
* Cold storage archives are retained per the PRD data retention policy (§8, max 36 months).

## 5. Security Constraints & Failsafes

### 5.1 Hardware-Rooted Binding 
To prevent the payload from running on any ad-hoc machine, the driver performs an early execution check:
1. **SMBIOS Check:** Queries the SMBIOS table for the unique System UUID.
2. **TPM EK Check:** Queries the TPM Endorsement Key public certificate.
3. If the identifiers do not cryptographically match the hardcoded values of the authorized lab equipment, the driver will issue an `EFI_ABORTED` status code and voluntarily unload itself.

### 5.2 Flash Recovery 
A fail-safe to prevent test hardware bricking:
* Employs QEMU `-pflash` snapshots allowing instantaneous rollback of the OVMF firmware state.

### 5.3 Build Chain Integrity & Reproducibility
To prevent supply-chain tampering and ensure academic reproducibility:
* **OVMF Version Pinning:** All builds must use a specific, pinned OVMF commit hash (e.g., `edk2-stable202405`, commit `a]b1c2d3e4f5`). The exact commit is recorded in `scripts/build.sh` and must match the value documented in the test environment setup.
* **Reproducible Builds:** `build.sh` uses deterministic compiler flags (`-frandom-seed`, fixed `SOURCE_DATE_EPOCH`) to ensure byte-identical outputs across machines.
* **Artifact Signing:** All compiled `.efi` binaries are signed with a project-specific Ed25519 key (stored in an HSM or hardware token, never committed to the repository). Signatures are verified before any QEMU test execution.
* **SBOM Generation:** Each build produces a Software Bill of Materials (SPDX format) cataloging all EDK II dependencies, compiler versions, and OVMF source hashes.
* **Commit Signing:** All repository commits must be GPG-signed. Unsigned commits are rejected by branch protection rules.

## 6. Repository Layout

```text
barzakh/
├── docs/
│   ├── SETUP.md              # Environment setup guide
│   ├── ARCHITECTURE.md       # This file
│   ├── ANDROID_BOOT.md       # Android boot security (9 modules)
│   ├── TESTING.md            # Testing strategy
│   ├── LAB_TESTING.md        # Hardware lab testing & build-mode reference
│   ├── LAB_AUTOMATION.md     # HIL lab automation
│   ├── USECASES.md           # Offense & defense use cases
│   ├── DASHBOARD.md          # REST API + web dashboard
│   ├── AGENT.md              # Real-time monitoring agent
│   ├── INTEL.md              # Threat intelligence (feeds, YARA, MISP)
│   ├── ML.md                 # Machine-learning analysis
│   ├── SCENARIOS.md          # Attack scenario builder
│   ├── KNOWLEDGE_BASE.md     # Firmware knowledge base
│   └── FUZZING.md            # Protocol fuzzing harness
├── src/
│   ├── BootkitPkg/           # EDK II package: UEFI bootkit emulation (C)
│   │   ├── DxeInject/        # DXE phase implantation + kill-switches
│   │   ├── ExitBootHook/     # ExitBootServices interception & MSR hooking
│   │   ├── Aarch64/          # ARM64 modules (ExceptionVectorHook, etc.)
│   │   └── RiscV/            # RISC-V M-mode firmware injection
│   ├── LegacyBootkit/        # Legacy BIOS (16-bit asm) MBR/VBR bootkit
│   ├── AttestationPkg/       # Defensive TPM querying & event log extractors
│   └── barzakh-scanner-rs/   # Rust workspace (8 crates, 4 binaries)
│       ├── crates/barzakh-core/       # Detection engine library
│       ├── crates/barzakh-cli/        # CLI binaries (barzakh-scanner + barzakh-adversary)
│       ├── crates/barzakh-adversary/  # Red-team payload generator library
│       ├── crates/barzakh-intel/      # IOC feeds, YARA-subset engine, MISP export
│       ├── crates/barzakh-ml/         # Isolation forest + logistic regression
│       ├── crates/barzakh-store/      # SQLite history + knowledge base
│       ├── crates/barzakh-server/     # REST API + web dashboard (barzakh-server)
│       └── crates/barzakh-agent/      # Monitoring agent (barzakh-agent)
├── scripts/
│   ├── build.sh              # EDK II compilation
│   ├── qemu-run.sh           # QEMU test harness with vTPM
│   ├── qemu-e2e.sh           # End-to-end testing
│   ├── qemu-automation.sh    # Automated QEMU test sequences
│   ├── generate-corpus.sh    # Adversary corpus generation
│   ├── dump-pcrs.sh          # PCR value extraction
│   ├── dump-memory.sh        # Memory acquisition for analysis
│   ├── validate-environment.sh # Pre-flight checks
│   └── audit-log.sh          # Append-only execution audit logger
├── tests/                    # Unit, integration, and corpus tests
├── .github/workflows/        # CI/CD pipeline
├── CONTRIBUTING.md
├── SECURITY.md
└── README.md
```

## 7. Adversary Crate Architecture

The `barzakh-adversary` crate implements a red-team payload generation and validation framework. It is exposed to end-users via the standalone `barzakh-adversary` binary (built from `barzakh-cli/src/adversary_main.rs`), which provides CLI commands: `generate`, `list`, `corpus`, `validate`, `qemu`, `esp`, `inject-single`, `scenario`, and `robustness`.

### 7.1 Payload Trait

```rust
pub trait Payload: Send + Sync {
    fn name(&self) -> &str;
    fn arch(&self) -> Arch;
    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>>;
    fn expected_detections(&self) -> Vec<ExpectedFinding>;
}
```

Each payload generates a raw binary blob mimicking a specific bootkit artifact. The `expected_detections()` method declares which scanner detectors should fire, enabling automated validation.

### 7.2 Payload Registry

| Payload | Binary Output | Scanner Detector Triggered |
| :--- | :--- | :--- |
| `TrampolinePayload` | x86_64: `FF 25` indirect JMP; ARM64: `LDR X16 + BR X16`; RISC-V: `AUIPC + LD + JALR` | `memory` (trampoline patterns) |
| `BootServicesHookPayload` | `BOOTSERV` header + mismatched CRC32 + suspicious pointers | `hook` (CRC + pointer range) |
| `PeInjectPayload` | Minimal MZ + PE\0\0 at page-aligned offset | `memory` (PE in runtime) |
| `FirmwareVolumeTamperPayload` | `_FVH` signature with corrupted 16-bit header checksum | `firmware_volume` (checksum failure) |
| `SignaturePlantPayload` | BlackLotus, CosmicStrand, MoonBounce byte sequences | `memory` (Aho-Corasick match) |

#### Android Boot Payloads (AArch64)

| Payload | Binary Output | Scanner Detector Triggered |
| :--- | :--- | :--- |
| `AndroidPkvmEscapePayload` | Forged pvmfw image with EL2 shellcode entry | `android_pkvm` |
| `AndroidDiceForgePayload` | CBOR DICE chain with predictable CDI values | `android_dice` |
| `AndroidGkiTamperPayload` | boot.img v4 with modified ramdisk + invalid AVB hash | `android_gki_boot` |
| `AndroidRkpSpoofPayload` | RKP blob with fake EEK certificate chain | `android_rkp` |
| `AndroidBtForgePayload` | Fake transparency log with crafted Merkle path | `android_binary_transparency` |
| `AndroidTrustyTamperPayload` | Trusty image with patched entry + disabled signature | `android_trusty` |
| `AndroidBootctrlPoisonPayload` | Poisoned boot_ctrl with both slots unbootable | `android_bootctrl` |
| `AndroidDlkmInjectPayload` | EROFS image with unsigned kernel module | `android_vendor_dlkm` |
| `AndroidBootconfigInjectPayload` | Boot image with malicious bootconfig section | `android_bootconfig` |

### 7.3 Validation Pipeline

```
generate() → Vec<u8> → write to temp file → BarzakhScanner::scan()
    → compare ScanResult.findings against expected_detections()
    → report: detected/missed, matched findings count, severity
```

### 7.4 Corpus Generator

`generate_corpus(output_dir)` produces paired files for each payload:
- `malicious_<name>.bin` — generated payload (triggers detections)
- `clean_<name>.bin` — zero-filled reference (no detections)

These integrate with `BarzakhScanner::validate_against_corpus()` for automated TPR/FPR measurement.

## 8. Conditional Functional Mode (AArch64)

The `ExceptionVectorHook` module supports two compilation modes:

| Mode | Build Flag | Behavior |
| :--- | :--- | :--- |
| **Simulation** (default) | None | Logs simulated VBAR relocation steps via DEBUG output |
| **Functional** | `-DBARZAKH_FUNCTIONAL=1` | Performs real `MRS/MSR VBAR_EL1` operations in QEMU EL1 |

In functional mode, the module:
1. Reads the current VBAR_EL1 via inline assembly
2. Allocates a page-aligned buffer via Boot Services
3. Copies the original 2KB vector table
4. Patches the Lower EL AArch64 Sync entry with a trampoline (`LDR X16; BR X16` → original handler)
5. Redirects VBAR_EL1 to the new table via `MSR + ISB`

The trampoline redirects back to the original handler — demonstrating the hook mechanism without destabilizing the system.