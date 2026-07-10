# Barzakh: Testing & Validation Strategy

This document defines the testing methodologies, environments, and validation criteria for Project Barzakh. Due to the low-level, firmware-centric nature of the project, testing is strictly controlled and heavily relies on virtualization and automation to ensure safety, reproducibility, and rigorous academic validation.

## 1. Test Environment Setup

All active execution and dynamic analysis must occur within the strictly defined virtualization sandbox to prevent accidental native infection.

### 1.1 Virtualization Infrastructure
* **Hypervisor:** QEMU with KVM acceleration.
* **Firmware:** Custom compiled OVMF (Open Virtual Machine Firmware) binaries. The specific OVMF commit hash must be documented for reproducible builds.
* **Virtual TPM (vTPM):** `swtpm` integrated with QEMU to emulate TPM 2.0 capabilities, enabling PCR measurements and TCG event logging.
* **Guest OS Options:** Windows 10/11 (for PatchGuard/VBS interactions) and Ubuntu Linux (for GRUB/kernel panic debugging).

### 1.2 Isolation Guarantees
* **Network:** The QEMU guest environment will be initialized without active NICs (`-net none`) to ensure a completely air-gapped test state.
* **Storage:** Isolated virtual disk images (`.qcow2`), specifically excluding any host folder passthrough during live execution phases.

## 2. Safety & Compliance Validation

Before any functional testing of the bootkit behavior is conducted, the kill-switches and binding mechanisms must be validated.

| Test Case | Description | Expected Outcome |
| :--- | :--- | :--- |
| **UUID Mismatch** | Launch Barzakh on a QEMU instance with a non-whitelisted SMBIOS UUID. | Driver unloads gracefully (`EFI_ABORTED`). System boots normally. |
| **vTPM EK Mismatch** | Present a vTPM with a simulated Endorsement Key different from the hardcoded lab key. | Driver unloads gracefully (`EFI_ABORTED`). System boots normally. |
| **Expiry Validation** | Boot the environment with the RTC (Real-Time Clock) set past the hardcoded project expiry date. | Driver aborts execution. |
| **Automated Rollback** | Trigger a corrupted NVRAM state and execute `nvram-recovery.py`. | Original OVMF NVRAM (`_VARS.fd`) is restored; system reboots successfully. |

## 3. Offensive Emulation Testing (Functional)

Validating that the malware simulation successfully reproduces specific TTPs without causing uncontrolled system crashes.

### 3.1 DXE Hook Injection
* **Method:** Verify via UEFI shell or serial debug output that `gBS->AllocatePool` and `gBS->CreateEvent` are successfully hijacked by the BootkitPkg.
* **Success Criteria:** The system does not hang during POST; serial logs confirm hook placement.

### 3.2 ExitBootServices Transition
* **Method:** Boot a full OS. Use kernel-level debuggers (e.g., WinDbg via serial pipe) to inspect memory mappings post-handoff.
* **Success Criteria:** The bootkit payload resides in `EfiRuntimeServicesCode` or `EfiRuntimeServicesData` memory spaces and actively survives the OS kernel initialization.

## 4. Defensive Attestation & Telemetry Testing

Testing the blue-team data collection capabilities of the `AttestationPkg`.

### 4.1 PCR Delta Verification
* **Method:** Record PCR [0, 2, 4, 7] values on a "clean" OVMF boot. Inject Barzakh, reboot, and record the new PCR configurations.
* **Success Criteria:** The `AttestationPkg` correctly identifies and logs the specific delta/hashes changed by the unauthorized DXE driver insertion.

### 4.2 Event Log Extraction
* **Method:** Run the event log extractor module from the UEFI shell post-infection.
* **Success Criteria:** The tool successfully writes the parsed TCG Event Log to the QEMU serial output or mounted FAT32 logging partition, accurately reflecting the malicious driver load events.

## 5. Detection Efficacy (Barzakh-Scanner Validation)

This validates the primary research outcome: improving the detection of firmware-level persistence.

### 5.1 Baseline Measurement
* Scan the infected QEMU memory dumps and firmware images using standard, unmodified commercial AV/EDR tools (simulated via API or standalone scanners). 
* **Target:** Confirm a near 0% detection rate of the advanced, memory-resident hooks.

### 5.2 Barzakh-Scanner Evaluation
* Run `BarzakhScanner` against the same infected artifacts.
* **Target Objective:** Achieve ≥85% effectiveness in detecting:
  1. Illegitimate DXE pointers.
  2. Modified `ExitBootServices` addresses.
  3. Anomalous `EfiRuntimeServicesCode` memory allocations.
* **False Positive Check:** Run the scanner against 50 "clean" reference OVMF boots. The False Positive Rate (FPR) must remain < 5%.

### 5.3 Adversarial & Evasion Testing
Validates scanner robustness against bootkit variants that attempt to evade detection:

| Test Case | Evasion Technique | Expected Scanner Behavior |
| :--- | :--- | :--- |
| **Polymorphic Hook Addresses** | Randomize the memory address of DXE hooks on each boot using ASLR-like relocation. | Scanner detects via pointer integrity checks (not hardcoded addresses). |
| **Fragmented Memory Layout** | Split the bootkit payload across multiple non-contiguous `EfiRuntimeServicesData` regions. | Scanner correlates fragmented allocations via cross-reference analysis. |
| **Timestamp Manipulation** | Tamper with TCG Event Log timestamps to obscure the injection sequence. | Scanner flags temporal anomalies in event ordering. |
| **Mimicry Attack** | Name the malicious DXE driver identically to a legitimate OVMF driver (e.g., `DxeCore.efi`). | Scanner detects via hash comparison against known-good OVMF driver manifests. |
| **PCR Replay** | Replay previously recorded "clean" PCR values via a hooked `EFI_TCG2_PROTOCOL`. | AttestationPkg detects mismatch between event log hashes and reported PCR values (quote verification). |

* **Target:** Scanner must maintain ≥ 70% detection rate against evasion variants (lower threshold acceptable given these are advanced techniques beyond baseline TTPs).

## 6. Performance & Regression Benchmarks

Boot-time overhead from hooks must be quantified to ensure the emulation does not introduce unrealistic side effects (e.g., infinite loops, deadlocks) that would invalidate the research.

| Benchmark | Measurement | Acceptable Threshold | Method |
| :--- | :--- | :--- | :--- |
| **Clean Boot Time** | Time from QEMU start to OS login prompt (no hooks) | Baseline reference | Automated via serial timestamp markers |
| **Infected Boot Time** | Time from QEMU start to OS login prompt (all hooks active) | ≤ 15% overhead vs. clean baseline | Same serial timestamp method |
| **DXE Hook Latency** | Time delta introduced by `AllocatePool`/`CreateEvent` hooks | < 50 ms cumulative | Measured via `gBS->Stall()` calibrated timer in serial output |
| **ExitBootServices Overhead** | Additional time in the `ExitBootServices` interception path | < 200 ms | Instrumented in the hook code itself |
| **Scanner Execution Time** | Wall-clock time for Barzakh-Scanner to analyze a full memory dump + firmware image | < 30 seconds | Timed in CI harness |

* **Regression policy:** If any benchmark degrades by > 20% between commits, the CI pipeline flags a warning (non-blocking) and the commit is tagged for manual review.

## 7. Statistical Rigor: FPR Validation

The original 50-boot FPR sample is insufficient for statistical confidence. The validation methodology is expanded as follows:

* **Sample Size:** ≥ 200 clean OVMF boots.
* **Configuration Variance:** Boots must span a matrix of:
  - **OVMF versions:** At minimum 3 distinct pinned commits (current, previous stable, oldest supported).
  - **Guest OS:** Windows 10, Windows 11, Ubuntu 22.04 LTS, Ubuntu 24.04 LTS.
  - **vTPM states:** Fresh EK enrollment vs. pre-existing EK.
* **Statistical Target:** FPR < 5% with 95% confidence interval (Wilson score interval).
* **Reporting:** FPR results are reported with exact binomial confidence intervals, not point estimates alone.
* **Automation:** The 200-boot suite runs nightly via `scripts/fpr-validation.sh` and results are appended to a rolling CSV for trend analysis.

## 8. Adversary Red-Team Testing (Automated)

The `barzakh-adversary` crate provides automated, closed-loop validation of the scanner's detection capabilities. It is exposed via the standalone `barzakh-adversary` binary for manual use and via `cargo test` for CI integration.

### 8.1 Payload-Level Validation

Each payload generator declares its expected detections. The validation runner:
1. Generates the binary payload via `Payload::generate()`
2. Writes it to a temporary file
3. Invokes `BarzakhScanner::scan()` on that file
4. Compares actual findings against `expected_detections()`
5. Reports: detected (bool), matched findings count, severity levels

```bash
# Run all adversary unit tests (each payload individually validated)
cargo test -p barzakh-adversary

# Run corpus-level E2E (generates all payloads + clean pairs, measures TPR/FPR)
cargo test -p barzakh-adversary -- --ignored corpus_validation

# Or use the standalone binary for manual testing:
barzakh-adversary list                        # Show all 116 payloads
barzakh-adversary generate --arch x86_64      # Generate payloads
barzakh-adversary corpus --output ./corpus    # Generate paired corpus
barzakh-adversary validate --corpus ./corpus  # Measure detection rates
```

### 8.2 Corpus Validation

The corpus generator produces paired files (`malicious_*.bin` + `clean_*.bin`) for all payloads. The scanner's `validate_against_corpus()` uses filename conventions to establish ground truth:
- Files containing "malicious" or "infected" → expected positive
- All others → expected negative

**Thresholds enforced in CI:**
- True Positive Rate (TPR) >= 80%
- False Positive Rate (FPR) <= 10%

### 8.3 Current Payload Coverage

| Payload | Detection Path | Status |
| :--- | :--- | :--- |
| Trampoline (x86_64) | `FF 25` indirect JMP pattern | Passing |
| Trampoline (ARM64) | `LDR X16 + BR X16` pattern | Passing |
| Boot Services Hook | CRC32 mismatch + pointer range | Passing |
| PE Injection | MZ + PE\0\0 at page-aligned offset | Passing |
| FV Tamper | `_FVH` header checksum corruption | Passing |
| Signature Plant | Aho-Corasick match (BlackLotus, CosmicStrand, MoonBounce) | Passing |

## 9. Automation & CI/CD

To ensure continuous integrity during the development lifecycle:
* **Script:** `scripts/build.sh` automatically compiles the EDK II packages.
* **Script:** `scripts/qemu-run.sh` initializes the exact testing sandbox.
* **Integration:** Any commit to the `main` branch must successfully compile all `.efi` binaries (without checking them in) and pass the `UUID Mismatch` fail-safe test in a headless QEMU mode.

### 8.1 Expanded CI Gate Requirements

All of the following must pass before a commit is merged to `main`:

| Gate | Test | Blocking? | Estimated Runtime |
| :--- | :--- | :--- | :--- |
| **G-1: Build** | `build.sh` compiles all EDK II packages without errors | Yes | ~2 min |
| **G-2: Artifact Signing** | All `.efi` outputs are signed and signature is verified | Yes | ~30 sec |
| **G-3: UUID Mismatch** | Bootkit aborts on non-whitelisted SMBIOS UUID | Yes | ~1 min |
| **G-4: vTPM EK Mismatch** | Bootkit aborts on non-whitelisted TPM EK | Yes | ~1 min |
| **G-5: Expiry Validation** | Bootkit aborts when RTC is past expiry date | Yes | ~1 min |
| **G-6: DXE Hook Injection** | Serial logs confirm `gBS->AllocatePool` and `gBS->CreateEvent` hooks placed | Yes | ~2 min |
| **G-7: ExitBootServices Transition** | Payload survives in `EfiRuntimeServicesCode` memory post-OS init | Yes | ~3 min |
| **G-8: PCR Delta Detection** | AttestationPkg detects tampered PCR [0, 2, 4, 7] values | Yes | ~2 min |
| **G-9: Scanner Smoke Test** | Barzakh-Scanner detects ≥1 injected artifact in a single infected boot | Yes | ~2 min |
| **G-10: SBOM Generation** | SPDX SBOM is generated and valid | Yes | ~30 sec |

* **Total estimated CI pipeline time:** ~15 minutes (parallelizable to ~8 min with 2 QEMU runners).
* **Nightly extended run:** Full 200-boot FPR validation and adversarial evasion suite (§5.3) runs on a nightly schedule rather than per-commit.